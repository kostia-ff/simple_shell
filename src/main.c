#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <ctype.h>
#include <netdb.h>

//блок констант
#define MAX_INPUT_SIZE  1024
#define MAX_ARG_COUNT   10

#if (_PC_PATH_MAX > 4096) 
#define PATH_MAX    _PC_PATH_MAX
#else
#define PATH_MAX    4096
#endif
#define PACKET_SIZE     64

//глабальная переменная разрывающая цикл захвата команд
bool glStop = false;

//структура которая хранит имя команды и соответсвующую этому имени функцию
typedef void (*command_func)(const char** args);
typedef struct {
	char* name;
	command_func func;
} Command;

//объявляем протопипы функций обрабатывающих команды
//последний аргумент всегда должен быть NULL
void cmd_ls(const char** args);
void cmd_cd(const char** args);
void cmd_pwd(const char** args);
void cmd_grep(const char** args);
void cmd_ping(const char** args);
void cmd_ping_sudo(const char** args);
void cmd_cp(const char** args);

//ядро оболочки: массив команд 
//добавляйте сюда новые команды и функции их обрабатывающие
Command commands[] = {
	{"ls", cmd_ls},
	{"cd", cmd_cd},
	{"pwd", cmd_pwd},
	{"grep", cmd_grep},
	{"ping", cmd_ping}, //system 
	{"ping_sudo", cmd_ping_sudo}, //sudo rights request
	{"cp", cmd_cp},
	{NULL, NULL}
};

/*----------------------блок функций----------------------*/
void cmd_ls(const char** args) {
	const char* path = args[1] ? args[1] : ".";
	DIR* dir = opendir(path);
	if (!dir) {
		perror("ls");
		return;
	}
	struct dirent* entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;
		printf("%s ", entry->d_name);
	}
	closedir(dir);
	printf("\n");
}

void cmd_cd(const char** args) {
	if (!args[1]) {
		fprintf(stderr, "cd: missing argument\n");
		return;
	}
	if (chdir(args[1]) != 0) {
		perror("cd");
	}
}

void cmd_pwd(const char** args) {
	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd))) {
		printf("%s\n", cwd);
	}
	else {
		perror("pwd");
	}
}

void cmd_grep(const char** args) {
	if (!args[1] || !args[2]) {
		fprintf(stderr, "Usage: grep pattern file\n");
		return;
	}
	FILE* file = fopen(args[2], "r");
	if (!file) {
		perror("grep");
		return;
	}
	char line[PATH_MAX];
	while (fgets(line, sizeof(line), file)) {
		if (strstr(line, args[1])) {
			printf("%s", line);
		}
	}
	if (ferror(file)) {
		perror("File reading error");
	}
	fclose(file);
}
//ping через системный вызов
void cmd_ping(const char** args) {
	if (!args[1]) {
		fprintf(stderr, "Usage: ping hostname\n");
		return;
	}
	char command[MAX_INPUT_SIZE + 256];
	snprintf(command, sizeof(command), "ping -c 4 %s", args[1]);
	system(command);
}
//стандартная функция чексуммы для icmp 
unsigned short checksum(const void* _buf, int len) {
	const unsigned short* buf = _buf;
	unsigned int sum = 0;
	unsigned short result;

	for (; len > 1; len -= 2)
		sum += *buf++;

	if (len == 1)
		sum += *(unsigned char*)buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}
//чтобы использовать этот ping нужны права судоря
void cmd_ping_sudo(const char** args) {
	if (!args[1]) {
		fprintf(stderr, "Usage: ping hostname\n");
		return;
	}

	const char* hostname = args[1];
	struct hostent* host = gethostbyname(hostname);
	if (!host) {
		herror("ping");
		return;
	}
	// Создание сокета с использованием сырого сокета для ICMP
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		perror("socket (did you have sudo rights?)");
		return;
	}

	// Установка тайм-аута (5 секунд)
	struct timeval tv;
	tv.tv_sec = 5;  // 5 секунд
	tv.tv_usec = 0; // 0 микросекунд
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		perror("setsockopt");
		close(sockfd);
		return;
	}

	// Переводим сокет в неблокирующий режим
	int flags = fcntl(sockfd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl");
		close(sockfd);
		return;
	}
	if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		perror("fcntl");
		close(sockfd);
		return;
	}

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_addr = *((struct in_addr*)host->h_addr_list[0]);

	// Подготовка ICMP-заголовка
	struct icmphdr icmp_hdr;
	memset(&icmp_hdr, 0, sizeof(icmp_hdr));
	icmp_hdr.type = ICMP_ECHO;
	icmp_hdr.un.echo.id = getpid();

	// Подготовка пакета для отправки
	char packet[PACKET_SIZE];
	memset(packet, 0, PACKET_SIZE);
	memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));

	// Вычисляем контрольную сумму
	icmp_hdr.checksum = checksum(packet, PACKET_SIZE);
	memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));

	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);
	char recv_buf[PACKET_SIZE];

	// Отправка 4 ICMP-запросов
	for (int i = 0; i < 4; i++) {
		if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
			perror("sendto");
			continue;
		}

		// Получение ответа
		ssize_t recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from, &from_len);
		if (recv_len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// Время ожидания истекло (тайм-аут)
				printf("Timeout while waiting for response\n");
			}
			else {
				perror("recvfrom");
			}
			continue;
		}

		printf("Packet %d received from %s\n", i + 1, inet_ntoa(from.sin_addr));
		sleep(1);
	}

	close(sockfd);
}

void cmd_cp(const char** args) {
	if (!args[1] || !args[2]) {
		fprintf(stderr, "Usage: cp source destination\n");
		return;
	}
	if (strcmp(args[1], args[2]) == 0) {
		fprintf(stderr, "cp: self-copying is prohibited\n");
		return;
	}
	int src = open(args[1], O_RDONLY);
	if (src < 0) {
		perror("cp");
		return;
	}
	int dest = open(args[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (dest < 0) {
		perror("cp");
		close(src);
		return;
	}
	char buffer[4096];

	ssize_t bytes_read, bytes_written, total_written;

	while ((bytes_read = read(src, buffer, sizeof(buffer))) > 0) {
		total_written = 0;
		while (total_written < bytes_read) {
			bytes_written = write(dest, buffer + total_written, bytes_read - total_written);
			if (bytes_written < 0) {
				perror("cp: write");
				close(src);
				close(dest);
				return;
			}
			total_written += bytes_written;
		}
	}

	if (bytes_read < 0) {
		perror("cp: read");
	}

	close(src);
	close(dest);
}
/*----------------------завершение блока функций----------------------*/

//диспетчер функций
void execute_command(char* input) {
	char* args[MAX_ARG_COUNT];
	int i = 0;
	char* token = strtok(input, " ");
	while (token && i < MAX_ARG_COUNT - 1) {
		args[i++] = token;
		token = strtok(NULL, " ");
	}
	args[i] = NULL;
	if (!args[0])
		return;
	for (int j = 0; commands[j].name; j++) {
		if (strcmp(args[0], commands[j].name) == 0) {
			commands[j].func((const char**)args);
			return;
		}
	}
	fprintf(stderr, "Unknown command: %s\n", args[0]);
}
//обаботка ошибок
void return_error(const char* msg, const char* file, const char* func, int line) {
	char errMsg[MAX_INPUT_SIZE];
	int res = snprintf(errMsg, sizeof(errMsg),
		"Error: %s\nfile: %s\nfunction: %s\nline: %d\nerrno",
		msg, file, func, line);
	if (res > 0)
		perror(errMsg);
	else
		perror(msg);

	printf("Press any key to exit...\n");
	getchar();

	exit(EXIT_FAILURE);
}
#define return_error(msg) return_error(msg, __FILE__, __func__, __LINE__)

//отчистка от слишком длинной входной строки
void clear_input_buffer() {
	int ch;
	while ((ch = getchar()) != '\n' && ch != EOF);
}
//функция выхода
void to_lower_case(char* str) {
	for (int i = 0; str[i]; i++) {
		str[i] = tolower((unsigned char)str[i]);
	}
}
bool exit_command(const char* input) {
	char lower_input[MAX_INPUT_SIZE];
	strlcpy(lower_input, input, sizeof(lower_input));
	to_lower_case(lower_input);

	if (strcmp(lower_input, "exit") == 0 ||
		strcmp(lower_input, "quit") == 0 ||
		strcmp(lower_input, "q") == 0) {
		return true;
	}
	return false;
}

int main() {
	char input[MAX_INPUT_SIZE];
	char cwd[PATH_MAX];
	char homedir[PATH_MAX];
	char hostname[_SC_HOST_NAME_MAX];
	char username[_SC_LOGIN_NAME_MAX];

	if (0 != gethostname(hostname, sizeof(hostname)))
		return_error("unable to get hostname");
	if (0 != getlogin_r(username, sizeof(username)))
	    snprintf(username, sizeof(username), "unknown");
		//return_error("unable to get username");
	if (0 > snprintf(homedir, sizeof(homedir), "/home/%s", username))
		return_error("unable to create homedir string");


	while (!glStop) {
		if (NULL != getcwd(cwd, sizeof(cwd))) {
			if (strncmp(cwd, homedir, strlen(homedir)) == 0) {
				printf("%s@%s:~%s> ", username, hostname, cwd + strlen(homedir));
			}
			else {
				printf("%s@%s:%s> ", username, hostname, cwd);
			}
		}
		else
			return_error("unable to create cwd");

		if (!fgets(input, sizeof(input), stdin)) {
			break;
		}

		if (input[strlen(input) - 1] != '\n') {
			clear_input_buffer();
			printf("Your string is to long. Please try again.\n");
			continue;
		}
		input[strcspn(input, "\n")] = 0;

		if (exit_command(input))
			break;

		//core processing function
		execute_command(input);
	}
	printf("Good bye!\n");
	return 0;
}
