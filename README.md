# Simple Shell Implementation in C

This is a simple shell implementation in C that supports basic commands like `ls`, `cd`, `pwd`, `grep`, `ping`, and `cp`. The shell also includes a custom `ping_sudo` command that requires sudo privileges to execute raw ICMP packets.
All code include in one .cpp file to to simplify its review.

## Features

- **Basic Commands**:
  - `ls`: List directory contents.
  - `cd`: Change directory.
  - `pwd`: Print working directory.
  - `grep`: Search for a pattern in a file.
  - `cp`: Copy files.
  - `ping`: Ping a host using the system's `ping` command.
  - `ping_sudo`: Ping a host using raw ICMP packets (requires sudo).

- **Error Handling**: Basic error handling and user feedback.
- **Custom Prompt**: Displays the current user, hostname, and working directory.

## Available Commands

- **`ls [path]`**: List files in the specified directory (default is current directory).
- **`cd <path>`**: Change to the specified directory.
- **`pwd`**: Print the current working directory.
- **`grep <pattern> <file>`**: Search for a pattern in a file.
- **`ping <hostname>`**: Ping a host using the system's `ping` command.
- **`ping_sudo <hostname>`**: Ping a host using raw ICMP packets (requires sudo).
- **`cp <source> <destination>`**: Copy a file from source to destination.
- **`exit` or `quit`**: Exit the shell.

## Notes

- The `ping_sudo` command requires root privileges to create raw sockets. Run the shell with `sudo` to use this command.
- The shell has a maximum input size of 1024 characters.