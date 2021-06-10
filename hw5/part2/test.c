// SPDX-License-Identifier: GPL-2.0
// Author: Harry Chong (Student ID: 14158124)
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int open_fd(void)
{
	int fd;

	printf("Opening: /dev/fakedrive\n");
	fd = open("/dev/fakedrive", O_RDWR);
	if (fd == -1) {
		perror("open /dev/fakedrive");
		exit(EXIT_FAILURE);
	}

	return fd;
}

void close_fd(int fd)
{
	printf("Closing: /dev/fakedrive\n");
	close(fd);
	printf("---------\n");
}

void read_fd(void)
{
	int fd, ret, i;
	char buf[1024];

	fd = open_fd();

	printf("Reading from: /dev/fakedrive\n");
	ret = read(fd, &buf, 1024);

	printf("Received %d bytes (raw): ", ret);
	for (i = 0; i < ret; i++) {
		printf("%x ", buf[i]);

		if (i == ret - 1)
			printf("\n");
	}

	printf("	       (ascii): ");
	for (i = 0; i < ret; i++) {
		printf("%c", buf[i]);

		if (i == ret - 1)
			printf("\n");
	}

	if (ret == -1)
		perror("reading /dev/fakedrive\n");
	else
		close_fd(fd);
}

void write_fd(char *buf)
{
	int fd, ret, i;

	fd = open_fd();

	printf("Writing \"%s\" to: /dev/fakedrive\n", buf);
	ret = write(fd, buf, strlen(buf));

	if (ret < 0)
		printf("write(): Invalid argument\n");
	else
		printf("Success!\n");

	close_fd(fd);
}

int main(void)
{
	read_fd(); // Tests reading
	write_fd("abc12345"); // Tests writing an INCORRECT Student ID Number
	write_fd("14158124"); // Tests writing an  CORRECT Student ID Number

	exit(EXIT_SUCCESS);
}
