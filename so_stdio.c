#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>

#include "so_stdio.h"

#define BUFSIZE 4096
#define EOF (-1)

struct _so_file {
	int fd;
	char *buf;
	int crpoz;
	int crbufsize;
	long bytesRead;
	int ferrorFlag;
	int lastOp;
	int pid;
};
/* return file descriptor number */
int so_fileno(SO_FILE *stream)
{
	return stream->fd;
}

/* open file in appropriate number and init struct values */
SO_FILE *so_fopen(const char *pathname, const char *mode)
{
	int file_descriptor = -1;

	if (strcmp(mode, "r") == 0)
		file_descriptor = open(pathname, O_RDONLY, 0644);

	if (strcmp(mode, "r+") == 0)
		file_descriptor = open(pathname, O_RDWR, 0644);

	if (strcmp(mode, "w") == 0)
		file_descriptor = open(pathname,
		O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (strcmp(mode, "w+") == 0)
		file_descriptor = open(pathname,
				O_RDWR | O_CREAT | O_TRUNC, 0644);

	if (strcmp(mode, "a") == 0)
		file_descriptor = open(pathname,
				O_WRONLY | O_CREAT | O_APPEND, 0644);

	if (strcmp(mode, "a+") == 0)
		file_descriptor = open(pathname,
			O_RDWR | O_CREAT | O_APPEND, 0644);

	if (file_descriptor < 0)
		return NULL;

	SO_FILE *file = (SO_FILE *)malloc(sizeof(SO_FILE));

	file->buf = (char *)malloc(sizeof(char) * BUFSIZE);

	memset(file->buf, 0, BUFSIZE);

	file->crpoz = 0;
	file->crbufsize = BUFSIZE;
	file->fd = file_descriptor;
	file->ferrorFlag = 0;
	file->bytesRead = 0;
	file->lastOp = 0;
	return file;
}

/* close stream */
int so_fclose(SO_FILE *stream)
{
	int flushRes = so_fflush(stream);
	int closeRes = close(stream->fd);

	/* free stream regardless of flush/close result */
	free(stream->buf);
	free(stream);

	if (closeRes != -1 && flushRes != EOF)
		return closeRes;

	return EOF;
}

/* flush stream buffer */
int so_fflush(SO_FILE *stream)
{
	if (stream != NULL && stream->crpoz != 0) {
		if (stream->lastOp == 1) {
			/* write data to disk if there is any in the buf */
			if (write(stream->fd, stream->buf, stream->crpoz)
					!= -1) {
				memset(stream->buf, 0, BUFSIZE);
				stream->crpoz = 0;
				stream->crbufsize = BUFSIZE;

				return 0;
			}
		}
		/* 0 buffer after read */
		if (stream->lastOp == 2) {
			memset(stream->buf, 0, BUFSIZE);
			stream->crpoz = 0;
			stream->crbufsize = BUFSIZE;

			return 0;
		}
		stream->ferrorFlag = 1;
		return EOF;
	}

	/* if buffer is empty, nothing to do */
	if (stream->crpoz == 0)
		return 0;

	/* otherwise, there was an error */
	stream->ferrorFlag = 1;
	return EOF;
}

/* put character in stream */
int so_fputc(int c, SO_FILE *stream)
{
	stream->lastOp = 1;
	if (stream != NULL) { /* flush if buffer is full */
		if (stream->crpoz >= stream->crbufsize) {
			stream->bytesRead += stream->crbufsize;
			if (so_fflush(stream) == EOF)
				return EOF;
		}
		/* otherwise add to buffer */
		stream->buf[stream->crpoz] = c;
		stream->crpoz++;
		return c;
	}
	stream->ferrorFlag = 1;
	return EOF;
}

/* write data py calling fputc */
size_t so_fwrite(const void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	char *charPtr = (char *) ptr;
	int bytesToWrite = nmemb * size;

	for (int i = 0; i < bytesToWrite; i++) {
		if (so_fputc(*(charPtr + i), stream) == EOF
				&& *(charPtr + i) != EOF)
			return i / size;
	}

	return nmemb / size;
}

/* get char from stream */
int so_fgetc(SO_FILE *stream)
{
	stream->lastOp = 2;
	int readBytes = 0;
	/* read from buffer if you can, otherwise do syscall */
	if ((stream->crpoz == 0 && stream->buf[stream->crpoz] == '\0')
			|| stream->crpoz == stream->crbufsize) {
		readBytes = read(stream->fd, stream->buf, BUFSIZE);
		if (readBytes > 0) {
			if (stream->crpoz == stream->crbufsize)
				stream->bytesRead += readBytes;

			stream->crbufsize = readBytes;
			stream->crpoz = 0;
		} else {
			stream->ferrorFlag = 1;
			return EOF;
		}
	}

	int res = (int)stream->buf[stream->crpoz];

	stream->crpoz++;

	return res;
}

/* read from stream by calling fgetc */
size_t so_fread(void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	int bytesToRead = nmemb * size;

	for (int i = 0; i < bytesToRead; i++) {
		int charRead = so_fgetc(stream);

		if (so_feof(stream) == 0)
			*((char *)ptr + i) = charRead;
		else
			return i / size;
	}

	return nmemb / size;
}

/* return feof */
int so_feof(SO_FILE *stream)
{
	return stream->ferrorFlag;
}

/* return ferror */
int so_ferror(SO_FILE *stream)
{
	return stream->ferrorFlag;
}

/* fseek to pos by calling lseek */
int so_fseek(SO_FILE *stream, long offset, int whence)
{
	/* flush regardless of seek result */
	so_fflush(stream);

	int seekedPoz = lseek(stream->fd, offset, whence);

	if (seekedPoz >= 0) {
		stream->bytesRead = seekedPoz;
		return 0;
	}

	return -1;
}

/* calculate stream pos = bytes read + poz in buf */
long so_ftell(SO_FILE *stream)
{
	return stream->bytesRead + stream->crpoz;
}


SO_FILE *so_popen(const char *command, const char *type)
{
	int fd[2];
	int childpid = -1;

	pipe(fd);

	SO_FILE *file = (SO_FILE *)malloc(sizeof(SO_FILE));

	file->buf = (char *)malloc(sizeof(char) * BUFSIZE);
	childpid = fork();
	if (childpid == -1) {
		free(file->buf);
		free(file);
		return NULL;
	}

	if (childpid == 0) {
		if (strchr(type, 'r')) {
			if (fd[1] != STDOUT_FILENO) {
				dup2(fd[1], STDOUT_FILENO);
				close(fd[1]);
				fd[1] = STDOUT_FILENO;
			}
			close(fd[0]);
		} else if (strchr(type, 'w')) {
			if (fd[0] != STDIN_FILENO) {
				dup2(fd[0], STDIN_FILENO);
				close(fd[0]);
			}
			close(fd[1]);
		}

		execlp("/bin/sh", "sh", "-c", command, NULL);
		return NULL;
	}

	/* in parent proc */
	int file_descriptor;

	if (strchr(type, 'r')) {
		file_descriptor = fd[0];
		close(fd[1]);
	}

	if (strchr(type, 'w')) {
		file_descriptor = fd[1];
		close(fd[0]);
	}

	memset(file->buf, 0, BUFSIZE);
	file->crpoz = 0;
	file->crbufsize = BUFSIZE;
	file->fd = file_descriptor;
	file->ferrorFlag = 0;
	file->bytesRead = 0;
	file->lastOp = 0;
	file->pid = childpid;
	return file;
}
int so_pclose(SO_FILE *stream)
{
	int pid = -1, pstat = -1;
	int waitedPid = stream->pid;
	so_fclose(stream);

	pid = waitpid(waitedPid, &pstat, 0);

	if (pid == -1)
		return -1;

	return pstat;
}
