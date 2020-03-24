#include "so_stdio.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#define BUFFERSIZE 4096
#define LAST_OP_WRITE 1
#define LAST_OP_READ 2

struct _so_file
{
    int file_descriptor;
    int cnt; /* index in buff */
    int size; /* bytes in buff */
    int err; /* error flag */
    int flag; /* last operation */
    int read; /* size of file */
    int pid;
    int eof; /* flag for end of file */
    unsigned char *ptr; /* pointer to current pos in buf */
    unsigned char *buffer;
};

/* parse the mode and convert it */
/* to an actual mod for open call */
int parse_mode(const char *mode)
{
    if(strcmp(mode, "r") == 0)
    {
        return O_RDONLY;
    }
    else if (strcmp(mode, "r+") == 0)
    {
        return O_RDWR;
    }
    else if (strcmp(mode, "w") == 0)
    {
        return O_WRONLY | O_CREAT | O_TRUNC;
    }
    else if (strcmp(mode, "w+") == 0)
    {
        return O_RDWR | O_CREAT | O_TRUNC;
    }
    else if (strcmp(mode, "a") == 0)
    {
        return O_WRONLY | O_CREAT | O_APPEND;
    }
    else if (strcmp(mode, "a+") == 0)
    {
        return O_RDWR | O_CREAT | O_APPEND;
    }
    else 
    {
        return -1;
    }
}

/* if we still have something in buffer we write everything */
/* and also we check for last operation to be write */
int so_fflush(SO_FILE *stream)
{
	if (stream->cnt != 0)
    {
		if (stream->flag == LAST_OP_WRITE)
        {
            ssize_t bytes_write = write(stream->file_descriptor, stream->buffer, stream->cnt);
			if (bytes_write == -1)
            {
                stream->err = 1;
                return SO_EOF;
			}
            memset(stream->buffer, 0, BUFFERSIZE*sizeof(*stream->buffer));
            stream->cnt = 0;
            stream->size = BUFFERSIZE;
            stream->ptr = &stream->buffer[0];

            return 0;
		}
        else if (stream->flag == LAST_OP_READ)
        {
            memset(stream->buffer, 0, BUFFERSIZE);
			stream->cnt = 0;
			stream->size = BUFFERSIZE;
            stream->ptr = &stream->buffer[0];
			return 0;
		}
        stream->err = 1;
		return SO_EOF;
	} else {
    	return 0;
    }
}

/* parse mode, call open and init a SO_FILE variable */
SO_FILE *so_fopen(const char *pathname, const char *mode)
{
    int mod = parse_mode(mode);
    if (mod == -1)
    {
        return NULL;
    }

    int fd = open(pathname, mod, 0644);
    if (fd < 0)
    {
        return NULL;
    }

    SO_FILE *file;

    file = calloc(1, sizeof(SO_FILE));

    file->buffer = calloc(BUFFERSIZE, sizeof(char));

    file->cnt = 0;
    file->err = 0;
    file->pid = 0;
    file->eof = 0;
    file->flag = 0;
    file->read = 0;
    file->size = BUFFERSIZE;
    file->file_descriptor = fd;
    file->ptr = &file->buffer[0];
    
    return file;
}

/* call fflush, close the file and free the SO_FILE structure */
int so_fclose(SO_FILE *stream)
{
	int res = so_fflush(stream);

    int rc = close(stream->file_descriptor);

    if (rc == -1 || res == -1)
    {
        free(stream->buffer);
        stream->buffer = NULL;

        free(stream);
        stream = NULL;

        return SO_EOF;
    }

    free(stream->buffer);
    stream->buffer = NULL;

    free(stream);
    stream = NULL;

    return 0;
}

/* set flag for last op to read */
/* if the buffer is empty we put data in it*/
/* else we continue to read and return data from buffer */
int so_fgetc(SO_FILE *stream)
{
    stream->flag = LAST_OP_READ;
    if (stream->cnt == 0)
    {
        memset(stream->buffer, 0, BUFFERSIZE*sizeof(*stream->buffer));
        ssize_t bytes_read = read(stream->file_descriptor, stream->buffer, BUFFERSIZE);
        if (bytes_read == 0)
        {
            stream->eof = 1;
            return SO_EOF;
        }
        stream->size = bytes_read;
        stream->read = bytes_read;
        stream->cnt = bytes_read - 1;
        stream->ptr = &stream->buffer[0];
    }
    else {
        stream->cnt -= sizeof(char);
        stream->ptr++;
    }
    return *stream->ptr;
}

/* set flag for last op to write */
/* if the buffer is full we write data in the file*/
/* else we continue to put and return data to buffer */
int so_fputc(int c, SO_FILE *stream)
{
    stream->flag = LAST_OP_WRITE;
    if (stream != NULL)
    {
        if (stream->cnt == BUFFERSIZE)
        {
            stream->read += stream->size;
            if (write(stream->file_descriptor, stream->buffer, stream->cnt)
                    != -1)
            {
                memset(stream->buffer, 0, BUFFERSIZE*sizeof(*stream->buffer));
                stream->cnt = 0;
                stream->size = BUFFERSIZE;
                stream->ptr = &stream->buffer[0];
            }
            else
            {
                stream->err = 1;
                return SO_EOF;
            }
        }
        *stream->ptr = c;
        stream->cnt++;
        stream->ptr++;
        return c;
    }
    stream->err = 1;
    return SO_EOF;
}

/* return flag for end of the file */
int so_feof(SO_FILE *stream)
{
    return stream->eof;
}

/* return flag used if any error occurred */
int so_ferror(SO_FILE *stream)
{
    return stream->err;
}

/* call pipe, call fork */
/* parse type */
/* get file descriptor */
/* alloc struct for SO_FILE */
SO_FILE *so_popen(const char *command, const char *type)
{
    int fd[2];
	int pid = -1;

	pipe(fd);

	SO_FILE *file = (SO_FILE *)malloc(sizeof(SO_FILE));

	file->buffer = malloc(sizeof(char) * BUFFERSIZE);

	pid = fork();
	if (pid == -1) {
		free(file->buffer);
		free(file);
		return NULL;
	}

	if (pid == 0)
    {
		if (strchr(type, 'r'))
        {
			if (fd[1] != STDOUT_FILENO)
            {
				dup2(fd[1], STDOUT_FILENO);
				close(fd[1]);
				fd[1] = STDOUT_FILENO;
			}
			close(fd[0]);
		}
        else if (strchr(type, 'w'))
        {
			if (fd[0] != STDIN_FILENO)
            {
				dup2(fd[0], STDIN_FILENO);
				close(fd[0]);
			}
			close(fd[1]);
		}

		execlp("/bin/sh", "sh", "-c", command, NULL);
		return NULL;
	}

	int file_descriptor;
	if (strchr(type, 'r')) {
		file_descriptor = fd[0];
		close(fd[1]);
	}

	if (strchr(type, 'w')) {
		file_descriptor = fd[1];
		close(fd[0]);
	}

	memset(file->buffer, 0, BUFFERSIZE);
	file->cnt = 0;
	file->size = BUFFERSIZE;
	file->file_descriptor = file_descriptor;
	file->err = 0;
	file->read = 0;
	file->flag = 0;
    file->eof = 0;
	file->pid = pid;
    file->ptr = &file->buffer[0];
	return file;
}

/* close SO_FILe, get pid from waitpid and return status */
int so_pclose(SO_FILE *stream)
{
    int pid = -1, stat = -1;
	int pid_wait = stream->pid;
	so_fclose(stream);

	pid = waitpid(pid_wait, &stat, 0);

	if (pid == -1)
		return SO_EOF;

	return stat;
}

/* fflush the SO_FILE buffer */
/* call lseek */
int so_fseek(SO_FILE *stream, long offset, int whence)
{
    so_fflush(stream);

	int seekedPoz = lseek(stream->file_descriptor, offset, whence);

	if (seekedPoz >= 0) {
		stream->read = seekedPoz;
		return 0;
	}

	return SO_EOF;
}

/* return calculated values from read and cnt */
long so_ftell(SO_FILE *stream)
{
    return stream->read + (stream->flag == 2 ? stream->size - stream->cnt : stream->cnt);
}

/* iterate size * nmem and call so_fgetc and parse the return */
size_t so_fread(void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
    ssize_t bytes_read = 0;
    for (int i = 0; i < nmemb * size; ++i)
    {
        int c = so_fgetc(stream);
        if (so_feof(stream) == 0)
        {
            *((unsigned char *) ptr) = c;
            ptr++;
            bytes_read++;
        }
        else
        {
            return bytes_read / size;
        }
        
    }
    return bytes_read / size;
}

/* iterate size * nmem and call so_fputc and parse the return */
size_t so_fwrite(const void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
    ssize_t bytes_write = 0;
    for (int i = 0; i < nmemb * size; ++i)
    {
        int ch;
        ch = *((unsigned char *) ptr);
        int c = so_fputc(ch, stream);
        if (c == SO_EOF)
        {
            return bytes_write / size;
        }
        ptr++;
        bytes_write++;
    }
    return bytes_write / size;
}

/* return file descriptor */
int so_fileno(SO_FILE *stream)
{
    return stream->file_descriptor;
}
