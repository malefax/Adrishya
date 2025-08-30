#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>


#define SPLICE_LEN 4096 // size of data to splice per iteration

int main(int argc, char *argv[]) {
    int fd_in, fd_out, pipefd[2];
    ssize_t spliced;
    off_t off_in = 0, off_out = 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    
    fd_in = open(argv[1], O_RDONLY);
    if (fd_in < 0) {
        perror("open input");
        return 1;
    }

    fd_out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out < 0) {
        perror("open output");
        close(fd_in);
        return 1;
    }


    if (pipe(pipefd) == -1) {
        perror("pipe");
        close(fd_in);
        close(fd_out);
        return 1;
    }

    while (1) {
        
        spliced = splice(fd_in, &off_in, pipefd[1], NULL, SPLICE_LEN, 0);
        if (spliced == 0)
            break; // EOF
        if (spliced < 0) {
            perror("splice read");
            break;
        }

        
        spliced = splice(pipefd[0], NULL, fd_out, &off_out, spliced, 0);
        if (spliced < 0) {
            perror("splice write");
            break;
        }
    }

    close(fd_in);
    close(fd_out);
    close(pipefd[0]);
    close(pipefd[1]);

    
    return 0;
}

