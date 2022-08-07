#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

// gcc arbitrary_write_puts.c -o arbitrary_write_puts

typedef struct {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    void *_markers;
    void *_chain;
    int _fileno;
} _IO_FILE;

#define _IO_LINE_BUF 0x0200

int main(void)
{
    _IO_FILE *p;
    char target[] = "Programmer: You can't change me";
    char buf[] = "Hacker: Hello!";

    printf("Let's Demo a arbitrary write\n");

    p = stdout;
    p->_IO_write_ptr = target;

    puts(buf);
    
    // Don't use stdout
    syscall(1, 1, "---\n", 4);
    syscall(1, 1, target, strlen(target));
    syscall(1, 1, "\n---\n", 5);
}


