#include <stdio.h>
#include <string.h>

// gcc arbitrary_read_puts.c -o arbitrary_read_puts

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
} _IO_FILE;

int main(void)
{
    _IO_FILE *p;
    char buf[] = "Programmer: You can't see me\n";

    printf("Let's Demo a arbitrary read\n");

    p = stdout;
    p->_IO_read_end   = buf;
    p->_IO_write_base = buf;
    p->_IO_write_ptr  = buf + strlen(buf);
    p->_IO_buf_end    = buf + strlen(buf);

    puts("Hacker: uhhh, but I can\n");
}


