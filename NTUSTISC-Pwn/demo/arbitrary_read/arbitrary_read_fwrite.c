#include <stdio.h>
#include <string.h>

// gcc arbitrary_read_fwrite.c -o arbitrary_read_fwrite

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
    char buf[] = "Programmer: You can't see me\n";

    printf("Let's Demo a arbitrary read\n");

    p = fopen("fwrite.txt", "w+");
    p->_flags        |= _IO_LINE_BUF;
    p->_IO_read_end   = buf;
    p->_IO_write_base = buf;
    p->_IO_write_ptr  = buf + strlen(buf);
    p->_IO_buf_end    = buf + strlen(buf);
    p->_fileno = 1;

    fwrite(buf, 1, sizeof(buf), p);
}


