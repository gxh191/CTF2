#include <stdio.h>
#include <string.h>

// gcc arbitrary_write_fread.c -o arbitrary_write_fread

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

int main(void)
{
    _IO_FILE *p;
    char target[] = "Programmer: You can't change me\n";
    char buf[0x20] = { 0 };

    printf("Let's Demo a arbitrary write\n");

    p = fopen("fread.txt", "r+");
    p->_IO_buf_base = target;
    p->_IO_buf_end  = target + sizeof(buf) + 1;
    p->_fileno = 0;
    
    fread(buf, 1, sizeof(buf), p);

    puts(target);
}


