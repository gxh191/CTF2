#include <stdio.h>
#include <string.h>

// gcc arbitrary_write_scanf.c -o arbitrary_write_scanf

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
    char target[] = "Programmer: You can't change me\n";
    char buf[0x20] = { 0 };

    printf("Let's Demo a arbitrary write\n");

    p = stdin;
    p->_IO_buf_base = target;
    p->_IO_buf_end  = target + strlen(target);

    printf("You can write to buf, but cannot write to target:\n");
    scanf("%31s", buf);
    
    puts("buf:");
    puts(buf);
    puts("target:");
    puts(target);
}


