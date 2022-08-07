#include <stdio.h>
#include <stdlib.h>

// Testing in libc-2.27
// gcc tcache_dup.c -o tcache_dup

char *g_ptrs;
int g_size;
int g_used;

void init()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
}

int read_num()
{
    int num;
    
    scanf("%d", &num);

    return num;
}

void menu()
{
    puts("=== Note System v0.087 ===");
    puts("1) Create Note");
    puts("2) Get Note");
    puts("3) Set Note");
    puts("4) Delete Note");
    puts("5) Bye");
    printf("# ");
}

void create()
{
    int size;

    printf("size:\n");
    scanf("%d", &size);

    g_ptrs = malloc(size);
    g_size = size;
    g_used = 1;
}

void get()
{
    if (g_used) {
        printf("g_ptrs: %s\n", g_ptrs);
    }
}

void set()
{
    if (g_used) {
        printf("str:\n");
        read(0, g_ptrs, g_size);
    }
}

void delete()
{
    if (g_ptrs) {
        free(g_ptrs);
        g_used = 0;
    }
}

int main(void)
{
    init();
    
    char name[100];

    puts("Name:");
    read(0, name, 0x100);
    printf("Hello, %s\n", name);

    while(1) {
        menu();
        switch(read_num()) {
        case 1:
            create();
            break;
        case 2:
            get();
            break;
        case 3:
            set();
            break;
        case 4:
            delete();
            break;
        case 5:
            return 0;
        default:
            exit(1);
        }
    }

    return 0;
}
