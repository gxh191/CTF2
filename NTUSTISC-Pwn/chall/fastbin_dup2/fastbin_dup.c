#include <stdio.h>
#include <stdlib.h>

// Testing in libc-2.31
// gcc fastbin_dup.c -o fastbin_dup

char *g_ptrs[0x20];
int g_size[0x20];
int g_used[0x20];
int idx = 0;

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
    puts("=== Note System v1.87 ===");
    puts("1) Create Note");
    puts("2) Create Note in NEW way");
    puts("3) Get Note");
    puts("4) Set Note");
    puts("5) Delete Note");
    puts("6) Bye");
    printf("# ");
}

void create()
{
    int size;

    if (idx >= 0x20) {
        return;
    }

    printf("size:\n");
    scanf("%d", &size);

    g_ptrs[idx] = malloc(size);
    g_size[idx] = size;
    g_used[idx] = 1;
    
    printf("Create: g_ptrs[%d]\n", idx);

    idx++;
}

void create2()
{
    int size;

    if (idx >= 0x20) {
        return;
    }

    printf("size:\n");
    scanf("%d", &size);

    g_ptrs[idx] = calloc(1, size);
    g_size[idx] = size;
    g_used[idx] = 1;
    
    printf("Create: g_ptrs[%d]\n", idx);

    idx++;
}

void get()
{
    int idx;

    printf("idx:\n");
    scanf("%d", &idx);

    if (g_used[idx]) {
        printf("g_ptrs[%d]: %s\n", idx, g_ptrs[idx]);
    }
}

void set()
{
    int idx;

    printf("idx:\n");
    scanf("%d", &idx);

    if (g_used[idx]) {
        printf("str:\n");
        read(0, g_ptrs[idx], g_size[idx]);
    }
}

void delete()
{
    int idx;

    printf("idx:\n");
    scanf("%d", &idx);
    
    if (g_ptrs[idx]) {
        free(g_ptrs[idx]);
        g_used[idx] = 0;
    }
}

int main(void)
{
    init();

    while(1) {
        menu();
        switch(read_num()) {
        case 1:
            create();
            break;
        case 2:
            create2();
            break;
        case 3:
            get();
            break;
        case 4:
            set();
            break;
        case 5:
            delete();
            break;
        case 6:
            return 0;
        default:
            exit(1);
        }
    }

    return 0;
}
