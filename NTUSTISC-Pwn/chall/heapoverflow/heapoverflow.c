#include <stdio.h>
#include <stdlib.h>

// gcc heapoverflow.c -o heapoverflow

typedef struct {
    char name[8];
    int privilege;
    char *msg;
    char reserved[0x18];
} Info;

void init()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
}

int main(void)
{
    Info *info;
    char *msg;

    init();

    printf("Hello~\n");
    printf("give me your msg: \n");

    msg = malloc(40);
    info = malloc(sizeof(Info));

    strcpy(info->name, "User");
    info->privilege = 2;
    info->msg = msg;

    read(0, msg, 0x40);

    printf("Checking privilege...\n");
    if (info->privilege == 1) {
        printf("Hello Admin %s\n", info->name);
    } else {
        printf("Your privilege is too low QQ, Bye %s\n", info->name);
    }

    return 0;
}

