#include <stdio.h>

// gcc intro.c -o intro -z lazy

void init()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
}

int main()
{
    init();

    printf("stdin: %p\n", stdin);
    printf("stdout: %p\n", stdout);
    printf("stderr: %p\n", stderr);

    puts("Yo");
    puts("Battle!");

    return 0;
}
