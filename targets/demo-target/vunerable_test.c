#include <stdio.h>

char *gets(char *);

int main(void) {
    char buf[1];

    gets(buf);   // intentionally vulnerable

    return 0;
}