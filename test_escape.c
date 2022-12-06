#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char* escape_string(char*);

int main() {
    char c = (char)strtol("27", (char**)NULL, 16);
    char a[2];
    a[0] = c;
    a[1] = '\0';
    printf("[%s]\n", a);


    char s[] = "Don&#x27;t call me";
    printf("escape [%s] \n", escape_string(s));
    return 0;
}
