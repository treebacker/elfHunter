#include <stdio.h>
#include <stdlib.h>

void changepointer(char** str){
	puts(str);
	*str = malloc(0x10);
	puts(*str);
	memcpy(*str, "change", 6);
	puts(*str);
}
int main(int argc, char const *argv[])
{
	char *str = malloc(0x10);
	memcpy(str, "strstr", 6);
	changepointer(&str);
	puts(str);
	return 0;
}