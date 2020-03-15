#include <stdio.h>
#include <stdlib.h>

int main()
{
	char buf[0x10];
	scanf("%s", &buf);
	printf("scanf: %s\n", &buf);
	puts("over!");
	return 0;
}