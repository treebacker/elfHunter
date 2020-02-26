#include <stdio.h>
#include <stdlib.h>

int main(){
	char buf[0x10] = {0};
	read(0, buf, 0x40);
	write(1, buf, strlen(buf));
}