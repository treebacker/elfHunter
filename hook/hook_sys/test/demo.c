#include <stdio.h>
#include <stdlib.h>


int main(int argc, char const *argv[])
{
	char a[0x10];
	a[0] = '1';
	a[1] = '2';
	a[2] = '3';
	a[3] = '4';
	a[4] = '5';
	a[5] = '6';
	a[6] = '7';
	a[7] = '8';
	a[8] = '9';
	a[9] = '0';

	int t = 1;
	while(t >= 0)
	{
		scanf("%d", &t);
		switch(t){
			default:
				printf("It's %c\n", a[t]);
		}
	}

}