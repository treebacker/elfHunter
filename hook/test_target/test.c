#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[], char* envp[])
{
	int i=0;
	char** childArgv =(char**)&argv[1];
	for(i=0; i<argc-1; i++)
	{
		printf("%d: %s\n",i, childArgv[i]);
	}
	return 0;
}