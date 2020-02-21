#include "hook.h"

// global mark for syscall state 
// enter | exit
int incalling = 0;
int main(int argc, char* argv[], char* envp[])
{
	checkArg(argc, argv, envp);
	pid_t childPid;
	char** childArgv;			//tracee's argv

	childArgv = (char**)&argv[1];
	childPid = fork();
	if(childPid == 0){
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execve(argv[1], childArgv, envp);
	}
	else{
		tracerwork(childPid);
	}
}