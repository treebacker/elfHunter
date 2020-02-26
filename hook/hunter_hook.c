#include "hook_libc.h"
#include "hook_sys.h"

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
		wait(NULL);				//must need
		plthook_t *plthook;
		//pre_sys_hook();
		//tracerwork(childPid);
		breakpoint(childPid, 0x400566);
		plthook_open(&plthook, argv[1], childPid);
		//plthook_put(plthook);
	}
}