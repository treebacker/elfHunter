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
		plthook_open(&plthook, argv[1], childPid);

		//set syscall hook & libc hook
		//pre_sys_hook();
		pre_libc_hook(childPid, plthook);


		puts("hook libc over!");
		tracerwork(childPid);
	}
}