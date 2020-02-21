#include "hook.h"

extern int incalling;
void checkArg(int argc, char* argv[], char* envp[]){
	if(argc < 2){
		puts("At least one param for target_process!");
		exit(1);
	}
	return;
}

void tracerwork(pid_t tracee){
	long orig_rax;
	struct user_regs_struct regs;
	int status;
	while(1)
	{
		wait(&status);
		if(WIFEXITED(status))
        {
            break;
        }
		orig_rax = ptrace(PTRACE_PEEKUSER,
	                              tracee, 8 * ORIG_RAX,
	                              NULL);
		switch (orig_rax){
			case SYS_write:
				Hunter_write(tracee);
				break;
			case SYS_read:
				Hunter_read(tracee);
				break;
			default:
				break;
		}
		//change syscall state
		ptrace(PTRACE_SYSCALL, tracee, NULL, NULL);
	}
}

int Hunter_write(pid_t tracee)
{
	long orig_rax;
	struct user_regs_struct regs;
	int status;
	ptrace(PTRACE_GETREGS, tracee, NULL, &regs);
	/*enter syscall*/
	if(!incalling){
		printf("Enter Sys_write call with: regs.rdi [%ld], regs.rsi[%ld], regs.rdx[%ld], regs.rax[%ld], regs.orig_rax[%ld]\n",
                    regs.rdi, regs.rsi, regs.rdx,regs.rax, regs.orig_rax);

	}
	/*leave syscall*/
	else{
		printf("[Leave SYS_write call] return regs.rax [%ld], regs.orig_rax [%ld]\n", regs.rax, regs.orig_rax);
	}
	incalling = !incalling;

}
int Hunter_read(pid_t tracee)
{
	long orig_rax;
	struct user_regs_struct regs;
	int status;
	ptrace(PTRACE_GETREGS, tracee, NULL, &regs);
	/*enter syscall*/
	if(!incalling){
		printf("Enter Sys_read call with: regs.rdi [%ld], regs.rsi[%ld], regs.rdx[%ld], regs.rax[%ld], regs.orig_rax[%ld]\n",
                    regs.rdi, regs.rsi, regs.rdx,regs.rax, regs.orig_rax);

	}
	/*leave syscall*/
	else{
		printf("[Leave SYS_read call return regs.rax [%ld], regs.orig_rax [%ld]\n", regs.rax, regs.orig_rax);
	}
	incalling = !incalling;
}