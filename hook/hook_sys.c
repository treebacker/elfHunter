#include "hook_sys.h"
#include "hook_libc.h"
#include "break.h"
// global mark for syscall state 
// enter | exita
int incalling = 0;

//global sys_hook_table
Hunter_sys_hook Sys_hook[0x300];
//global break points info

extern bkpoint* break_list[0x1000];
void checkArg(int argc, char* argv[], char* envp[]){
	if(argc < 2){
		puts("At least one param for target_process!");
		exit(1);
	}
	return;
}

void tracerwork(pid_t tracee){
	long orig_rax, orig_rip;
	struct user_regs_struct regs;
	siginfo_t sig;
	int status;
	while(1)
	{
		orig_rax = ptrace(PTRACE_PEEKUSER,
	                              tracee, 8 * ORIG_RAX,
	                              NULL);
        ptrace(PTRACE_GETSIGINFO, tracee, 0, &sig);
        ptrace(PTRACE_GETREGS, tracee, 0, &regs);
		
        //判断是否到达 hook 
        //PTRACE_SYSCALL下　syscall 和 breakpoint 都会触发SIGTRAP
        if((sig.si_signo == SIGTRAP)){

        	if(break_list[breakIndex(regs.rip-1)])
	        {
	        	break_list[breakIndex(regs.rip-1)]->dealfunc(tracee);
	        	singalstep(tracee, break_list[breakIndex(regs.rip-1)]);
	        }
	        if(Sys_hook[orig_rax])
	        {
	        	Sys_hook[orig_rax](tracee);
	        }
        }

		//change syscall state
		ptrace(PTRACE_SYSCALL, tracee, NULL, NULL);
		wait(&status);

		if(WIFEXITED(status))
        {
            break;
        }
	}
}

void pre_sys_hook(){
	Hunter_sys_reg(SYS_write, Hunter_sys_write);
	Hunter_sys_reg(SYS_read, Hunter_sys_read);
}
//demo hook_sys do function
int Hunter_sys_write(pid_t tracee)
{
	long orig_rax;
	struct user_regs_struct regs;
	int status;
	ptrace(PTRACE_GETREGS, tracee, NULL, &regs);
	/*Entry write syscall*/
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
int Hunter_sys_read(pid_t tracee)
{
	long orig_rax;
	struct user_regs_struct regs;
	int status;
	ptrace(PTRACE_GETREGS, tracee, NULL, &regs);
	/*enter syscall*/
	if(!incalling){
		printf("Enter Sys_read call with: regs.rdi [%ld], regs.rsi[%ld], regs.rdx[%ld], regs.rax[%ld], regs.orig_rax[%ld]\n",
                    regs.rdi, regs.rsi, regs.rdx,regs.rax, regs.orig_rax);
		//check_stack(tracee);
	}
	/*leave syscall*/
	else{
		printf("[Leave SYS_read call return regs.rax [%ld], regs.orig_rax [%ld]\n", regs.rax, regs.orig_rax);
	}
	incalling = !incalling;
}


//define two functions for syscall callback function reg | unreg
void Hunter_sys_reg(long syscall, Hunter_sys_hook callback){
	//to do
	//other check
	Sys_hook[syscall] = callback;
}

void Hunter_sys_unreg(long syscall){
	Sys_hook[syscall] = NULL;
}

void check_stack(tracee){
	long orig_rax;
	struct user_regs_struct regs;
	int status;
	ptrace(PTRACE_GETREGS, tracee, NULL, &regs);

	//test rbp  >= buf_base + length
	puts("Check********************");
	printf("rbp: %lx, rsi: %lx, rdx: %lx\n", regs.rbp, regs.rsi, regs.rdx);
	if(regs.rbp < regs.rsi + regs.rdx){
		puts("[xxx]Buffer over flow!");
	}

}