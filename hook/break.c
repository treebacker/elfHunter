#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>

#include "break.h"


extern void setbreak(pid_t tracee, bkpoint* bkp)
{
    bkvalue int3;
 	//make a bak for this breakpoint
	int3.val = ptrace(PTRACE_PEEKDATA, tracee, bkp->bkaddr, NULL);
	bkp->bakval.val = int3.val;

	int3.chars[0]=0xcc;
	//write 0xcc to this addr
	ptrace(PTRACE_POKEDATA, tracee, bkp->bkaddr, int3.val);
	//ptrace(PTRACE_CONT, tracee, 0, 0);
}

extern void singalstep(pid_t tracee, bkpoint* bkp)
{
	struct user_regs_struct regs;

	//write the value back
	ptrace(PTRACE_POKEDATA, tracee, bkp->bkaddr, bkp->bakval);

	//rip - 1
	ptrace(PTRACE_GETREGS, tracee, NULL, &regs);
	regs.rip -= 1;

	ptrace(PTRACE_SETREGS, tracee, 0, &regs);
    ptrace(PTRACE_SINGLESTEP, tracee, 0, 0);
    wait(0);

    //set break point again
    setbreak(tracee, bkp);
}
extern void clearbreak(pid_t tracee, bkpoint* bkp)
{
	//write breakpoint's bak value
	ptrace(PTRACE_POKEDATA, tracee, bkp->bkaddr, bkp->bakval);
	ptrace(PTRACE_CONT, tracee, 0, 0);
}