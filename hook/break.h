#include <unistd.h>

#define maxBreakLen 0x1000
#define breakIndex(bkaddr)	((bkaddr) % maxBreakLen)

//breakpoint address's value
union breakval{
    size_t val;
    unsigned char chars[sizeof(size_t)];
};

typedef int (*Hunter_hook)(pid_t tracee);
//breakpoint info
struct breakpoint{
	size_t bkaddr;	//addr % 0x1000
	Hunter_hook dealfunc;	//Hunter function
	union breakval bakval;	//breakpoint's value

};

typedef union breakval bkvalue;
typedef struct breakpoint bkpoint;


void setbreak(pid_t tracee, bkpoint* bkp);
void singalstep(pid_t tracee, bkpoint* bkp);
void clearbreak(pid_t tracee, bkpoint* bkp);