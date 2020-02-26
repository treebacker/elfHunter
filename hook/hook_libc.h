#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>
#include <errno.h>
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include "allelf.h"



typedef struct plthook plthook_t;
//get target process's dynsym information
int plthook_open(plthook_t **plthook_out, const char* filename, pid_t tracee);
int plthook_replace(plthook_t *plthook, const char *funcname, void *funcaddr, void **oldfunc);
void plthook_close(plthook_t *plthook);

size_t
find_plt(plthook_t *plthook, const char* funcname);

void ptrace_getdata(pid_t tracee, char* addr_in, 
                        char** addr_out, size_t size);
int
check_elf_ident(FILE *stream);
Elf_Ehdr *
get_elf_header(FILE *stream);
Elf_Shdr *
get_sec_header_tab(FILE *stream, Elf_Ehdr *header);
char *
get_shstrtab(FILE *stream,
             Elf_Shdr *str_tab_header);
Elf_Shdr *
get_section_by_name(const char *name,
                    Elf_Ehdr *header,
                    Elf_Shdr *sec_header_tab,
                    char *str_tab);