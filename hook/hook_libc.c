#include "hook_libc.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>

//open
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define Mapfile "/proc/%d/maps"

//elf
#include "allelf.h"
#include "break.h"


//breakpoints list info
bkpoint* break_list[0x1000];
struct plthook {
    //addr in tracee
    //cnt
    //copy data in tracer
    const void *dynsym;
    size_t dynsym_cnt;
    Elf_Sym *dynsym_out;

    const void *dynstr;
    size_t dynstr_size;
    char *dynstr_out;

    const void *rela_plt;
    size_t rela_plt_cnt;
    Elf_Rela *rela_plt_out;

    size_t plt;
    size_t plt_size;
    size_t codebase;
};

size_t getCodebase(pid_t pid)
{
    size_t addr;
    char buf[2 * sizeof(size_t)];
    char* end;
    char* mapfile[0x18];
    sprintf(mapfile, Mapfile, pid);
    int fd = open(mapfile, O_RDONLY);
    if(fd == -1)
    {
        perror("open maps");
        return 0;
    }
    read(fd, buf, 2 * sizeof(size_t));
    end = strchr(buf, '-');
    addr = strtol(buf, &end, 16);

    close(fd);
    return addr;
}

/*
    copy data from tracee's memory addr_in to addr_out
*/
void ptrace_getdata(pid_t tracee, char* addr_in, 
                        char** addr_out, size_t size)
{
    union traceval{
        int val;
        unsigned char chars[sizeof(int)];
    };

   // char* data_out;
    union traceval buf;
    unsigned int idx, num, mod;
    num = size / sizeof(int);
    mod = size % sizeof(int);

    //malloc a mem to store the data
    *addr_out = malloc(size);
    if(*addr_out == NULL){
        perror("malloc in ptrace_getdata");
    }
    //loop get data
    for(idx=0; idx < num; idx++){
        buf.val = ptrace(PTRACE_PEEKDATA, tracee, 
                                                addr_in, NULL);
        memcpy(*addr_out+idx*sizeof(int), buf.chars, sizeof(int));
        addr_in += sizeof(int);
    }
    
    if(mod){
        buf.val = ptrace(PTRACE_PEEKDATA, tracee,
                                                addr_in, NULL);
        memcpy(*addr_out+num*sizeof(int), buf.chars, mod);
    }

    return;
}


int plthook_open(plthook_t **plthook_out, const char *filename, pid_t tracee)
{
    plthook_t *plthook = NULL;

    const Elf_Dyn *dyn;
    const char *dyn_addr_base = NULL;
    puts(filename);
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
  
    if(check_elf_ident(fp) == 0){
        perror("check_elf_ident");
        return 1;
    }

    Elf_Ehdr *header = get_elf_header(fp);
    if(header == NULL){
        perror("get_elf_header");
        return 1;
    }
    Elf_Shdr *sec_header_tab = get_sec_header_tab(fp, header);
    if(sec_header_tab == NULL){
        perror("get_sec_header_tab");
        return 1;
    }
    //Get str_tab_header
    Elf_Shdr *str_tab_header = sec_header_tab + header->e_shstrndx;
    char* shstrtab = get_shstrtab(fp, str_tab_header);

    //Get plt section
    Elf_Shdr *plt = get_section_by_name(".plt",
                                        header,
                                        sec_header_tab,
                                        shstrtab);
    //Get dynsym section
    Elf_Shdr *dynsym = get_section_by_name(".dynsym",
                                            header,
                                            sec_header_tab,
                                            shstrtab);

    //Get rela.plt section
    Elf_Shdr *rela_plt = get_section_by_name(".rela.plt",
                                            header,
                                            sec_header_tab,
                                            shstrtab);

    Elf_Shdr *dynstr = get_section_by_name(".dynstr",
                                        header,
                                        sec_header_tab,
                                        shstrtab);


    if(plt == NULL || dynsym == NULL || rela_plt == NULL || dynstr == NULL){
        perror("plt || dynsym || rela_plt || dynstr");
    }

    plthook = malloc(sizeof(plthook_t));
    if(plthook == NULL){
        perror("malloc for plthook");
    }
    plthook->codebase = getCodebase(tracee);
    if(!plthook->codebase){
        perror("Failed to get codebase!");
        return 0;
    }

    plthook->plt = plt->sh_addr;
    plthook->dynsym = dynsym->sh_addr;
    plthook->dynstr = dynstr->sh_addr;
    plthook->rela_plt = rela_plt->sh_addr;

    plthook->plt_size = plt->sh_size;
    plthook->dynsym_cnt = dynsym->sh_size / (sizeof(Elf_Sym));
    plthook->dynstr_size = dynstr->sh_size;
    plthook->rela_plt_cnt = rela_plt->sh_size / (sizeof(Elf_Rela));


    //add codebase to virtual addr
    if(plthook->dynsym < 0x400000)
    {
        plthook->plt += ((size_t)plthook->plt + plthook->codebase);
        plthook->dynsym += ((size_t)(plthook->dynsym) + plthook->codebase);
        plthook->dynstr += plthook->codebase;
        plthook->rela_plt += ((size_t)(plthook->rela_plt) +  plthook->codebase);
    }

    ptrace_getdata(tracee, plthook->dynstr, &(plthook->dynstr_out), plthook->dynstr_size);
    ptrace_getdata(tracee, plthook->dynsym, &(plthook->dynsym_out), plthook->dynsym_cnt * sizeof(Elf_Sym));
    ptrace_getdata(tracee, plthook->rela_plt, &(plthook->rela_plt_out), plthook->rela_plt_cnt * sizeof(Elf_Rela));

    if(plthook->dynstr_out == NULL)
    {
        puts("out pointer failed!");
    }
  
    /* test find_plt
    size_t addr = find_plt(plthook, "__isoc99_scanf");
    if(addr == 0){
        perror("find_plt");
        exit(0);
    }
    printf("scanf address: %p\n", addr);
    */

    *plthook_out = plthook;
    return 0;
}

//find function'plt by function name
size_t find_plt(plthook_t *plthook, const char* funcname)
{
    char* now_name;
    Elf_Sym now_dynsym;
    Elf_Rela now_rela_plt;
    Elf_Xword st_name = 0;
    Elf_Xword r_info = 0;
    size_t i;
    int plt_index = 0;

    //find function name in dynstr
    //where funtion name is string splited with \x00
    for(i=0; i < plthook->dynstr_size; i++)
    {
        now_name = plthook->dynstr_out + i;
       // puts(now_name);
        if(strcmp(now_name, funcname) == 0){
            st_name = i;
           // printf("st_name: %d\n", st_name);
            break;
        }
        i += strlen(now_name);
    }

    //find the st_name in .dynsym
    for(i=0; i<plthook->dynsym_cnt; i++){

        now_dynsym = plthook->dynsym_out[i];
        if(now_dynsym.st_name == st_name){
            r_info = stname_to_info(i);
         //   printf("r_info: %x\n", r_info);

            break;
        }
    }

    //find the r_info in .rela.plt
    for(i=0; i<plthook->rela_plt_cnt; i++) {

        now_rela_plt = plthook->rela_plt_out[i];
        if(now_rela_plt.r_info == r_info){
            //jmp over PLT[0]

            plt_index = i+1;
            //printf("st_name: %d\n", st_name);
            //printf("r_info: %x\n", r_info);
            //printf("plt_index: %d\n", plt_index);
            break;
        }
    }

    if((plt_index >0) && ((plt_index+1) * 0x10 <= plthook->plt_size))
        return (plthook->plt + plt_index*0x10);

    //failed to find this function's plt
    return 0;

}

void pre_libc_hook(pid_t tracee, plthook_t* plthook)
{
    Hunter_libc_reg(tracee, plthook, "puts", Hunter_puts);
    Hunter_libc_reg(tracee, plthook, "__isoc99_scanf", Hunter_scanf);
}

void Hunter_libc_reg(pid_t tracee, plthook_t* plthook, const char* name, Hunter_libc_hook Hunter_function)
{
    bkpoint *bk = NULL;
    bk = malloc(sizeof(size_t)*3+1);
    if(!bk){
        perror("error in malloc for breakpoint!");
        return;
    }

    size_t plt_addr = find_plt(plthook, name);
    if(!plt_addr){
        perror("find plt");
        return;
    }

    printf("%s's plt: 0x%x\n", name, plt_addr);
    //set break info
    bk->bkaddr = plt_addr;
    bk->dealfunc = Hunter_function;

    //set 0xcc
    setbreak(tracee, bk);
    break_list[breakIndex(bk->bkaddr)] = bk;
    printf("Hook %s success!", name);
    return ;
}

void Hunter_libc_unreg(pid_t tracee, plthook_t* plthook, const char* name){
    size_t plt_addr = find_plt(plthook, name);
    if(plt_addr == NULL){
        perror("find plt");
        return;
    }
    //clear break info
    clearbreak(tracee, break_list[breakIndex(plt_addr)]);

    free(break_list[breakIndex(plt_addr)]);
    break_list[breakIndex(plt_addr)] = NULL;
    printf("Unhook %s success!", name);
    return ;
}

int Hunter_puts(pid_t tracee)
{
    puts("tracee is at puts");
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, tracee, 0, &regs);

    //puts args
    char* puts_str;
    printf("data addr: 0x%x", regs.rdi);
    ptrace_getdata(tracee, regs.rdi, &puts_str, 5);
    printf("puts_str: %s\n", puts_str);
    return 0;
}

int Hunter_scanf(pid_t tracee)
{
    puts("tracee is at scanf");
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, tracee, 0, &regs);

    //printf's fmt
    char* scanf_fmt;
    printf("data addr: 0x%x", regs.rdi);
    ptrace_getdata(tracee, regs.rdi, &scanf_fmt, 2);
    printf("scanf_fmt: %s\n", scanf_fmt);
    return 0;
}

//dynsym
int
check_elf_ident(FILE *stream)
{
    int elf_type = 0;
    unsigned char e_ident[EI_NIDENT];
    long offset = ftell(stream);

    if (fread(e_ident, 1, EI_NIDENT, stream) != EI_NIDENT) {
        fprintf(stderr, "%s\n", "Incomplete ELF Identification!");
        goto restore_file_offset_and_return_error;
    }

    if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s\n", "Bad ELF Magic Number!");
        goto restore_file_offset_and_return_error;
    }

    //little or big endian
    if (e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "%s\n", "We Only Support Elf LE!");
        goto restore_file_offset_and_return_error;
    }
    //32 or 64bits
    else if(e_ident[EI_CLASS] == ELFCLASS64){
        printf("Target is 64bits!\n");
        elf_type = 2;
    }
    else if(e_ident[EI_CLASS] == ELFCLASS32){
        printf("Target is 32bits!\n");
        elf_type = 1;
    }

    fseek(stream, offset, SEEK_SET);
    return elf_type;

 restore_file_offset_and_return_error:
    fseek(stream, offset, SEEK_SET);
    return elf_type;
}


Elf_Ehdr *
get_elf_header(FILE *stream)
{
    Elf_Ehdr *header = malloc(sizeof *header);
    if (header == NULL) {
        perror("malloc");
        return NULL;
    }

    long offset = ftell(stream);
    if (fread(header, 1, sizeof *header, stream) != sizeof *header) {
        fprintf(stderr, "%s\n", "Incomplete ELF Header!");
        header = NULL;
    }

    fseek(stream, offset, SEEK_SET);
    return header;
}


Elf_Shdr *
get_sec_header_tab(FILE *stream, Elf_Ehdr *header)
{
    size_t size = header->e_shnum * header->e_shentsize;
    long offset = ftell(stream);

    Elf_Shdr *sec_header_tab = malloc(size);
    if (sec_header_tab == NULL) {
        perror("malloc");
        goto restore_file_offset_and_return_error;
    }

    fseek (stream, header->e_shoff, SEEK_CUR);
    if (fread(sec_header_tab, 1, size, stream) != size) {
        fprintf(stderr, "%s\n", "Incomplete Section Header Table!");
        goto restore_file_offset_and_return_error;
    }

    fseek(stream, offset, SEEK_SET);
    return sec_header_tab;

 restore_file_offset_and_return_error:
    fseek(stream, offset, SEEK_SET);
    return NULL;
}


char *
get_shstrtab(FILE *stream,
             Elf_Shdr *str_tab_header)
{
    size_t size = str_tab_header->sh_size;
    long offset = ftell(stream);

    char *str_tab = malloc(size);
    if (str_tab == NULL) {
        perror("malloc");
        goto restore_file_offset_and_return_error;
    }

    fseek (stream, str_tab_header->sh_offset, SEEK_CUR);
    if (fread(str_tab, 1, size, stream) != size) {
        fprintf(stderr, "%s\n",
                "Incomplete Section Header String Table!");
        goto restore_file_offset_and_return_error;
    }

    fseek(stream, offset, SEEK_SET);
    return str_tab;

 restore_file_offset_and_return_error:
    fseek(stream, offset, SEEK_SET);
    return NULL;
}

Elf_Shdr *
get_section_by_name(const char *name,
                    Elf_Ehdr *header,
                    Elf_Shdr *sec_header_tab,
                    char *str_tab)
{
    for (unsigned num = 0; num < header->e_shnum; num += 1) {
        Elf_Shdr *sec_header = sec_header_tab + num;
        char *sec_name = str_tab + sec_header->sh_name;
        if (strcmp(sec_name, name) == 0) {
            return sec_header;
        }
    }

    return NULL;
}