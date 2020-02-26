#include "hook_libc.h"
#include "dynsym/dynsym.h"


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#define Mapfile "/proc/%d/maps"

struct plthook {
    const Elf64_Sym *dynsym;
    const char *dynstr;
    size_t dynstr_size;
    const char *plt_addr_base;
    const Elf64_Rel *rela_plt;
    size_t rela_plt_cnt;
#ifdef R_GLOBAL_DATA
    const Elf64_Rel *rela_dyn;
    size_t rela_dyn_cnt;
#endif
};
size_t getCodebase(pid_t pid)
{
    size_t addr;
    char buf[2 * sizeof(size_t)];
    char* end;
    char* mapfile[0x18];
    sprintf(mapfile, Mapfile, pid);
    int fd = open(mapfile, "r");
    if(fd == -1)
    {
        printf("open maps error!");
        exit(1);
    }
    read(fd, buf, 2 * sizeof(size_t));
    end = strchr(buf, '-');
    addr = strtol(buf, &end, 16);
    printf("The codebase is: 0x%lx\n", addr);

    close(fd);
    return addr;
}

void ptrace_getdata(pid_t tracee, void* addr_in, 
                        void* addr_out, size_t size)
{
    return;
}


int plthook_open(plthook_t **plthook_out, const char *filename, pid_t tracee)
{
    plthook_t plthook = {NULL, };
    const Elf64_Dyn *dyn;
    const char *dyn_addr_base = NULL;

    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
    if(check_elf_ident(fp) != 0){
        perror("check_elf_ident");
        return 1;
    }

    Elf64_Ehdr *header = get_elf_header(fp);
    if(header == NULL){
        perror("get_elf_header");
        return 1;
    }

    Elf64_Shdr *sec_header_tab = get_sec_header_tab(fp, header);
    if(sec_header_tab == NULL){
        perror("get_sec_header_tab");
        return 1;
    }
    //Get str_tab_header
    Elf64_Shdr *str_tab_header = sec_header_tab + header->e_shstrndx;
    char* shstrtab = get_shstrtab(fp, str_tab_header);
    //Get got section
    Elf64_Shdr *got_plt = get_section_by_name(".got.plt",
                                            header,
                                            sec_header_tab,
                                            shstrtab);
    //Get dynsym section
    Elf64_Sym *dynsym = get_section_by_name(".dynsym",
                                            header,
                                            sec_header_tab,
                                            shstrtab);

    //Get rela.plt section
    Elf64_Rel *rela_plt = get_section_by_name(".rela.plt",
                                            header,
                                            sec_header_tab,
                                            shstrtab);
    if(dynsym == NULL || rela_plt == NULL ){
        perror("dynsym || rela_plt");
    }
    getCodebase(tracee);
    exit(1);
    struct link_map *lmap=0;


#ifdef R_GLOBAL_DATA
    /* get .rela.dyn or .rel.dyn section */
   Elf64_Rel rela_dyn = get_section_by_name(".rela.dyn",
                                            header,
                                            sec_header_tab,
                                            shstrtab);
   if(rela_dyn == NULL){
    perror("rela_dyn");
   }
   plthook.rela_dyn = rela_dyn.r_offset;
   plthook.rela_dyn = rela_dyn.
#endif

#ifdef R_GLOBAL_DATA
    if (plthook.rela_plt == NULL && plthook.rela_dyn == NULL) {
        perror("failed to find either of DT_JMPREL and DT_REL");
        return 1;
    }
#else
    if (plthook.rela_plt == NULL) {
        perror("failed to find DT_JMPREL");
        return 1;
    }
#endif

    *plthook_out = malloc(sizeof(plthook_t));
    if (*plthook_out == NULL) {
        perror("malloc");
        return 1;
    }
    plthook.dynsym = dynsym->st_value;
    plthook.dynstr = NULL;
    plthook.dynstr_size = 1;
    plthook.rela_plt = rela_plt->r_offset;
    plthook.rela_plt_cnt = 2;

    **plthook_out = plthook;
    return 0;
}

void plthook_put(const plthook_t plthook)
{
    printf("dynsym addr: %p\n", plthook.dynsym->st_value);
    printf("dynstr addr: %p\n", plthook.dynstr);
    printf("plt_addr_base: %p\n", plthook.plt_addr_base);
    printf("rela_plt addr: %p\n", plthook.rela_plt);
#ifdef R_GLOBAL_DATA
    printf("rela_dyn addr: %p\n", plthook.rela_dyn);
#endif
}


int
check_elf_ident(FILE *stream)
{
    int ret = 0;
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

    if (e_ident[EI_CLASS] != ELFCLASS64 ||
        e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "%s\n", "We Only Support ELF64 LE!");
        goto restore_file_offset_and_return_error;
    }

    fseek(stream, offset, SEEK_SET);
    return 0;

 restore_file_offset_and_return_error:
    fseek(stream, offset, SEEK_SET);
    return 1;
}


Elf64_Ehdr *
get_elf_header(FILE *stream)
{
    Elf64_Ehdr *header = malloc(sizeof *header);
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


Elf64_Shdr *
get_sec_header_tab(FILE *stream, Elf64_Ehdr *header)
{
    size_t size = header->e_shnum * header->e_shentsize;
    long offset = ftell(stream);

    Elf64_Shdr *sec_header_tab = malloc(size);
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
             Elf64_Shdr *str_tab_header)
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

Elf64_Shdr *
get_section_by_name(const char *name,
                    Elf64_Ehdr *header,
                    Elf64_Shdr *sec_header_tab,
                    char *str_tab)
{
    for (unsigned num = 0; num < header->e_shnum; num += 1) {
        Elf64_Shdr *sec_header = sec_header_tab + num;
        char *sec_name = str_tab + sec_header->sh_name;
        if (strcmp(sec_name, name) == 0) {
            return sec_header;
        }
    }

    return NULL;
}