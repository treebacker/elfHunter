# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <elf.h>
# ifndef _GU_ZHENGXIONG_UELF_H
# define _GU_ZHENGXIONG_UELF_H


int
check_elf_ident(FILE *stream);
Elf64_Ehdr *
get_elf_header(FILE *stream);
Elf64_Shdr *
get_sec_header_tab(FILE *stream, Elf64_Ehdr *header);
char *
get_shstrtab(FILE *stream,
             Elf64_Shdr *str_tab_header);
Elf64_Shdr *
get_section_by_name(const char *name,
                    Elf64_Ehdr *header,
                    Elf64_Shdr *sec_header_tab,
                    char *str_tab);

# endif