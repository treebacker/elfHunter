# include <stdlib.h>
// fopen, fprintf, printf.
# include <stdio.h>
// perror.
# include <string.h>
// Get PRIx64, PRIu64.
# include <inttypes.h>

# include <elf.h>
# include "dynsym.h"

int
main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "%s\n", "Invalid Arguments!");
        return EXIT_FAILURE;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    if (check_elf_ident(fp) != 0) {
        return EXIT_FAILURE;
    }

    Elf64_Ehdr *header = get_elf_header(fp);
    if (header == NULL) {
        return EXIT_FAILURE;
    }

    Elf64_Shdr *sec_header_tab = get_sec_header_tab(fp, header);
    if (sec_header_tab == NULL) {
        return EXIT_FAILURE;
    }

    Elf64_Shdr *str_tab_header = sec_header_tab + header->e_shstrndx;
    char *shstrtab = get_shstrtab(fp,
                                  str_tab_header);
    if (shstrtab == NULL) {
        return EXIT_FAILURE;
    }

    Elf64_Shdr *gotab = get_section_by_name(".got",
                                            header,
                                            sec_header_tab,
                                            shstrtab);
    Elf64_Shdr *dynsym = get_section_by_name(".dynsym",
                                            header,
                                            sec_header_tab,
                                            shstrtab);    
    Elf64_Shdr *rela_dyn = get_section_by_name(".rela.dyn",
                                            header,
                                            sec_header_tab,
                                            shstrtab);
    Elf64_Shdr *rela_plt = get_section_by_name(".rela.plt",
                                            header,
                                            sec_header_tab,
                                            shstrtab);

    if (dynsym == NULL || rela_dyn == NULL || rela_plt == NULL || gotab == NULL) {
        return EXIT_FAILURE;
    }

    printf("Got: %p", gotab->sh_addr);
    printf("dynsym: %p", dynsym->sh_addr);
    printf("rela_dyn: %p", rela_dyn->sh_addr);
    printf("rela_plt: %p", rela_plt->sh_addr);

}