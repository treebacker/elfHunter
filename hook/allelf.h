/*
	兼容ELF 32 64
*/
#include <elf.h>

#if defined __x86_64__ || defined __x86_64
#define Elf_Half Elf64_Half
#define Elf_Xword Elf64_Xword
#define Elf_Sxword Elf64_Sxword
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym  Elf64_Sym
#define Elf_Dyn  Elf64_Dyn
#define Elf_Rel  Elf64_Rel
#define Elf_Rela Elf64_Rela
#define Dynsym_idx	4
#define Check		64

#elif defined __i386__ || defined __i386
#define Elf_Half Elf32_Half
#define Elf_Xword Elf32_Word
#define Elf_Sxword Elf32_Sword
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym  Elf32_Sym
#define Elf_Dyn  Elf32_Dyn
#define Elf_Rel  Elf32_Rel
#define Elf_Rela Elf32_Rela
#define Dynsym_idx	1
#define Check		32
#endif

//each plt unit 0x10 size
#define Plt_Unit  0x10

//get dynsym index from rel.plt's r_info
#define info_to_stname(r_info) ((r_info) >> (Dynsym_idx*8))
//reverse
#define stname_to_info(index) (((index) <<(Dynsym_idx*8)) + 0x7)