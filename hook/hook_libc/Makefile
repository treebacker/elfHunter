obj = hook_libc.o dynsym.o

hook_libc:hook_libc.o dynsym.o
	gcc dynsym.o  hook_libc.o -o hook_libc -g -ldl

dynsym.o:
	cc -c dynsym/dynsym.c
clean:
	rm *.o hook_libc