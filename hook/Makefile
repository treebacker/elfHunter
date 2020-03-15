obj = hook_libc.o hook_sys.o hunter_hook.o break.o

hunter_hook:$(obj)
	gcc $(obj) -o hunter_hook

hook_libc.o:break.o
clean:
	rm *.o hunter_hook