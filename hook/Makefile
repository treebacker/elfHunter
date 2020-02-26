obj = hook_libc.o hook_sys.o hunter_hook.o

hunter_hook:$(obj)
	gcc $(obj) -o hunter_hook

clean:
	rm *.o hunter_hook