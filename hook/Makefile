hook_api:hook_api.o hook.o
	gcc hook_api.o hook.o -o hook_api

hook_api.o:
		gcc -c hook_api.c -o hook_api.o -g

hook.o:
	gcc -c hook.c -o hook.o -g

clean:
	rm hook_api.o hook_api hook.o hook