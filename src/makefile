
vpath %.c srcfile

vpath %.h include


obj = main.o ulog.o decode.o 


behavor_manage_log: $(obj)
	$(CC) -o behavor_manage_log $(obj)

clean:
	-rm behavor_manage_log $(obj)
