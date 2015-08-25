CC=gcc
NAME=pdscli
OBJFILES=types.o scanner.yy.o parser.tab.o pdscli.o
obj-m += pdsfw.o

all: $(OBJFILES)
	$(CC) -o $(NAME) $(OBJFILES)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f *.o $(NAME)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
