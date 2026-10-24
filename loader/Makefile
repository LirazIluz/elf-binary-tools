all: my_loader

start.o: start.s
	nasm -f elf32 start.s -o start.o

my_loader.o: my_loader.c
	gcc -m32 -g -Wall -fno-stack-protector -c my_loader.c -o my_loader.o

my_loader: my_loader.o start.o startup.o
	ld -m elf_i386 -T linking_script -dynamic-linker /lib32/ld-linux.so.2 -o my_loader my_loader.o start.o startup.o -lc -L/usr/lib32

clean:
	rm -f my_loader my_loader.o start.o