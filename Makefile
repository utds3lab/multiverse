
all: teeny nolibc

teeny: 
	nasm -f elf teeny.asm
	gcc -o teeny -Wall -m32 -s -nostartfiles teeny.o

nolibc:
	nasm -f elf nolibc.asm
	gcc -o nolibc -Wall -m32 -s -nostdlib nolibc.o

clean:
	rm -f teeny.o teeny nolibc.o nolibc
