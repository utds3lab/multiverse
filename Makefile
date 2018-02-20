
all: popgm simplest

popgm: 
	gcc -o x86_populate_gm -m32 -Wall -nostdlib -fno-toplevel-reorder -masm=intel -O1 x86_populate_gm.c
	gcc -o x64_populate_gm -m64 -Wall -nostdlib -fno-toplevel-reorder -masm=intel -O1 x64_populate_gm.c
	bash parse_popgm.sh

simplest:
	gcc -o simplest64 -m64 -O1 simplest.c
	gcc -o simplest32 -m32 simplest.c 

clean:
	rm -f x86_populate_gm x64_populate_gm x86_popgm x64_popgm simplest64 simplest32 simplest64-r simplest32-r
