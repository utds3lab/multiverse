
all: popgm

popgm: 
	gcc -o x86_populate_gm -m32 -Wall -nostdlib -fno-toplevel-reorder -masm=intel -O1 x86_populate_gm.c
	gcc -o x64_populate_gm -m64 -Wall -nostdlib -fno-toplevel-reorder -masm=intel -O1 x64_populate_gm.c
	bash parse_popgm.sh

clean:
	rm -f x86_populate_gm x64_populate_gm x86_popgm x64_popgm
