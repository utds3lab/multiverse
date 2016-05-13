/*
 * debug: gcc -m32 -Wall -DDEBUG -fno-toplevel-reorder -masm=intel -O1 populate_gm.c
 * build: gcc -m32 -Wall -nostdlib -fno-toplevel-reorder -masm=intel -O1 populate_gm.c
 * dd if=a.out of=popgm skip=text_offset bs=1 count=text_size
 *
 * Read and parse /proc/self/maps filling in the global mapping
 *
 * This file uses no external libraries and no global variables
 * The .text section of the compiled binary can be cut out and reused without modification
 *
 *
 * TODO: [?] implement blacklist of mapped file names
 * 			  e.g., [vdso], ld-X.XX.so, etc
 * 		 [?] read /proc in buf_size chunks
 * 		 [!] handle reading less bytes than requested (when there are more to read)
 * 		 		- can happen in rare(?) cases... the file is not a "normal file"
 *
 */
#ifdef DEBUG
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#else
#define NULL ( (void *) 0)
#endif

unsigned int __attribute__ ((noinline)) my_read(int, char *, unsigned int);
int __attribute__ ((noinline)) my_open(const char *);
void populate_mapping(unsigned int, unsigned int, unsigned int, unsigned int *);
void process_maps(char *, unsigned int *);
unsigned int lookup(unsigned int, unsigned int *);

#ifdef DEBUG
int wrapper(unsigned int *global_mapping){
#else
int _start(void *global_mapping){
#endif
	// force string to be stored on the stack even with optimizations
	//char maps_path[] = "/proc/self/maps\0";
	volatile int maps_path[] = {
			0x6f72702f,
			0x65732f63,
			0x6d2f666c,
			0x00737061,
	};

	unsigned int buf_size = 0x1000;
	char buf[buf_size];
	int proc_maps_fd;


	proc_maps_fd = my_open((char *) &maps_path);
	my_read(proc_maps_fd, buf, buf_size);
	buf[buf_size -1] = '\0'; // must null terminate

#ifdef DEBUG
	printf("READ:\n%s\n", buf);
	// simulation for testing - dont call process maps
	populate_mapping(0x08800000, 0x08880000, 0x07000000, global_mapping);
	/*
	int i;
	for (i = 0x08800000; i < 0x08880000; i++){
		if (lookup(i, global_mapping) != 0x07000000){
			printf("Failed lookup of 0x%08x\n", i);
		}
	}
	*/
	//chedck edge cases

	lookup(0x08800000-1, global_mapping);
	lookup(0x08800000, global_mapping);
	lookup(0x08880000+1, global_mapping);
	//printf("0x08812345 => 0x%08x\n", lookup(0x08812345, global_mapping));
#else
	process_maps(buf, global_mapping);
#endif
	return 0;
}

#ifdef DEBUG
unsigned int lookup(unsigned int addr, unsigned int *global_mapping){
	unsigned int index = addr >> 12;
	//if (global_mapping[index] == 0xffffffff){
		printf("0x%08x :: mapping[%d] :: &0x%p :: 0x%08x\n", addr, index, &(global_mapping[index]), global_mapping[index]);
	//}
	return global_mapping[index];
}
#endif

unsigned int __attribute__ ((noinline)) my_read(int fd, char *buf, unsigned int count){
	unsigned int bytes_read;
	asm volatile(
		".intel_syntax noprefix\n"
		"mov eax, 3\n"
		"mov ebx, %1\n"
		"mov ecx, %2\n"
		"mov edx, %3\n"
		"int 0x80\n"
		"mov %0, eax\n"
		: "=g" (bytes_read)
		: "g" (fd), "g" (buf), "g" (count)
		: "ebx", "esi", "edi"
	);
	return bytes_read;
}

int __attribute__ ((noinline)) my_open(const char *path){
	int fp;
	asm volatile(
		".intel_syntax noprefix\n"
		"mov eax, 5\n"
		"mov ebx, %1\n"
		"mov ecx, 0\n"
		"mov edx, 0\n"
		"int 0x80\n"
		"mov %0, eax\n"
		: "=r" (fp)
		: "g" (path)
		: "ebx", "esi", "edi"
	);
	return fp;
}

int is_exec(char *line){
	// e.g., "08048000-08049000 r-xp ..."
	return line[20] == 'x';
}

int is_write(char *line){
	// e.g., "08048000-08049000 rw-p ..."
	return line[19] == 'w';
}

char *next_line(char *line){
	/*
	 * finds the next line to process
	 */
	for (; line[0] != '\0'; line++){
		if (line[0] == '\n'){
			if (line[1] == '\0')
				return NULL;
			return line+1;
		}
	}
	return NULL;
}

unsigned int my_atoi(char *a){
	/*
	 * convert 8 byte hex string into its integer representation
	 * assumes input is from /proc/./maps
	 * i.e., 'a' is a left-padded 8 byte lowercase hex string
	 * e.g., "0804a000"
	 */
	unsigned int i = 0;
	int place, digit;
	for (place = 7; place >= 0; place--, a++){
		digit = (int)(*a) - 0x30;
		if (digit > 9)
			digit -= 0x27; // digit was [a-f]
		i += digit << (place << 2);
	}
	return i;
}

void parse_range(char *line, unsigned int *start, unsigned int *end){
	// e.g., "08048000-08049000 ..."
	*start = my_atoi(line);
	*end   = my_atoi(line+9);
}

void populate_mapping(unsigned int start, unsigned int end, unsigned int lookup_function, unsigned int *global_mapping){
	unsigned int index = start >> 12;
	int i;
	for(i = 0; i < (end - start) / 0x1000; i++){
		global_mapping[index + i] = lookup_function;
	}
#ifdef DEBUG
	printf("Wrote %d entries\n", i);
#endif
}

void process_maps(char *buf, unsigned int *global_mapping){
	/*
	 * Process buf which contains output of /proc/self/maps
	 * populate global_mapping for each executable set of pages
	 */
	char *line = buf;
	//unsigned int global_start, global_end;
	unsigned int old_text_start, old_text_end;
	unsigned int new_text_start, new_text_end;

	//Assume global mapping is first entry at 0x7000000 and that there is nothing before
	//Skip global mapping
	line = next_line(line);
	do{ // process each block of maps
		// process all segments from this object under very specific assumptions
		if ( is_exec(line) ){
			if( !is_write(line) ){
				parse_range(line, &old_text_start, &old_text_end);
			}else{
				parse_range(line, &new_text_start, &new_text_end);
				populate_mapping(old_text_start, old_text_end, new_text_start, global_mapping);
			}
		}
		line = next_line(line);
	} while(line != NULL);
	// assume the very last executable and non-writable segment is that of the dynamic linker (ld-X.X.so)
	// populate those ranges with the value 0x00000000 which will be compared against in the global lookup function
	populate_mapping(old_text_start, old_text_end, 0x00000000, global_mapping);
}

#ifdef DEBUG
int main(void){
	void *mapping_base = (void *)0x09000000;
	int fd = open("./map_shell", O_RDWR);
	void *global_mapping = mmap(mapping_base, 0x400000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (global_mapping != mapping_base){
		printf("failed to get requested base addr\n");
		exit(1);
	}
	wrapper(global_mapping);

	return 0;
}
#endif

