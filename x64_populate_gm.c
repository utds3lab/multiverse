/*
 * debug: gcc -o x64_populate_gm -Wall -DDEBUG -fno-toplevel-reorder -masm=intel -O1 x64_populate_gm.c
 * build: gcc -o x64_populate_gm -Wall -nostdlib -fno-toplevel-reorder -masm=intel -O1 x64_populate_gm.c
 * dd if=x64_populate_gm of=x64_popgm skip=text_offset bs=1 count=text_size
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

struct gm_entry {
	unsigned long lookup_function;
	unsigned long start;
	unsigned long length;
};

unsigned int __attribute__ ((noinline)) my_read(int, char *, unsigned int);
int __attribute__ ((noinline)) my_open(const char *);
void populate_mapping(unsigned int, unsigned long, unsigned long, unsigned long, struct gm_entry *);
void process_maps(char *, struct gm_entry *);
struct gm_entry lookup(unsigned long, struct gm_entry *);

#ifdef DEBUG
int wrapper(struct gm_entry *global_mapping){
#else
int _start(struct gm_entry *global_mapping){
#endif
	// force string to be stored on the stack even with optimizations
	//char maps_path[] = "/proc/self/maps\0";
	volatile int maps_path[] = {
			0x6f72702f,
			0x65732f63,
			0x6d2f666c,
			0x00737061,
	};

	unsigned int buf_size = 0x10000;
	char buf[buf_size];
	int proc_maps_fd;
	int cnt, offset = 0;


	proc_maps_fd = my_open((char *) &maps_path);
	cnt = my_read(proc_maps_fd, buf, buf_size);
        while( cnt != 0 && offset < buf_size ){
                offset += cnt;
        	cnt = my_read(proc_maps_fd, buf+offset, buf_size-offset);
	}
	buf[offset] = '\0';// must null terminate

#ifdef DEBUG
	printf("READ:\n%s\n", buf);
	process_maps(buf,global_mapping);
	int items = global_mapping[0].lookup_function;
	// simulation for testing
	populate_mapping(items + 0, 0x08800000, 0x08880000, 0x07000000, global_mapping);
	populate_mapping(items + 1, 0x09900000, 0x09990000, 0x07800000, global_mapping);
	global_mapping[0].lookup_function += 2;//Show that we have added these
	/*
	int i;
	for (i = 0x08800000; i < 0x08880000; i++){
		if (lookup(i, global_mapping) != 0x07000000){
			printf("Failed lookup of 0x%08x\n", i);
		}
	}
	*/
	//check edge cases

	printf("Testing %x (out of range)\n",0x08800000-1);
	lookup(0x08800000-1, global_mapping);
	printf("Testing %x (in range)\n",0x08800000);
	lookup(0x08800000, global_mapping);
	printf("Testing %x (in range)\n",0x08800001);
	lookup(0x08800001, global_mapping);
	printf("Testing %x (in range)\n",0x08880000);
	lookup(0x08880000, global_mapping);
	printf("Testing %x (out of range)\n",0x08880000+1);
	lookup(0x08880000+1, global_mapping);
	//printf("0x08812345 => 0x%08x\n", lookup(0x08812345, global_mapping));
#else
	process_maps(buf, global_mapping);
#endif
	return 0;
}

#ifdef DEBUG
struct gm_entry lookup(unsigned long addr, struct gm_entry *global_mapping){
	unsigned int index;
	unsigned long gm_size = global_mapping[0].lookup_function;//Size is stored in first entry
	global_mapping++;//Now we point at the true first entry
	//Use binary search on the already-sorted entries
	//Here is a linear search for simple testing purposes.
	//For small arrays, binary search may not be as useful, so I may for now just use linear search.
	//I can try using binary search later and doing a performance comparison.
	//However, if I want to do binary search, I should do a conditional mov to reduce the number of branches
	for(index = 0; index < gm_size; index++){
		//printf("SEARCHING 0x%lx :: mapping[%d] :: 0x%lx :: 0x%lx :: 0x%lx\n", addr, index, global_mapping[index].lookup_function, global_mapping[index].start, global_mapping[index].length);
		if( addr - global_mapping[index].start <= global_mapping[index].length){
			printf("0x%lx :: mapping[%d] :: 0x%lx :: 0x%lx :: 0x%lx\n", addr, index, global_mapping[index].lookup_function, global_mapping[index].start, global_mapping[index].length);
		}
	}
	
	return global_mapping[index];
}
#endif

unsigned int __attribute__ ((noinline)) my_read(int fd, char *buf, unsigned int count){
	unsigned long bytes_read;
	asm volatile(
		".intel_syntax noprefix\n"
		"mov rax, 0\n"
		"mov rdi, %1\n"
		"mov rsi, %2\n"
		"mov rdx, %3\n"
		"syscall\n"
		"mov %0, rax\n"
		: "=g" (bytes_read)
		: "g" ((long)fd), "g" (buf), "g" ((long)count)
		: "rax", "rdi", "rsi", "rdx", "rcx", "r11"
	);
	return (unsigned int) bytes_read;
}

int __attribute__ ((noinline)) my_open(const char *path){
	unsigned long fp;
	asm volatile(
		".intel_syntax noprefix\n"
		"mov rax, 2\n"
		"mov rdi, %1\n"
		"mov rsi, 0\n"
		"mov rdx, 0\n"
		"syscall\n"
		"mov %0, rax\n"
		: "=r" (fp)
		: "g" (path)
		: "rcx", "r11"
	);
	return (int) fp;
}

#define PERM_WRITE 1
#define PERM_EXEC 2
unsigned char get_permissions(char *line){
	// e.g., "08048000-08049000 r-xp ..." or "08048000-08049000 rw-p ..."
	unsigned char permissions = 0;
	while( *line != ' ' ) line++;
	line+=2; //Skip space and 'r' entry, go to 'w'
	if( *line == 'w' ) permissions |= PERM_WRITE;
	line++; //Go to 'x'
	if( *line == 'x' ) permissions |= PERM_EXEC;
	return permissions;
}

#define is_write(p) (p & PERM_WRITE)
#define is_exec(p) (p & PERM_EXEC)

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

unsigned long my_atol(char *a){
	/*
	 * convert unknown length (max 16) hex string into its integer representation
	 * assumes input is from /proc/./maps
	 * i.e., 'a' is a left-padded 16 byte lowercase hex string
	 * e.g., "000000000804a000"
	 */
#ifdef DEBUG
	//printf("Converting string to long: \"%s\"\n", a);
#endif
	unsigned long l = 0;
	unsigned char digit = *a;
	while( (digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f') ){
		digit -= '0';
		if( digit > 9 ) digit -= 0x27; // digit was hex character
		l <<= 4; // Shift by half a byte
		l += digit;
		digit = *(++a);
	}
#ifdef DEBUG
	//printf("Resulting value: %lx\n", l);
#endif
	return l;
}

void parse_range(char *line, unsigned long *start, unsigned long *end){
	/* 
	 * e.g., "08048000-08049000 ..."
	 * Unfortunately, for 64-bit applications, the address ranges do not have a
	 * consistent length!  We must determine how many digits are in each number.
	 */
	char *line_start = line;
	while( *line != '-' ) line++;
	*start = my_atol(line_start);
	*end   = my_atol(line+1);
}

void populate_mapping(unsigned int gm_index, unsigned long start, unsigned long end, unsigned long lookup_function, struct gm_entry *global_mapping){
	global_mapping[gm_index].lookup_function = lookup_function;
	global_mapping[gm_index].start = start;
	global_mapping[gm_index].length = end - start;
#ifdef DEBUG
	printf("Added gm entry @ %d: (0x%lx, 0x%lx, 0x%lx)\n", gm_index, global_mapping[gm_index].lookup_function, global_mapping[gm_index].start, global_mapping[gm_index].length);
#endif
}

void process_maps(char *buf, struct gm_entry *global_mapping){
	/*
	 * Process buf which contains output of /proc/self/maps
	 * populate global_mapping for each executable set of pages
	 */
	char *line = buf;
	unsigned int gm_index = 1;//Reserve first entry for metadata
	unsigned char permissions = 0;
	//unsigned int global_start, global_end;
	unsigned long old_text_start, old_text_end;
	unsigned long new_text_start, new_text_end;

	//Assume global mapping is first entry at 0x200000 and that there is nothing before
	//Skip global mapping (put at 0x200000 in 64-bit binaries, as opposed to 0x7000000 for x86)
	line = next_line(line);
	do{ // process each block of maps
		permissions = get_permissions(line);
		// process all segments from this object under very specific assumptions
		if ( is_exec(permissions) ){
			if( !is_write(permissions) ){
				parse_range(line, &old_text_start, &old_text_end);
#ifdef DEBUG
				printf("Parsed range for r-xp: %lx-%lx\n", old_text_start, old_text_end);
#endif
			}else{
				parse_range(line, &new_text_start, &new_text_end);
#ifdef DEBUG
				printf("Parsed range for rwxp: %lx-%lx\n", new_text_start, new_text_end);
#endif
				populate_mapping(gm_index, old_text_start, old_text_end, new_text_start, global_mapping);
				gm_index++;
			}
		}
		line = next_line(line);
	} while(line != NULL);
	// assume the very last executable and non-writable segment is that of the dynamic linker (ld-X.X.so)
	// populate those ranges with the value 0x00000000 which will be compared against in the global lookup function
	//TODO: this will NOT be the dynamic linker!  It will be [vsyscall], so we must try something else!
	populate_mapping(gm_index, old_text_start, old_text_end, 0x00000000, global_mapping);
	gm_index++;
	global_mapping[0].lookup_function = gm_index;// Use first entry for storing how many entries there are
}

#ifdef DEBUG
int main(void){
	void *mapping_base = (void *)0x200000;
	void *new_section = (void *)0x8000000;
	int fd = open("/dev/zero", O_RDWR);
	void *global_mapping = mmap(mapping_base, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	mmap(new_section, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0); //Create a mock new "text" section that would be added by process_maps
	if (global_mapping != mapping_base){
		printf("failed to get requested base addr\n");
		exit(1);
	}
	wrapper(global_mapping);

	return 0;
}
#endif

