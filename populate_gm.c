/*
 * gcc -m32 -nostdlib -fno-toplevel-reorder -masm=intel -O1 populate_gm.c
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

//#include <stdio.h>

#ifndef NULL
#define NULL ( (void *) 0)
#endif

unsigned int __attribute__ ((noinline)) my_read(int fd, char *buf, unsigned int count);
int __attribute__ ((noinline)) my_open(const char *path);
void process_maps(char *buf, int *global_mapping);

//int wrapper(int *global_mapping){
int _start(int *global_mapping){

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
	unsigned int bytes_read;


	proc_maps_fd = my_open((char *) &maps_path);
	bytes_read = my_read(proc_maps_fd, buf, buf_size);
	buf[buf_size -1] = '\0'; // must null terminate

	process_maps(buf, global_mapping);

	//printf("READ:\n%s", buf);
	return 0;

}

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
	return line[18] == 'w';
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
	int base = 16;
	int place, digit;
	for (place = 7; place >= 0; place--, a++){
		digit = (int)(*a) - 0x30;
		if (digit > 9)
			digit -= 0x27; // digit was [a-f]
		i += digit << (place << 2);
	}
	return i;
}

void parse_range(char *line, int *start, int *end){
	// e.g., "08048000-08049000 ..."
	*start = my_atoi(line);
	*end   = my_atoi(line+9);
}

void populate_mapping(unsigned int start, unsigned int end, unsigned int lookup_function, unsigned int *global_mapping){
	do{
		global_mapping[(start >> 12) << 2] = lookup_function;
		start += 0x1000;
	} while(start < end);
}

void process_maps(char *buf, int *global_mapping){
	/*
	 * Process buf which contains output of /proc/self/maps
	 * populate global_mapping for each executable set of pages
	 */
	char *line = buf;
	//unsigned int global_start, global_end;
	unsigned int old_text_start, old_text_end;
	unsigned int new_text_start, new_text_end;

	line = next_line(line);
	do{ // process each block of maps
		// process all segments from this object under very specific assumptions
		if (is_exec(line) && is_write(line)){
			// first exec and write segment must be the "global section"
			//parse_range(line, &global_start, &global_end);
			// jump to the old text segment
			do{
				line = next_line(line);
			} while (!is_exec(line));
			parse_range(line, &old_text_start, &old_text_end);

			// jump to the new text segment
			do{
				line = next_line(line);
			} while (!(is_exec(line) && is_write(line)));
			parse_range(line, &new_text_start, &new_text_end);

			populate_mapping(old_text_start, old_text_end, new_text_start, global_mapping);
		}
		line = next_line(line);
	} while(line != NULL);

}

/*
int main(void){
	int *global_mapping = (int *)0x09000000;
	wrapper(global_mapping);
}
*/

