BITS 32
EXTERN _exit
GLOBAL _start
SECTION .text
_start:
	xor eax,eax
        jz finish
	db 'garbage bytes'
finish:
	push dword 42
	call _exit
	
