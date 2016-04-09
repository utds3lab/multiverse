BITS 32
GLOBAL _start
SECTION .text
_start:
	xor eax,eax
        jz finish
	db 'garbage bytes'
finish:
	mov eax, 1
	mov ebx, 42
	int 0x80
