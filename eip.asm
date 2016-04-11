BITS 32
EXTERN _exit
EXTERN printf
GLOBAL _start
SECTION .text
_start:
	xor eax,eax
        jz finish
	;db 'garbage bytes'
finish:
	call get_eip
get_eip:
	pop eax
	push eax	;return value for application, but only returns last byte of eip
	push eax
	push msg
	call printf
	add esp,8	;restore stack pointer
	call _exit
	
section .data

msg db 'eip: 0x%x', 10, 0
