BITS 32
EXTERN _exit
GLOBAL _start
SECTION .text
_start:
	mov eax, [hopa]
        jmp eax
	;db 'garbage bytes'
	db 0xF4,0xF4,0xF4,0xF4
hop1:
	mov eax, hopa	;We will then jump over hopa's bytes to hopb
        mov ebx, 1
	jmp [eax + (ebx*4)]
	db 0xF4,0xF4,0xF4,0xF4
hop2:
	jmp [fin]
	db 0xF4,0xF4,0xF4,0xF4
finish:
	push dword 42
	call _exit
SECTION .data
hopa dd hop1
hopb dd hop2
fin dd finish
