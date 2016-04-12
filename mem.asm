BITS 32
EXTERN _exit
GLOBAL _start
SECTION .text
_start:
	mov eax, [hopd]
        jmp eax
	db 'garbage bytes'
hop1:
	mov eax, [fin]
        mov ebx, 1
	jmp [eax + (ebx*1) + 0x4]
finish:
	db 0xF4,0xF4,0xF4,0xF4
	push dword 42
	call _exit
SECTION .data
hopd dd hop1
fin dd finish
