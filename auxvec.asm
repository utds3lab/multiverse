BITS 32
EXTERN _exit
EXTERN printf
GLOBAL _start
SECTION .text
_start:
getsysinfo:
	mov [esp-4],esi		;I think there's no need to save these, but in case somehow 
	mov [esp-8],ecx		;the dynamic linker leaves something of interest for _start, we can save them
	mov esi,[esp]
	mov ecx,esp
	lea ecx,[ecx+esi*4+4]
;	add ecx,4
;	test esi,esi		;Check for zero args
;	jz loopenv
;loopargv:			;Iterate through each arg
;	sub esi,1
;	add ecx,4
;	test esi,esi
;	jnz loopargv
loopenv:			;Iterate through each environment variable
	add ecx,4
	mov esi,[ecx]
	test esi,esi
	jnz loopenv
	add ecx,4		;Hop over 0 byte to first entry
loopaux:			;Iterate through auxiliary vector, looking for AT_SYSINFO (32)
	mov esi,[ecx]
	cmp esi,32
	jz foundsysinfo
	test esi,esi
	jz restore		;Go to _start if we reach the end
	add ecx,8		;Each entry is 8 bytes
	jmp loopaux
foundsysinfo:
	mov esi,[ecx+4]
	mov [sysinfo],esi
restore:
	mov esi,[esp-4]
	mov ecx,[esp-8]
	jmp realstart
realstart:
	mov eax,[sysinfo]
	call putmsg
	jmp finish
putmsg:
	push eax		;Return value from lookup; should be offset
	push msg
	call printf
	add esp,8		;restore stack pointer
	ret
finish:
	push dword 0
	call _exit
SECTION .data
msg db "sysinfo address: 0x%x", 10, 0
sysinfo dd 0
