BITS 32
EXTERN _exit
EXTERN printf
GLOBAL _start
SECTION .text
_start:
getsysinfo:
	mov [esp-4],esi		;I think there's no need to save these, but in case somehow the
	mov [esp-8],ecx		;dynamic linker leaves something of interest for _start, we can save them
	mov esi,[esp]		;Retrieve argc
	mov ecx,esp		;Retrieve address of argc
	lea ecx,[ecx+esi*4+4]	;Skip argv
;	add ecx,4
;	test esi,esi		;Check for zero args
;	jz loopenv
;loopargv:			;Iterate through each arg
;	sub esi,1
;	add ecx,4
;	test esi,esi
;	jnz loopargv
loopenv:			;Iterate through each environment variable
	add ecx,4		;The first loop skips over the NULL after argv
	mov esi,[ecx]		;Retrieve environment variable
	test esi,esi		;Check whether it is NULL
	jnz loopenv		;If not, continue through environment vars
	add ecx,4		;Hop over 0 byte to first entry
loopaux:			;Iterate through auxiliary vector, looking for AT_SYSINFO (32)
	mov esi,[ecx]		;Retrieve the type field of this entry
	cmp esi,32		;Compare to 32, the entry we want
	jz foundsysinfo		;Found it
	test esi,esi		;Check whether we found the entry signifying the end of auxv
	jz restore		;Go to _start if we reach the end
	add ecx,8		;Each entry is 8 bytes; go to next
	jmp loopaux
foundsysinfo:
	mov esi,[ecx+4]		;Retrieve sysinfo address
	mov [sysinfo],esi	;Save address
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
