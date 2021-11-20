.code

__peb_ldte proc
	mov rax, qword ptr gs:[60h]
	mov rax, [rax + 18h]
	mov rax, [rax + 10h]
	;mov rax, [rax]
	ret
__peb_ldte endp

end