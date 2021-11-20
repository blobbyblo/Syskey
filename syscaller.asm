.code

fnNtUserGetAsyncKeyState proc
	mov r10, rcx
    mov rax, rdx
    syscall
    ret
fnNtUserGetAsyncKeyState endp

end