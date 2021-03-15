section .text
        global _start

_start:
        xor rax,rax
        mov rdx,rax             ; No Env
        mov rsi,rax             ; No argv
        lea rdi, [rel msg]

        add al, 0x3b

        syscall
        msg db '/bin/sh',0
