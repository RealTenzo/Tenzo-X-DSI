EXTERN wNtAllocateVirtualMemory:DWORD
EXTERN wNtWriteVirtualMemory:DWORD
EXTERN wNtReadVirtualMemory:DWORD
EXTERN wNtProtectVirtualMemory:DWORD
EXTERN wNtFreeVirtualMemory:DWORD
EXTERN wNtQueryVirtualMemory:DWORD
EXTERN wNtCreateThreadEx:DWORD
EXTERN wNtWaitForSingleObject:DWORD
EXTERN wNtOpenProcess:DWORD
EXTERN wNtClose:DWORD

.code

PUBLIC NtAllocateVirtualMemory
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtAllocateVirtualMemory
    syscall
    ret
NtAllocateVirtualMemory ENDP

PUBLIC NtWriteVirtualMemory
NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtWriteVirtualMemory
    syscall
    ret
NtWriteVirtualMemory ENDP

PUBLIC NtReadVirtualMemory
NtReadVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtReadVirtualMemory
    syscall
    ret
NtReadVirtualMemory ENDP

PUBLIC NtProtectVirtualMemory
NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtProtectVirtualMemory
    syscall
    ret
NtProtectVirtualMemory ENDP

PUBLIC NtFreeVirtualMemory
NtFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtFreeVirtualMemory
    syscall
    ret
NtFreeVirtualMemory ENDP

PUBLIC NtQueryVirtualMemory
NtQueryVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtQueryVirtualMemory
    syscall
    ret
NtQueryVirtualMemory ENDP

PUBLIC NtCreateThreadEx
NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, wNtCreateThreadEx
    syscall
    ret
NtCreateThreadEx ENDP

PUBLIC NtWaitForSingleObject
NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, wNtWaitForSingleObject
    syscall
    ret
NtWaitForSingleObject ENDP

PUBLIC NtOpenProcess
NtOpenProcess PROC
    mov r10, rcx
    mov eax, wNtOpenProcess
    syscall
    ret
NtOpenProcess ENDP

PUBLIC NtClose
NtClose PROC
    mov r10, rcx
    mov eax, wNtClose
    syscall
    ret
NtClose ENDP

END
