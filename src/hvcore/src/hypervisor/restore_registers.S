# Restores register values and resumes execution at the captured RIP.
#
# extern "C" fn restore_registers(registers: &Registers) -> !;
.align 16
.global restore_registers
restore_registers:
    mov     r11, rcx

    movaps  xmm0, xmmword ptr [r11 + registers_xmm0]
    movaps  xmm1, xmmword ptr [r11 + registers_xmm1]
    movaps  xmm2, xmmword ptr [r11 + registers_xmm2]
    movaps  xmm3, xmmword ptr [r11 + registers_xmm3]
    movaps  xmm4, xmmword ptr [r11 + registers_xmm4]
    movaps  xmm5, xmmword ptr [r11 + registers_xmm5]

    mov     r15, [r11 + registers_r15]
    mov     r14, [r11 + registers_r14]
    mov     r13, [r11 + registers_r13]
    mov     r12, [r11 + registers_r12]
    mov     r10, [r11 + registers_r10]
    mov      r9, [r11 + registers_r9]
    mov      r8, [r11 + registers_r8]
    mov     rdi, [r11 + registers_rdi]
    mov     rsi, [r11 + registers_rsi]
    mov     rbp, [r11 + registers_rbp]
    mov     rbx, [r11 + registers_rbx]
    mov     rdx, [r11 + registers_rdx]
    mov     rcx, [r11 + registers_rcx]

    mov     rax, [r11 + registers_rflags]
    push    rax
    popfq

    mov     rsp, [r11 + registers_rsp]
    mov     rax, [r11 + registers_rax]
    jmp     qword ptr [r11 + registers_rip]
