# Restores register values and resumes execution at the captured RIP via RET.
#
# extern "C" fn restore_registers(registers: &Registers) -> !;
.align 16
.global restore_registers
restore_registers:
    push    r11
    mov     r10, rcx                # r10 = &Registers (kept until all fields are read)

    # Stash values that cannot be restored directly yet (order: rsp, rip, rax, r11).
    push    qword ptr [r10 + registers_rsp]
    push    qword ptr [r10 + registers_rip]
    push    qword ptr [r10 + registers_rax]
    push    qword ptr [r10 + registers_r11]

    movaps  xmm0, xmmword ptr [r10 + registers_xmm0]
    movaps  xmm1, xmmword ptr [r10 + registers_xmm1]
    movaps  xmm2, xmmword ptr [r10 + registers_xmm2]
    movaps  xmm3, xmmword ptr [r10 + registers_xmm3]
    movaps  xmm4, xmmword ptr [r10 + registers_xmm4]
    movaps  xmm5, xmmword ptr [r10 + registers_xmm5]
    ldmxcsr dword ptr [r10 + registers_mxcsr]

    mov     r15, [r10 + registers_r15]
    mov     r14, [r10 + registers_r14]
    mov     r13, [r10 + registers_r13]
    mov     r12, [r10 + registers_r12]
    mov     rdi, [r10 + registers_rdi]
    mov     rsi, [r10 + registers_rsi]
    mov     rbp, [r10 + registers_rbp]
    mov     rbx, [r10 + registers_rbx]

    mov     rax, [r10 + registers_rflags]
    push    rax
    popfq

    # Pop in reverse order: r11, rax, rip, rsp.
    pop     r11
    pop     rax
    pop     r8                      # guest rip (temporary)
    pop     r9                      # guest rsp (temporary)

    mov     rcx, [r10 + registers_rcx]
    mov     rdx, [r10 + registers_rdx]

    # Push the return address onto the guest stack and resume with RET so that
    # RSP ends up at the captured value after the implicit pop.
    lea     rsp, [r9 - 8]
    mov     [rsp], r8

    mov     r8, [r10 + registers_r8]
    mov     r9, [r10 + registers_r9]
    mov     r10, [r10 + registers_r10]
    ret
