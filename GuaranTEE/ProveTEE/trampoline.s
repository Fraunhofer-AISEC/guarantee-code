/*
 *  Copyright (C) 2021 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  trampoline.s
 *
 *  Implements the trampoline functions called from the instrumentation.
 *
 *  All Rights Reserved.
 */

.section .text
.global trampoline_i
.global trampoline_ia

.global trampoline
.type trampoline, @function

.intel_syntax noprefix
# ########################################################################### #
# Trampoline function saving the registers and calling the actual trampoline. #
# This version is used directly before return instructions because it         #
# preserves the registers filled with the return values.                      #
# ########################################################################### #
trampoline_ia:
    push rax                # Safe return value (lower 64bit)
    push rdx                # Safe return value (upper 64bit)
    push rdx                # Align stack to 16 byte before call
    call trampoline         # Call the actual trampoline
    pop rdx                 # Stack alignment
    pop rdx                 # Restore return value (upper 64bit)
    pop rax                 # Restore return value (lower 64bit)
    ret                     # Return


# ########################################################################### #
# Trampoline function saving the registers and calling the actual trampoline. #
# The ID is passed in r11 because it is an caller saved register and can      #
# therefore be clobbered by the instrumentation. This version is used before  #
# indirect calls and jumps because it preserves the already prepared          #
# function parameters in the registers.                                       #
# ########################################################################### #
trampoline_i:
    push rdi                # Safe rdi
    push rsi                # Safe rsi
    push rax                # Safe rax
    push rbx                # Safe rbx
    push rcx                # Safe rcx
    push rdx                # Safe rdx
    push r8                 # Safe r8
    push r9                 # Safe r9
    push r10                # Safe r10
    push r11                # Safe r11
    push r12                # Safe r12
    push r13                # Safe r13
    push r14                # Safe r14
    push r15                # Safe r15
    sub rsp, 0x8            # Stack alignment
    # !!!! All registers except r11 have to be pushed to the stack !!!!

    mov rdi, r11            # Prepare identifier as first parameter for trampoline
    call trampoline         # Call the actual tampoline

    # !!!! All registers except r11 have to be popped from the stack !!!!
    add rsp, 0x8            # Stack alignment
    pop r15                 # Restore r15
    pop r14                 # Restore r14
    pop r13                 # Restore r13
    pop r12                 # Restore r12
    pop r11                 # Restore r11
    pop r10                 # Restore r10
    pop r9                  # Restore r9
    pop r8                  # Restore r8
    pop rdx                 # Restore rdx
    pop rcx                 # Restore rcx
    pop rbx                 # Restore rbx
    pop rax                 # Restore rax
    pop rsi                 # Restore rsi
    pop rdi                 # Restore rdi
    ret                     # Return
