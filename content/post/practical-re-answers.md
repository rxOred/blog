---
title: "Practical Reverse Engineering Answers"
date: 2021-09-29T09:46:25Z
draft: false
---

# Introduction

Hello, rxOred here, with another badly written write-up.

A years ago, i started reading practical reverse engineering book. Eventhough I was familiar with most of those concepts,
that book's exercises were pretty challenging.
Aand guess what, there were no solutions to those Exercises in the book. Authors have encouraged RE community to share 
solutions with others using their blogs, r/reverse-egnineering etc.

At that time, i never really wanted to create a blog. however while doing those challenges, i have wrote 
some, not-very-detailed explainations. So, i will be sharing those stuff with yall.
This 2 part series post will provide some solutions for Exercises in chapter 1, which is about x86.

# Chapter 1, page 11

1) 4 bytes (32 bits). makes sense right? if you have read the whole snippet, line 5 is a,
	repne scasb
   intel indentifies these instructions as string operation instructions. which is perfectly fine.About scasb,
   scasb/scasw/scasd instructions compare al/ax/eax with value at memory address specified in edi. rep is a prefix. 
   it is used for repeating same thing. So the what the whole instruction does is, it compares al (because scas'b') 
   with whatever value at memory address specified in edi while increasing edi by 1 until the byte is found in the 
   buffer or ecx == 0. so as for our answer, it is 4 bytes because since edi is an memory address, memory addresses in
   x86 takes upto 4bytes :)

2) 1 byte
	rep stosb
   this instruction is used to initialize a buffer with some value (like memset). edi should contain the address of 
   buffer, and since its a stos'b', which is the indication of byte, al contain the value that the buffer should be
   assigned with. So from that, it is clear that ebp+c, second argument to the function is sizeof byte:)

3) What the snippet does is pretty simple, in line 1, edi is assigned with ebp+8 (first arg), which we concluded as a
   memory address. next line, we can see that its saving that address in edx followed by a xor eax, eax, which clears 
   out eax register. In line 4, ecx is ored(did i spell that correct?) with 0xffffffff. result of this operation is, 
   well, 0xffffffff because anything | 1 results in a 1.

   then we have what we discussed in 1), repe scasb. I won't explain it again ew.

   So next we have some add ecx, 2, which, as anyone can guess, adds 2 to ecx. Followed by a negation. then we have a
   mov  al, ebp+c, which moves our byte into al register. then edi is assigned with edx, where we saved our edi before.
   Then we have what we discussed in 2). 

   So what this basically does is, it compares 0 with whatever at memory address edi until 0 is found in the 
   buffer while decrementing ecx. then we set ecx + 2, then we negate it to get the string len, then we write [ebp-c] 
   to [edi] byte by byte :3


# Chapter 1, page 17

1) So, in this exercise we want to write a program that reads instruction pointer :3. here we go
   ```asm
      ; here we are reading address of the instruction after the call instruction.
      readeip: call     lbl         ; call lbl, this pushes address of next instruction to the stack
               mov      ebx, 0
               mov      eax, 0
               int      0x80        ; exit

      lbl:     mov      eax, [esp]  ; we read value at esp to eax. which is the return address.
               ret
   ```

2) Next we have to set eip to 0xAABBCCDD
   ```asm
      ; 1. here we when we call, return address is pushed to stack
      writeeip:   call  write
                  mov   ebx,  0
                  mov   eax,  0
                  int   0x80

      ; 2. we then modify the value at stack to 0xAABBCCDD
      write:      mov   [esp], 0xAABBCCDD
                  ret   ; cause a segfault
   ```

   ```asm
      writeeip:   call  write

      ; remember, ret just pops whatever at esp to eip
      write:      push  0xAABBCCDD
                  ret
   ```

   ```asm
      writeeip: jmp  0xAABBCCDD
      ;yeaup simple as that
   ```

   ```asm
      writeeip: mov     eax, 0xAABBCCDD
                call    eax
      ; this is bit important. lot of malware authors use this method to access win32 APIs
   ```

3) same thing that happened to many of above snippets. it will crash with a seg fault. The reason is that, we are returning to 
   a totally unknown address.

4) edx:eax will be used.


#THE-END

In the next article, we will go through the last exercise :) Until then!
