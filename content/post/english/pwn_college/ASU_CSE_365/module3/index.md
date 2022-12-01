---
title: "PwnCollege_Note3"
description: the 3rd module of ASU CSE 365, assembly crash course
date: 2022-11-29
image: pwncollege.png
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - Pwn.college
    - ForeignCourse


---

# Assembly Crash Course

-----------**ASU CSE 365**: Introduction to Cybersecurity

## Assembly Crash Course: Computer Architecture

①all roads lead to cpu

- **SourceCode**(python/java/javascript)---->Interpreter or JIT---->CPU

- **SourceCode**(c/c++/rust)---->Compiler---->CPU

②logic gates

![](img/pwn_college/lesson/LogicGate.png)

and gate&	or gate≥1	xor gate=1	not gate1

③

![](img/pwn_college/lesson/ComputerA.png)

CU: control units

## Assembly Crash Course: Assembly

① nouns: Data

- data we directly give it as part of the instruction
- data that is close at hand(register)
- data in storage(memory)

② verbs: operations

**add** :add some data together

**sub** :subtract some data

**mul** :multiply some data

**div** :divide some data

**mov** :move some data into or out of storage

**cmp** :compare two pieces of data with each other

**test** :test some other properties of data

③every architecture has its own variant: **x86(√)、arm、ppc、mips、risc-v、pdp-11**

history: 8085->8086->80186->80286->80386--x86

intel syntax(√) and AT&T syntax

## Assembly Crash Course: Data

decimal(base 10), binary(base 2), a binary digit is called a *bit*



## embryoasm

-----------send/craft/assemble/pipe raw bytes over stdin to program

 **registers**

level1: **mov**---->`* rdi = 0x11`

```assembly
#1.s
.global _start
#global:make a symbol visible to the linker _start:the starting address of function
.intel_syntax noprefix
#use the intel syntax
_start:
	mov rdi,0x11
```

shell: to get the flag

```shell
gcc -nostdlib -static 1.s	#get a.out
#-nostdlib: Do not use the standard system startup files or libraries when linking
#-static: Disable the use of dynamic libraries
objcopy --dump-section .text=a.bin a.out
#Copy the part or all of the content of the target file to another file
#[--dump-section sectionname=filename]
cat a.bin | /challenge/embryoasm #pipe it to program
```

something to mention:

```shell
hacker@embryoasm_level1:~/module3/1$ objdump -M intel -d a.out

a.out:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       48 c7 c7 37 13 00 00    mov    rdi,0x1337
```

level2: **add**--->`* add 0x11 to rdi`

```assembly
.global _start
.intel_syntax noprefix
_start:
	add rdi,0x11
```

level3: **function**--->`rax:f(x) = mx + b
m = rdi, x = rsi, b = rdx`

```assembly
imul rdi,rsi #multiply--->imul
add rdi,rdx
mov rax,rdi
```

