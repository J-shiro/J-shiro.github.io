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

level4: **divide**

```assembly
mov rax, reg1; div reg2 #reg1:divided reg2:divisor
#rax = reg1/reg2	;rdx = remainder
mov rax, rdi; div rsi #get the flag
```

level5: **modulo**

```assembly
# rdi % rsi ->remainder to rax
mov rax, rdi; div rsi
mov rax, rdx
```

level6: **lower register**

independent access to lower register bytes

| 64bits | 32bits | 16bits | 8bits |
| ------ | ------ | ------ | ----- |
| rax    | eax    | ax     | ah al |

![](img/pwn_college/level6/rax.png)

only use the 'mov' to compute:

- rax = rdi modulo 256				,256=2^8^---------->8---1,0000,0000
- rbx = rsi modulo 65536            ,65536=2^16^------->16---1,0000,0000,0000,0000

```assembly
mov rcx,rdi #first move to the General-Purpose Registers
mov al,cl	#8bits
mov rdx,rsi
mov bx,dx	#16bits
```

If B is a power of 2, `A % B` can be simplified to `A & (B-1)` . A can be any number, B = 2^0^,2^1^,2^2^,2^N^...(If B is 256, so B-1 is FFFF,FFFF in binary)

level7: **shl,shr**---->it will add 0 in another side

shift: **rax=10001010** ,  after the instruction`shl rax, 1`, **rax=00010100**------>8bits

register has 64bits=8*8bits			

shl reg1, x       <=>     Shift reg1 left by x
shr reg1, x      <=>     Shift reg1 right by x

rdi = | B7 | B6 | B5 | B4 | B3 | B2 | B1| B0 |, and set the rax to the value of B4, (rdi=0x77665544332211)

```assembly
mov rax,rdi
shl rax,24 #3*8=0x18
shr rax,56 #3*8+4*8=0x38 <----It's important to add the front move
```

level8: **and,or,xor,no**---->bitwise logic

![](img/pwn_college/level8/andorxor.png)

rax = rdi AND rsi

```assembly
and rdi, rsi
xor rax, rax #make the rax to 0
or rax, rdi  #use the or 
```

level9: **and,or,xor**

```text
if x is even(2,4,6..) then	y = 1
else	y = 0
where:x = rdi;y = rax 
only use the 'and,or,xor'
```

tips: We judge it by the value on the smallest bit.==>0: even, 1: odd

```assembly
and rdi, 1 #first 0and1=0,1and1=1,so the smalliest bit even turn to 0,odd turn to 1
#other bits and 0 so they're turned to 0
xor rdi, 1 #second 0xor1=1,1xor1=0,so the smalliest bit even to 1, odd to 0
#other bits 0 xor 0 = 0
xor rax, rax #make rax 0
or rax, rdi 
```

level10: **AddressOperation**

mov rax, [some_address]        <=>     Moves the thing at 'some_address' into rax

task: move the [xxx] to rax, and then value in [xxx] should add yyy

```assembly
mov rax, [xxx]
mov rbx, rax
add rbx, yyy
mov [xxx], yyy
```

level11: **byte,word,dword,qword**

memory size:

* Quad Word = 8 Bytes = 64 bits			 rax
* Double Word = 4 bytes = 32 bits          eax
* Word = 2 bytes = 16 bits                        ax
* Byte = 1 byte = 8 bits                              ah, al

perform:

 	1. Set rax to the **byte** at 0x404000
 	2. Set rbx to the **word** at 0x404000
 	3. Set rcx to the **double** word at 0x404000
 	4. Set rdx to the **quad** word at 0x404000

```assembly
mov al, [0x404000]
mov bx, [0x404000]
mov ecx, [0x404000]
mov rdx, [0x404000] #get flag
```

level12:

**Little Endian **:  values are stored *in reverse* order of how we represent them

[0x1330] = 0x00000000deadc0de

[0x1330] = 0xde 0xc0 0xad 0xde 0x00 0x00 0x00 0x00	<--------actually in memory

**Register indirect addressing** : Perform----> set [rdi] = 0xaaa , can't directly use like this

```assembly
mov rax, 0xaaa
mov [rdi], rax #get flag
#show like below:
movabs  rax, 0xaaa
mov     qword ptr [rdi], rax
```

