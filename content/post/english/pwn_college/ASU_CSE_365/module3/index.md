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

hexadecimal(base 16), decimal(base 10),octal(base 8),  binary(base 2), a binary digit is called a *bit*

①Expressing text

ASCII(American Standard Code for Information Exchange): Specified how to encode, in 7 bits, the English alphabet and common symbols.

below: the top is the first hex digit, the left is the second hex digit

![](img/pwn_college/lesson/ascii.png)

Uppercase(Lowercase) letters: 0x40(0x60) + LETTER_INDEX_IN_HEX

Digit representations: 0x30 + DIGIT

lower than 0x20(SPACE) are "control characters": 0x09(tab), 0x0a(newline), 0x07(bell)

**ASCII has evolved into UTF-8, used on 98% of the web. Extend more than 8 bits**

②  Grouping bits into bytes

IBM invented 8-bits EBCDIC in 1963 for use on their terminals. ASCII(1963) replaced it but the 8-bit byte stuck.

③ Grouping bytes into words

most modern architectures are 64-bit

**Nibble: 4bits**

**Byte: 8 bits**

**word: 2 bytes, 16bits**

**Double word(dword): 4 bytes, 32 bits**

**Quad word(qword): 8 bytes, 64 bits**

`thinking: what happens if add 1 to 0xffffffffffffffff`

integer overflow: 1 + 0x<ins>ffffffffffffffff</ins> = 0x1<ins>0000000000000000</ins>

the extra bit gets put in common carry bit storage by the CPU and the result becomes 0

④Expressing negative numbers(-1)

- sign bit(leftmost bit): **0b00000011 == 3** and **0b10000011 == -3**

drawback1: 0b00000000 = 0 = 0b10000000

drawback2: arithmetic operations have to be signedness-aware

> (unsigned) 0b00000000 - 1 = 0 - 1 = 255 == 0b11111111
>
> (signed) 	 0b00000000 - 1 = 0 - 1 = -1    == 0b10000001

- two's complement

1. 0 == 0b00000000
2. negative numbers are represented as the large positive numbers that they would correlate to
   1.   0 - 1 == 0b11111111 == 255(unsigned) == -1(signed)
   2.  -1 - 1 == 0b11111110 == 254 == -2
3. the leftmost sign is still there, smallest expressible negative number : 0b10000000 = -128
4. unsigned: -128->127             signed: 0->255

⑤anatomy of a word

![](img/pwn_college/lesson/Word.png)

## Assembly Crash Course: Registers

CPU need rapid access to data via the Register File, it's fast and temporary stores for data

**"general purpose" registers**

- 8085: a,c,d,b,e,h,l
- 8086:ax,cx,dx,bx,`sp`,`bp`,si,di
- x86:eax,ecx,edx,ebx,`esp`,`ebp`,esi,edi
- amd64:rax,rcx,rdx,rbx,`rsp`,`rbp`,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15
- arm:r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,`r13`,`r14`

**address of the next instruction**

- eip(x86), rip(amd64), r15(arm)

①partial accesses on amd64

![](img/pwn_college/lesson/register1.png)

data specified directly in the instruction is called an **Immediate Value**

`sets rax to 0xffffffffffff0539`

```assembly
mov rax, 0xffffffffffffffff		;doesn't move, it copies it
mov ax, 0x539
```

`sets rax to 0x0000000000000539`

```assembly
mov rax, 0xffffffffffffffff
mov eax, 0x539	;---->32-bit partial:CPU will zero out the rest of the register
```

```assembly
mov rax, rbx;	between registers
```

②extending data

`mov eax, -1`

eax is now 0xffffffff(both 4294967295 and -1)

rax is now 0x00000000ffffffff(only 4294967295 )

**operate on that -1 in 64-bit land**

`mov eax, -1`

`movsx rax, eax` ---> do a sign-extending move, preserving the two's complement value(copies the top bit to the rest of the register)

eax is now 0xffffffff(both 4294967295 and -1)

rax is now 0xffffffffffffffff(both 4294967295 and -1) 

③register arithmetic

most arithmetic instructions the first specified register stores the result

![](img/pwn_college/lesson/operation.png)

④special registers

- can't directly read from or write to **rip** , it contains the memory address of the next instruction to be executed (Instruction Pointer)
- careful with **rsp** , it contains the address of an region of memory to store temporary data (Stack Pointer)

## Assembly Crash Course: Memory

Registers: expensive+limited numbers

system Memory: a place to store lots of data and fast

①Process Perspective

Memory <----> Registers+Dist+Network+Video Card

Process memory is addressed linearly

**From: 0x10000** (for security reasons)

**To: 0x7fffffffffff** (for architecture / OS purposes)

| 0x10000 |                     |      |                                                    |      |                                                   |      |              |      |               |      |                   | 0x7fffffffffff |
| ------- | ------------------- | ---- | -------------------------------------------------- | ---- | ------------------------------------------------- | ---- | ------------ | ---- | ------------- | ---- | ----------------- | -------------- |
|         | Program Binary Code |      | Dynamically Allocated Memory(managed by libraries) |      | [Dynamically Mapped Memory(requested by process)] |      | Library Code |      | Process Stack |      | OS Helper Regions |                |

②Stack - temporary data storage

registers and immediates can be pushed to stack `push rax`, `push 0xaabbccdd` (even on 64-bit x86, can only push 32-bit immediates)

values can be popped back off of the stack(to the register) `pop rax`

[CPU knows: stack address is stored in rsp] (top stack address < bottom stack address)

- push decreases rsp by 8 in hex
- pop increases rsp by 8 in hex

③accessing memory(between register and memory)

load the 64-bit value stored at memory address 0x12345 into rbx:

```assembly
mov rax, 0x12345
mov rbx, [rax]
```

store the 64-bit value in rbx into memory at address 0x133337

```assembly
mov rax, 0x133337
mov [rax], rbx
```

push rcx :

```assembly
sub rsp, 8
mov [rsp], rcx
```

**Each addressed memory location contains one byte!!!: 8-byte write at address 0x133337 will write to addresses 0x133337 through 0x13333f**

④Memory Endianess

backwards--->in little endian

![](img/pwn_college/lesson/endian.png)

⑤address calculation

get the calculated address with **Load Effective Address(lea)**

```assembly
mov rax, 1
pop rcx
lea rbx, [rsp+rax*8+5] 			;rbx holds the computed address
mov rbx, [rbx]
```

limits: **reg+reg*(2 or 4 or 8)+value**

⑥RIP-Relative Addressing

```assembly
lea rax, [rip+8]
lea rax, [rip]
--------------
mov rax, [rip]
--------------
mov [rip], rax
```

also can write immediate values (must specify the size)

```assembly
mov rax, 0x133337
mov DWORD PTR [rax], 0x1337
```

## Assembly Crash Course: Control Flow 



## embryoasm

-----------send/craft/assemble/pipe raw bytes over stdin to program

 **registers**

level1: **mov**---->`* rdi = 0x11`

```assembly
; 1.s
.global _start					; global:make a symbol visible to the linker _start:the starting address of function
.intel_syntax noprefix			; use the intel syntax
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
imul rdi,rsi 	; multiply--->imul
add rdi,rdx
mov rax,rdi
```

level4: **divide**

```assembly
mov rax, reg1; div reg2 	; reg1:divided reg2:divisor
							;#rax = reg1/reg2	; rdx = remainder
mov rax, rdi; div rsi 		; get the flag
```

level5: **modulo**

```assembly
; rdi % rsi ->remainder to rax

mov rax, rdi; div rsi
mov rax, rdx
```

level6: **lower register**

independent access to lower register bytes

| 64bits | 32bits | 16bits | 8bits |
| ------ | ------ | ------ | ----- |
| rax    | eax    | ax     | ah al |
| rdi    | edi    | di     | dil   |

![](img/pwn_college/level6/rax.png)

only use the 'mov' to compute:

- rax = rdi modulo 256				,256= 2<sup>8</sup> ---------->8---1,0000,0000
- rbx = rsi modulo 65536            ,65536=2<sup>16</sup>------->16---1,0000,0000,0000,0000

```assembly
mov rcx,rdi 		; first move to the General-Purpose Registers
mov al,cl			; 8bits
mov rdx,rsi
mov bx,dx			; 16bits
```

If B is a power of 2, `A % B` can be simplified to `A & (B-1)` . A can be any number, B = 2<sup>0</sup> ,2<sup>1</sup> ,2<sup>2</sup> ,2<sup>N</sup> ...(If B is 256, so B-1 is FFFF,FFFF in binary)

level7: **shl,shr**---->it will add 0 in another side

shift: **rax=10001010** ,  after the instruction`shl rax, 1`, **rax=00010100**------>8bits

register has 64bits=8*8bits			

shl reg1, x       <=>     Shift reg1 left by x
shr reg1, x      <=>     Shift reg1 right by x

rdi = | B7 | B6 | B5 | B4 | B3 | B2 | B1| B0 |, and set the rax to the value of B4, (rdi=0x77665544332211)

```assembly
mov rax,rdi
shl rax,24 		; 3*8=0x18
shr rax,56 		; 3*8+4*8=0x38 <----It's important to add the front move
```

level8: **and,or,xor,no**---->bitwise logic

![](img/pwn_college/level8/andorxor.png)

rax = rdi AND rsi

```assembly
and rdi, rsi
xor rax, rax 		; make the rax to 0
or rax, rdi  		; use the or 
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
and rdi, 1 					; first 0and1=0,1and1=1,so the smalliest bit even turn to 0,odd turn to 1
							; other bits and 0 so they're turned to 0
xor rdi, 1 					; second 0xor1=1,1xor1=0,so the smalliest bit even to 1, odd to 0
							; other bits 0 xor 0 = 0
xor rax, rax 				; make rax 0
or rax, rdi 
```

**memory**

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

* Quad Word = 8 Bytes = 64 bits			 rax             0x1234567812345678
* Double Word = 4 bytes = 32 bits          eax            0x12345678
* Word = 2 bytes = 16 bits                        ax              0x1234
* Byte = 1 byte = 8 bits                              ah, al         0x12

perform:

 	1. Set rax to the byte at 0x404000
 	2. Set rbx to the word at 0x404000
 	3. Set rcx to the double word at 0x404000
 	4. Set rdx to the quad word at 0x404000

```assembly
mov al, [0x404000]
mov bx, [0x404000]
mov ecx, [0x404000]
mov rdx, [0x404000] 		; get flag
```

level12:

**Little Endian** :  values are stored *in reverse* order of how we represent them

[0x1330] = 0x00000000deadc0de

[0x1330] = 0xde 0xc0 0xad 0xde 0x00 0x00 0x00 0x00	<--------actually in memory

**Register indirect addressing** : Perform----> set [rdi] = 0xaaa , can't directly use like this

```assembly
mov rax, 0xaaa
mov [rdi], rax 		; get flag

; show like below:
movabs  rax, 0xaaa
mov     qword ptr [rdi], rax
```

level13:

```
[0xa] = 0x1122334455667778
--->byte by byte
[0xa] = 0x78
[0xa + 1] = 0x77
...
[0xa + 7] = 0x11
```

**relative addressing**  -------> perform:

- Load two consecutive quad words from the address stored in rdi, get a, b.
- Get the sum of a, b. 
- Store the sum at the address in rsi.

```assembly
mov rax, [rdi]
mov rbx, [rdi+8]	;8bytes => quad words
add rax,rbx
mov [rsi], rax
```

**stack**

level14:	

stack: last in first out(LIFO) memory structure and **push** value into it and **pop** value out of it.

perform: **"Subtract rdi from the top value on the stack"** means `TopValue in stack - rdi`

```assembly
pop rax
sub rax, rdi
push rax
```

level15: **exchange** ----> swap rdi, rsi only use the push and pop

```assembly
push rdi
push rsi
pop rdi
pop rsi
```

level16: **rsp**---->rsp points to the top of the stack, can use the [rsp] to access the value at the memory address in rsp.

perform: calculate average of 4 consecutive qwords on the stack, and store it to the top of the stack 

```assembly
mov rax, [rsp]
add rax, [rsp+8]
add rax, [rsp+16]
add rax, [rsp+24]
mov rbx, 4
div rbx
mov [rsp], rax			#-----> the first method

;mov [rsp-8], rax
;sub rsp, 8     		#-----> the second method:simulate the `push` instruction
```

**control flow manipulation** : directly or indirectly control the regester "RIP"

level17: **jumps** 

- **unconditional** jumps and **conditional** jumps
- **Relative** jumps and **Absolute** jumps and **Indirect** jumps

relative jump: we should fill space in the code to make it possible so we use the `nop` like

```assembly
jmp (reg1 | addr | offset) ; nop
```

perform:

> 1. Make the first instruction in your code a jmp
> 2. Make that jmp a relative jump to 0x51 bytes from its current position
> 3. At 0x51 write the following code:
> 4. Place the top value on the stack into register rdi
> 5. jmp to the absolute address 0x403000

we should use the `.rept count ... .endr` : Repeat the sequence of lines between the .rept directive and the next .endr directive count times.

```assembly
_start:
	jmp instruction			;relative jumps
	.rept 0x51
		nop					;0x51 nop so the instruction is after 0x51 from the 2:jmp
	.endr

instruction:
	mov rdi, [rsp]
	mov rax, 0x403000		;address!
	jmp rax					; absolute jumps
```

level18: **conditional jumps** ---> get a if-else function using the `jne` and `je` and `cmp`

> if [x] is 0x7f454c46:
> y = [x+4] + [x+8] + [x+12]
> else if [x] is 0x00005A4D:
> y = [x+4] - [x+8] - [x+12]
> else:
> y = [x+4] * [x+8] * [x+12]
> where:
> x = rdi, y = rax. Assume each dereferenced value is a **signed dword** .

```assembly
_start:
        mov ebx, [rdi]
        cmp ebx, 0x7f454c46
        je first
        nop
        mov ebx, [rdi]
        cmp ebx, 0x00005A4D
        je second
        nop
        mov ecx, [rdi+4]
        imul ecx, [rdi+8]
        imul ecx, [rdi+12]
        jmp done
first:
        mov ecx, [rdi+4]
        add ecx, [rdi+8]
        add ecx, [rdi+12]
        jmp done
second:
        mov ecx, [rdi+4]
        sub ecx, [rdi+8]
        sub ecx, [rdi+12]
        jmp done
done:
        mov eax, ecx
```

1. `done` function is the most important to add because of the **order of execution** .
2. the **ZF, the Zero Flag** . The ZF is set to 1 when a cmp is equal. 0 otherwise.

level19

> switch(number):
>  0: jmp do_thing_0
>  1: jmp do_thing_1
>  2: jmp do_thing_2
>  default: jmp do_default_thing

reduced else-if

using jump table: A jump table is a contiguous section of memory that holds addresses of places to jump

jump table could look like:

> [0x1337] = address of do_thing_0
> [0x1337+0x8] = address of do_thing_1
> [0x1337+0x10] = address of do_thing_2
> [0x1337+0x18] = address of do_default_thing

**implement:** 

> if rdi is 0:
>  jmp 0x403040
> else if rdi is 1:
>  jmp 0x4030f7
> else if rdi is 2:
>  jmp 0x4031f1
> else if rdi is 3:
>  jmp 0x4032b9
> else:
>  jmp 0x40337c

**an example jump table:** 

> [0x4041df] = 0x403040 
> [0x4041e7] = 0x4030f7
> [0x4041ef] = 0x4031f1
> [0x4041f7] = 0x4032b9
> [0x4041ff] = 0x40337c

**constraints:**

- assume rdi will NOT be negative
- use no more than 1 cmp instruction
- use no more than 3 jumps (of any variant)
- we will provide you with the number to 'switch' on in rdi.
- we will provide you with a jump table base address in rsi.

```assembly
_start:
        mov rax, rdi
        cmp rax, 4
        jl done			;jump to `done` if less
        nop
        mov rdi, 4

done:
        jmp [rsi+rdi*0x8]
        nop
```

level20: **for-loop** ----->iterate for a *number* of times

perform: compute the average of n consecutive quad words

```python
sum = 0		
i = 1	
for i <= n:
    sum += i
    i += 1
#rdi = memory address of the 1st quad word
#rsi = n (amount to loop for)
#rax = average compute
```

- [0x404128:0x404310] = {n qwords}	---->8 bytes

- rdi = 0x404128
- rsi = 61

```assembly
_start:
        xor rax, rax
        xor rbx, rbx
        mov rbx, rsi
loop:
        sub rbx, 1
        add rax, [rdi+rbx*8]
        cmp rbx, 0
        jne loop
        nop
        div rax, rsi
```

ps: **jle : ≤**

level21: **while-loop** ----->iterate until meet a *condition*

```python
average = 0
i = 0
while x[i] < 0xff:
    average += x[i]
    i += 1
average /= i
```

**Count** the consecutive non-zero bytes in a contiguous region of memory, where:

- rdi = memory address of the 1st byte

- rax = number of consecutive non-zero bytes
- if rdi = 0, then set rax = 0

**Example**

```assembly
rdi = 0x1000
[0x1000] = 0x41
[0x1001] = 0x42
[0x1002] = 0x43
[0x1003] = 0x00

;then: rax = 3 should be set
```

```assembly
.global _start
.intel_syntax noprefix

_start:
        xor rbx, rbx
        xor rax, rax
        cmp rdi, 0
        je done
        mov rsi, 0
loop:
        mov rbx, [rdi+rsi]	;<------------------------------------------+
        add rsi, 1			;<------------------------------------------|
        cmp rbx,0			;											|
        jne loop			;											|
        sub rsi, 1			;rsi need to sub 1 because of the add 1 is behind the mov
        mov rax, rsi
done:
```

**functions**

level22: **function** ---->a callable segment of code that does not destory control flow. Use the "call" and "ret" instructions

>  ip control 、utilize the stack to save things 、call other functions provided

The "call" instruction pushes the memory address of the next instruction onto the stack and then jumps to the value stored in the first argument.

```assembly
0x1021 mov rax, 0x400000
0x1028 call rax
0x102a mov [rsi], rax
...
0x1042 ret

STACK ADDR VALUE
RSP+0x0	   0x0000102a
```

- call pushes `0x102a`, the address of the next instruction, onto the stack
- call jumps to `0x400000`, the value stored in rax
- ret pops the top value off of the stack and jumps to it`0x102a`

**implement the following logic:**

```c
str_lower(src_addr):
    rax = 0
    if src_addr != 0:
        while [src_addr] != 0x0:
            if [src_addr] <= 90:
                [src_addr] = foo([src_addr])
                rax += 1
            src_addr += 1
//foo is provided at 0x403000. foo takes a single argument as a value
```

**example**

```
- (data) [0x404000] = {10 random bytes},
- rdi = 0x404000
```

```assembly
_start:
	mov rax,0
    mov rsi,rdi
    cmp rsi,0
    je done
loop:
    mov bl,[rsi]	
    cmp bl,0			;**bl**! --->0x00
    je done
    cmp bl,90			;**bl**! --->0x5a
    ja next
    mov dil,bl		  	;rdi is the first parameter of the function call
    mov rdx,rax			;rax is the first return of function call,save original rax to rdx
    mov rcx,0x403000
    call rcx
    mov [rsi],al
    mov rax,rdx		
    add rax,1
next:
	add rsi,1
	jmp loop
done:
	ret
```

level23

