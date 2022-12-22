---
title: "PwnCollege_Note4"
description: the 4th module of ASU CSE 365, building a web server
date: 2022-12-22
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

# Building a Web Server

-----------**ASU CSE 365**: Introduction to Cybersecurity

## Building a Web Server: Introduction

①Computation

{{<ppt src="/img/pdf/BaWS1.pdf" >}}

②accessing hardware

instructions should first talk to the OS with the systemcall( **syscall**  like `mov rax, 42; syscall`) and then OS will operate with the hardware in Kernel

## Building a Web Server: Linux Processes

①syscall

**read(int fd, void `*`buf, size_t count)**  attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.

**write(int fd, void `*`buf, size_t count)** writes up to count bytes from the buffer starting at buf to the file referred to by the file descriptor fd.

**open(char `*`pathname, int flags, mode_t mode)** opens the file specified by pathname. If the specified file doesn't exist, it may optionally be created(if O_CREAT is specified in flags), the return value of it is a file descriptor that used in subsequent system calls(read(2),write(2),lseek(2),fcntl(2)) to refer to the open file.

②Linux process

struct task_struct *current

![](img/pwn_college/lesson/struct.png)

this blob of data is living in kernel memory

{{<ppt src="/img/pdf/BaWS2.pdf" >}}

In the end, the file descriptor is 3 for '/flag' and the RAX is set to 3 as the result of `open() syscall` . It saved the data into the kernel memory.

③system calls

![](img/pwn_college/lesson/systemcall.png)

for more system call can see [this](https://x64.syscall.sh/)



## babyserver

In this series of challenges, we should writing assembly to interact with the environment, and ultimately build a web server

Usage: `/challenge/babyserver <path_to_web_server>`

level1: **exit a program**

| NR   | SYSCALL NAME | references | RAX  | ARG0(rdi)      | ARG1(rsi) | ARG2(rdx) | ARG3(r10) | ARG4(r8) | ARG5(r9) |
| ---- | ------------ | ---------- | ---- | -------------- | --------- | --------- | --------- | -------- | -------- |
| 60   | exit         | man/ cs/   | 3C   | int error_code | -         | -         | -         | -        | -        |

exit (0) : run the program normally and exit the program

exit (1) : abnormal operation causes the program to exit

```assembly
.global _start
.intel_syntax noprefix

.section .text

_start:
	mov rdi, 0
	mov rax, 60			# SYS_exit
	syscall
	
.section .data
```

then use the `as` (compiler) to generates an object file from the assembly file and use the `ld` (linker) to link the object file to the library as an executable or library file

```shell
as -o server.o server.s && ld -o server server.o
```

**strace** : tracks system calls and received signals as a process executes

```shell
hacker@babyserver_level1:~/module4/1$ strace ./server
execve("./server", ["./server"], 0x7ffc21a0ed30 /* 29 vars */) = 0
exit(0)                                 = ?
+++ exited with 0 +++
```

get flag:

```shell
/challenge/babyserver ./server
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] exit(0) = ?

===== Trace: Parent Process =====
[✓] execve("/proc/self/fd/3", ["/proc/self/fd/3"], 0x7f9ad0f54a80 /* 0 vars */) = 0
[✓] exit(0)                                 = ?
[?] +++ exited with 0 +++

===== Result =====
[✓] Success
```

level2: **create a socket**

| NR   | SYSCALL NAME | references | RAX  | ARG0(rdi) | ARG1(rsi) | ARG2(rdx) | ARG3(r10) | ARG4(r8) | ARG5(r9) |
| ---- | ------------ | ---------- | ---- | --------- | --------- | --------- | --------- | -------- | -------- |
| 41   | socket       | man/ cs/   | 29   | int       | int       | int       | -         | -        | -        |

```shell
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] exit(0) = ?
```

> **int socket(int domain, int type, int protocol)** 
>
> need: **socket(AF_INET, SOCK_STREAM, IPPROTO_IP)**

- First, we can write it in a c program and look at the errors so that we can put the header files(.h) to c program, seeing each argument

- then, use the `find /usr/include | grep xxx.h`  and then `cat` it to find the `define` things. Strace the c program can find out some syscalls

- finally, use the `objdump -D -M intel xx.out` to see the assembly program

(such as the IPPROTO_IP in netinet/in.h is 0)

![](img/pwn_college/level2/cpro.png)

![](img/pwn_college/level2/ctoas.png)

```shell
#some useful tool
grep -r 'IPPROTO_IP' /usr/include | grep define
grep -r 'define AF_INET' /usr/include
#define AF_INET PF_INET
grep -r 'define PF_INET' /usr/include
#define PF_INET 2
----------------------------------
```

```python
import pwn
pwn.constants.AF_INET	#get the constant of AF_INET
print(int(pwn.constants.AF_INET))
```

so we can get the solution:

```assembly
.global _start
.intel_syntax noprefix

.section .text

_start:
        mov rdi, 2			;domain:AF_INET
        mov rsi, 1			;type:SOCK_STREAM
        mov rdx, 0 			;protocol:IPPROTO_IP
        mov rax, 41
        syscall				;socket
        mov rdi, 0
        mov rax, 60
        syscall
.section .data
```

