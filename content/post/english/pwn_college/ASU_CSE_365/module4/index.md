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

## Building a Web Server: Network System Calls

①socket

```c
int socket(in domain, int type, int protocol)
//socket() creates an endpoint for communication and returns a file descriptor that refers to that endpoint
```

②bind

```c
int bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
//when a socket(2) is created with socket, it exits in a name space but has no address assigned to it.bind() assigns the address specified by addr to the socket referred to by the file descriptor sockfd.
```

③struct sockaddr_in

```c
struct sockaddr{
	uint16_t sa_family;
	uint8_t sa_data[14];
};

struct sockaddr_in{
	uint16_t sin_family;
	uint16_t sin_port;
	uint32_t sin_addr;
	uint8_t __pad[8];
}
```

![](img/pwn_college/lesson/structlesson.png)

AF_INET is 2; htons() function used to convert the number from little endian to big endian for networking work on big ending integers; ipv4 address of 4 bytes is also big endian, the inet_addr() function converts an unsigned integer IP from a host end-order to a network end-order

④listen

```c
int listen(int sockfd, int backlog)
//listen() marks the socket referred to by sockfd as a passive socket that will be used to accept incoming connection requests using accept(2)
```

⑤accept

```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
//it's used with connection-based socket types(SOCK_STREAM,SOCK_SEQPACKET).It extracts the first connection request on the queue of pending connections for the listening socket, sockfd, creates a new connected socket, and returns a new file descriptor referring to that socket.
```

⑥accept TCP/IP network connections

![](img/pwn_college/lesson/acceptTCP.png)

## Building a Web Server: HTTP

![](img/pwn_college/lesson/Uhttp.png)

## Building a Web Server: Multiprocessing

if there're lots of http requests, we should another system call.

①fork()

creates a new process by duplicating the calling process. The new process is referred to as the child process. The calling process is referred to as the parent process.

On success, the PID of the child process is returned to the parent, and 0 is returned in the child.

{{<ppt src="/img/pdf/BaWS5.pdf" >}}

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

level3: **bind an address to a socket**

| NR   | SYSCALL NAME | references | RAX  | ARG0(rdi)        | ARG1(rsi) | ARG2(rdx) | ARG3(r10) | ARG4(r8) | ARG5(r9) |
| ---- | ------------ | ---------- | ---- | ---------------- | --------- | --------- | --------- | -------- | -------- |
| 49   | bind         | man/ cs/   | 31   | struct sockaddr* | int       | -         | -         | -        | -        |

> **int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)**
>
> func: Bind a socket file that specifies the communication protocol to the IP and port

```shell
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, { sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] exit(0) = ?
```

we can use the pwntools to set the little ending data(port):

```python
import pwn
pwn.p16(80,endian="little").hex() #port
```

the solution:

```assembly
.global _start
.intel_syntax noprefix

.section .text

_start:
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0 
        mov rax, 41 		#socket
        syscall

        mov rdi, 3
        lea rsi, [rip+sockaddr]			#lea(load effective address)Take the source's offset address
        mov rdx, 16
        mov rax, 49 		#bind
        syscall

        mov rdi, 0
        mov rax, 60 		#exit
        syscall

.section .data
sockaddr:
        .2byte 2			#AF_INET
        .2byte 0x5000		#port:80--->little ending 50 00
        .4byte 0			#addr:0.0.0.0
        .8byte 0
```

we first find the file `/usr/include/netinet/in.h` and find out the sockaddr_in struct

```c
struct sockaddr_in
{
	__SOCKADDR_COMMON (sin_);
    in_port_t sin_port;                 /* Port number.  */
    struct in_addr sin_addr;            /* Internet address.  */

    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr)
                           - __SOCKADDR_COMMON_SIZE
                           - sizeof (in_port_t)
                           - sizeof (struct in_addr)];
};
```

and then we step by step find out the size of every type of data.

```c
#define __SOCKADDR_COMMON_SIZE        (sizeof (unsigned short int))		//2bytes

/* Type to represent a port.  */
typedef uint16_t in_port_t;		//2bytes

/* Internet address.  */
typedef uint32_t in_addr_t;		//4bytes
struct in_addr
{
    in_addr_t s_addr;
};
```

