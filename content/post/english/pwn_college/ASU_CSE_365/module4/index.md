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

level4: **listen on a socket**

```shell
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] listen(3, 0) = 0
[ ] exit(0) = ?
```

| NR   | SYSCALL NAME | references | RAX  | ARG0(rdi) | ARG1(rsi) | ARG2(rdx) | ARG3(r10) | ARG4(r8) | ARG5(r9) |
| ---- | ------------ | ---------- | ---- | --------- | --------- | --------- | --------- | -------- | -------- |
| 50   | listen       | man/ cs/   | 32   | int       | int       | -         | -         | -        | -        |

> **int listen(int sockfd, int backlog)**

```assembly
mov rdi, 3
mov rsi, 0
mov rax, 50
syscall
```

level4: **accept a connection**

```shell
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] listen(3, 0) = 0
[ ] accept(3, NULL, NULL) = 4
[ ] exit(0) = ?
```

| NR   | SYSCALL NAME | references | RAX  | ARG0(rdi) | ARG1(rsi)         | ARG2(rdx) | ARG3(r10) | ARG4(r8) | ARG5(r9) |
| ---- | ------------ | ---------- | ---- | --------- | ----------------- | --------- | --------- | -------- | -------- |
| 43   | accept       | man/ cs/   | 2B   | int       | struct sockaddr * | int *     | -         | -        | -        |

> **int accept(int sockfd, struct sockaddr `*`addr, socklen_t *addrlen)**

I write a c program about the accept and `objdump` it, then I find that the `NULL` should only set to the `0x0` to the register. It works.

```assembly
mov rdi, 3
mov rsi, 0x0
mov rdx, 0x0
mov rax, 43 #accept
syscall
```

level6: **respond to an http request**

```shell
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] listen(3, 0) = 0
[ ] accept(3, NULL, NULL) = 4
[ ] read(4, <read_request>, <read_request_count>) = <read_request_result>
[ ] write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
[ ] close(4) = 0
[ ] exit(0) = ?
```

| NR   | SYSCALL NAME | references | RAX  | ARG0(rdi)       | ARG1(rsi)       | ARG2(rdx)    | ARG3(r10) | ARG4(r8) | ARG5(r9) |
| ---- | ------------ | ---------- | ---- | --------------- | --------------- | ------------ | --------- | -------- | -------- |
| 0    | read         | man/ cs/   | 0    | unsigned int fd | char *buf       | size_t count | -         | -        | -        |
| 1    | write        | man/ cs/   | 1    | unsigned int fd | const char *buf | size_t count | -         | -        | -        |
| 3    | close        | man/ cs/   | 3    | unsigned int fd | -               | -            | -         | -        | -        |

> **ssize_t read(int fd, void `*`buf, size_t count);**
>
> **ssize_t write (int filedes, void `*` buf, size_t nbytes);** 
>
> **int close(int fd);**

Only show the newly added code: 

```assembly
		mov rdi, 4
        mov rsi, rsp
        mov rdx, 256
        mov rax, 0 #read
        syscall

        mov rdi, 4
        lea rsi, [rip+msg]
        mov rdx, 19
        mov rax, 1 #write
        syscall

        mov rdi, 4
        mov rax, 3 #close
        syscall
.section .data
msg:
        .ascii "HTTP/1.0 200 OK\r\n\r\n"
```

level7: **respond to a GET request for the contents of a specified file**

```shell
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] listen(3, 0) = 0
[ ] accept(3, NULL, NULL) = 4
[ ] read(4, <read_request>, <read_request_count>) = <read_request_result>
[ ] open("<open_path>", O_RDONLY) = 5
[ ] read(5, <read_file>, <read_file_count>) = <read_file_result>
[ ] close(5) = 0
[ ] write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
[ ] write(4, <write_file>, <write_file_count> = <write_file_result>
[ ] close(4) = 0
[ ] exit(0) = ?
```

find out the definition of the `O_RDONLY`: 

```shell
hacker@babyserver_level7:~/module4/7$ grep -r "O_RDONLY" /usr/include/
/usr/include/x86_64-linux-gnu/bits/fcntl-linux.h:#define O_RDONLY            00
```

There're something to mention: the `<open_path>` should be the file that accept from the client and it is automatic, so we can't put a casual path to the open(). The second thing is that we must get the right content of the file so we should save the count after reading from the file.

```assembly
.global _start
.intel_syntax noprefix

.section .text

_start:
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0 
        mov rax, 41 #socket
        syscall

        mov rdi, 3
        lea rsi, [rip+sockaddr]
        mov rdx, 16
        mov rax, 49 #bind
        syscall

        mov rdi, 3
        mov rsi, 0
        mov rax, 50 #listen
        syscall

        mov rdi, 3
        mov rsi, 0x0
                mov rdx, 0x0
        mov rax, 43 #accept
        syscall

        mov rdi, 4
        mov rsi, rsp
        mov rdx, 0x1000
        mov rax, 0 #read
        syscall
#GET /temp/xxxx HTTP/1.0
#      		   ^
# r10		   \0

#got the /temp/xxxx<----automatic

loop:
        mov al, [rsp]
        cmp al, ' '
        je next
        inc rsp
        jmp loop
next:
        inc rsp
        mov r10, rsp

loop2:
        mov al, [rsp]
        cmp al, ' '
        je next2
        inc rsp
        jmp loop2
next2:
        mov byte ptr [rsp], 0
        mov rdi, r10
        #lea rdi, [rip+filepath]
        mov rsi, 0
        mov rax, 2 #open
        syscall

        mov rdi, 5
        mov rsi, rsp
        mov rdx, 0x1000
        mov rax, 0 #read
        syscall
        mov r12, rax		#tried the r11 will have errors so change to the r12
        					#save the size returning from the read func

        mov rdi, 5
        mov rax, 3
        syscall

        mov rdi, 4
        lea rsi, [rip+msg]
        mov rdx, 19
        mov rax, 1 #write
        syscall

        mov rdi, 4
        mov rsi, rsp
        mov rdx, r12
        mov rax, 1
        syscall

        mov rdi, 4
        mov rax, 3 #close
        syscall

        mov rdi, 0
        mov rax, 60 #exit
        syscall

.section .data
sockaddr:
        .2byte 2
        .2byte 0x5000
        .4byte 0
        .8byte 0
msg:
        .ascii "HTTP/1.0 200 OK\r\n\r\n"
filepath:
        .ascii "/tmp/"		#didn't use
```

level8: **accept multiple requests**

Compare with the level7, delete the `exit` and add the `accept` again

level9: **concurrently accept multiple requests**

```shell
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] listen(3, 0) = 0
[ ] accept(3, NULL, NULL) = 4
[ ] fork() = <fork_result>
[ ] close(4) = 0
[ ] accept(3, NULL, NULL) = ?

===== Expected: Child Process =====
[ ] close(3) = 0
[ ] read(4, <read_request>, <read_request_count>) = <read_request_result>
[ ] open("<open_path>", O_RDONLY) = 3
[ ] read(3, <read_file>, <read_file_count>) = <read_file_result>
[ ] close(3) = 0
[ ] write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
[ ] write(4, <write_file>, <write_file_count> = <write_file_result>
[ ] exit(0) = ?
```

| NR   | SYSCALL NAME | references | RAX  | ARG0(rdi) | ARG1(rsi) | ARG2(rdx) | ARG3(r10) | ARG4(r8) | ARG5(r9) |
| ---- | ------------ | ---------- | ---- | --------- | --------- | --------- | --------- | -------- | -------- |
| 57   | fork         | man/ cs/   | 39   | -         | -         | -         | -         | -        | -        |

> **pid_t fork(void);**

For the parent process it will get the ID or return Number of the new created child processes and the child process get the `0` ID so we need to use conditional jumps to distinguish between them.

```assembly
mov rax, 57 #fork
syscall

mov r8, rax
cmp r8, 7
je parent
cmp r8, 0
je child
```

level10: **respond to a POST request with a specified file and update its contents**

```shell
===== Expected: Child Process =====
[ ] close(3) = 0
[ ] read(4, <read_request>, <read_request_count>) = <read_request_result>
[ ] open("<open_path>", O_WRONLY|O_CREAT, 0777) = 3
[ ] write(3, <write_file>, <write_file_count> = <write_file_result>
[ ] close(3) = 0
[ ] write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
[ ] exit(0) = ?
```

| NR   | SYSCALL NAME | references | RAX  | ARG0(rdi)            | ARG1(rsi) | ARG2(rdx)    | ARG3(r10) | ARG4(r8) | ARG5(r9) |
| ---- | ------------ | ---------- | ---- | -------------------- | --------- | ------------ | --------- | -------- | -------- |
| 2    | open         | man/ cs/   | 2    | const char *filename | int flags | umode_t mode | -         | -        | -        |

> **int open(const char `*`pathname, int flags, mode_t mode);**

```shell
/usr/include/x86_64-linux-gnu/bits/fcntl-linux.h:# define O_CREAT          0100 /* Not fcntl.  */
/usr/include/x86_64-linux-gnu/bits/fcntl-linux.h:#define O_WRONLY            01
```

the 3rd argument of `0777` is OCT so we need to change it to the HEX `1FF`.

`POST`:

![](img/pwn_college/level10/POST.png)

and we should do in level10 is :

![](img/pwn_college/level10/TODO.png)

```assembly
.global _start
.intel_syntax noprefix

.section .text

_start:
		mov rdi, 2
		mov rsi, 1
		mov rdx, 0 
		mov rax, 41 #socket
		syscall
	
		mov rdi, 3
		lea rsi, [rip+sockaddr]
        mov rdx, 16	
        mov rax, 49 #bind
        syscall

        mov rdi, 3
        mov rsi, 0
        mov rax, 50 #listen
        syscall

        mov rdi, 3
        mov rsi, 0x0
        mov rdx, 0x0
        mov rax, 43 #accept
        syscall	

        mov rax, 57 #fork
        syscall

        mov r8, rax
        cmp r8, 7
        je parent
        cmp r8, 0
        je child
parent:
		mov rdi, 4
        mov rax, 3 #close
        syscall

		mov rdi, 3
        mov rsi, 0x0
        mov rdx, 0x0
        mov rax, 43 #accept
        syscall	
child:
		mov rdi, 3
        mov rax, 3 #close
        syscall
	
		mov rdi, 4
        mov rsi, rsp
        mov rdx, 0x1000
        mov rax, 0 #read
        syscall
		mov r14, rax	
		sub r14, 177		#calculate the size
loop:
        mov al, [rsp]
        cmp al, ' '
        je next
        inc rsp
        jmp loop
next:
        inc rsp
        mov r10, rsp

loop2:
        mov al, [rsp]
        cmp al, ' '
        je next2
        inc rsp
        jmp loop2
next2:
        mov byte ptr [rsp], 0
        mov rdi, r10
        mov rsi, 0100|01		#O_WRONLY|O_CREAT
		mov rdx, 0x1ff
        mov rax, 2 #open
        syscall
	
loop3:
		mov al, [rsp]	#must in the loop
        cmp al, 'H'
        je next3
        inc rsp
        jmp loop3
next3:
		inc rsp
loop4:
        mov al, [rsp]
        cmp al, 'L'
        je next4
        inc rsp
        jmp loop4
next4:
		add rsp, 15		#calculate the size
        mov r8, rsp

		mov rdi, 3
        mov rsi, r8
        mov rdx, r14
        mov rax, 1 #write
        syscall

		mov rdi, 3
        mov rax, 3 #close
        syscall

		mov rdi, 4
        lea rsi, [rip+msg]
        mov rdx, 19
        mov rax, 1 #write
        syscall

		mov rdi, 0
        mov rax, 60 #exit
        syscall
.section .data
sockaddr:
        .2byte 2
        .2byte 0x5000
        .4byte 0
        .8byte 0
msg:
		.ascii "HTTP/1.0 200 OK\r\n\r\n"
```

emmmm, I feel like I'm using a little trick.....

level11: **respond to multiple concurrent GET and POST requests**

![](img/pwn_college/level11/PG.png)

(still trying...)

