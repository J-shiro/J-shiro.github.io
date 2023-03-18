---
title: "PwnCollege_Note9"
description: ASU CSE 365, debugging refresher
date: 2023-03-12
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

# Debugging Refresher

-----------**ASU CSE 365**: System Security



## embryogdb

`GDB` is a very **powerful dynamic analysis tool**. 

level1: **using the command 'continue' or 'c' to continue program execution**

- We can use the command `start` to start a program with a breakpoint set on `main`
- We can use the command `starti` to start a program with a breakpoint set on `_start`
- We can use the command `run` to start a program with no breakpoint set
- We can use the command `attach <PID>` to attach some other already running program
- We can use the command `core <PATH>` to analyze the coredump of an already run program

```shell
Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000562ea524dbe3 in main ()
(gdb) c
Continuing.
You win! Here is your flag:
pwn.college{a}
```

level2: **figure out the current random value of register r12 in hex**

You can see the values for all your registers with `info registers`. Alternatively, you can also just print a particular register's value with the `print` command, or `p` for short. 

For example, `p $rdi` will print the value of **$rdi** in decimal. You can also print it's value in hex with `p/x $rdi`

```shell
0x00005570c16a0bfd in main ()
(gdb) p/x $r12
$1 = 0xbd8828029758eae2
(gdb) c
Continuing.
Random value: 0xbd8828029758eae2
You input: bd8828029758eae2
The correct answer is: bd8828029758eae2
You win! Here is your flag:
pwn.college{a}
```

level3: **figure out the random value on the stack (the value read in from `/dev/urandom`).Think about what the arguments to the read system call are.**

Examine the contents of memory using the `x/<n><u><f> <address>` parameterized command. In this format 

- `<u>` is the **unit size** to display

  - Valid unit sizes are `b` (1 byte), `h` (2 bytes), `w` (4 bytes), and `g` (8 bytes).

  - ```shell
    (gdb) x/4bx $rsp
    0x7ffd419bf2c0: 0x02    0x00    0x00    0x00
    (gdb) x/4hx $rsp
    0x7ffd419bf2c0: 0x0002  0x0000  0x0000  0x0000
    (gdb) x/4wx $rsp
    0x7ffd419bf2c0: 0x00000002      0x00000000      0x419bf408      0x00007ffd
    (gdb) x/4gx $rsp
    0x7ffd419bf2c0: 0x0000000000000002      0x00007ffd419bf408
    0x7ffd419bf2d0: 0x00007ffd419bf3f8      0x00000001722e1d10
    ```

- `<f>` is the **format** to display it in

  - Valid formats are `d` (decimal), `x` (hexadecimal), `s` (string) and `i` (instruction).

  - ```shell
    (gdb) x/4gd $rsp
    0x7ffd419bf2c0: 2       140725704193032
    0x7ffd419bf2d0: 140725704193016 6210592016
    (gdb) x/4gx $rsp
    0x7ffd419bf2c0: 0x0000000000000002      0x00007ffd419bf408
    0x7ffd419bf2d0: 0x00007ffd419bf3f8      0x00000001722e1d10
    (gdb) x/4gs $rsp
    #warning: Unable to display strings with size 'g', using 'b' instead.
    (gdb) x/4bs $rsp
    0x7ffd419bf2c0: "\002"
    0x7ffd419bf2c2: ""
    0x7ffd419bf2c3: ""
    0x7ffd419bf2c4: ""
    (gdb) x/4gi $rsp
    0x7ffd419bf2c0:      add    (%rax),%al
    0x7ffd419bf2c2:      add    %al,(%rax)
    0x7ffd419bf2c4:      add    %al,(%rax)
    0x7ffd419bf2c6:      add    %al,(%rax)
    ```

- `<n>` is the **number of elements** to display. 

>  The address can be specified using a register name, symbol name, or absolute address

For example, `x/8i $rip` will print the next 8 instructions from the current instruction pointer. `x/16i main` will print the first 16 instructions of main. You can also use `disassemble main`, or `disas main` for short, to print all of the instructions of main. Alternatively, `x/16gx $rsp` will print the first 16 values on the stack.`x/gx $rbp-0x32` will print the local variable stored there on the stack.

You will probably want to view your instructions using the CORRECT assembly syntax. You can do that with the command `set disassembly-flavor intel`.

![](index.assets/image-20230312223322758.png)

level4: **figure out a series of random values which will be placed on the stack**

-  `stepi <n>` command, or `si <n>` for short, in order to step forward one instruction
- `nexti <n>` command, or `ni <n>` for short, in order to step forward one instruction, while stepping over any function calls. The `<n>` parameter is optional, but allows you to perform multiple steps at once
-  `finish` command in order to finish the currently executing function
- `break *<address>` parameterized command in order to set a breakpoint at the specified-address.
- `continue` command, which will continue execution until the program hits a breakpoint.

- `display/<n><u><f>` parameterized command, which follows exactly the same format as the `x/<n><u><f>` parameterized command

For example, `display/8i $rip` will always show you the next 8 instructions. On the other hand, `display/4gx $rsp` will always show you the first 4 values on the stack.

Another option is to use the `layout regs` command. This will put gdb into its TUI mode and show you the contents of all of the registers, as well as nearby instructions.

```shell
./xxx
(gdb)r
(gdb)display/4i $rip
(gdb)display/20gx $rsp

#finally we can find the change address is the rsp+0x30

(gdb)ni
#until the read
(gdb)ni
#until the scanf
#input the value of rsp+0x30
(gdb)ni #loop for a series of time
#finally get the flag
You win! Here is your flag:
pwn.college{abc}
```

