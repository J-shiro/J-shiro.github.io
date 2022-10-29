---
title: "PwnCollege_Note"
description: 
date: 2022-10-29
image: 
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - Pwn.college
    - ForeignCourse

---

# ASU CSE 365

## Program Misuse

### Program Interaction:Linux Command Line



### babysuid challenge

there're some simple programs that can directly read the flag：**cat, more, less, tail, head, sort**

there're some tools  ----> over-privileged editors：**vim, emacs, nano**

level 10：**rev**---> Used to output each line of a file in reverse order of characters, that is, the first character is last and the last character is first.

level 11: **od**---> Octal, decimal, hex, ASCII dump

```shell
-b:octal		-x -h:hex
-c:ASCII		-d:Decimal(ten)
```

