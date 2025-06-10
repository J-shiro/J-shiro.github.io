# LINUX


## 配置

bash的配置在`~/.bashrc`中

git的配置在`~/.gitconfig`中

vim的配置在`~/.vimrc`中

## 基础命令

**tree**：列举所有文件，递归列举文件

**tldr**：连接 `command` 可以列举使用该命令的用法

**journalctl**：查看和管理 systemd 日志

**alias**：命令别名，`alias command`查看别名意义

**tac**：最后一行开始，逐行向上显示内容

**curl**： 可查看公网ip地址

**htop**：进程查看器和系统监视器

**wc**：`wc -l file`，统计文件行数

**time**：获取命令执行的真实、用户、系统时间

**paste**：`paste -sd,` 将多个文件对应行合并为一行，以逗号分隔，`-s`合并为一行，`-d`指定分隔符

**tee**：`xx | tee file`从标准输入读取数据，并将数据同时写入到一个或多个文件和标准输出

**nohup**：`nohup python3 xx.py`使得一个进程在用户登出或会话终止后仍然后台继续运行

**bg**：将`jobs`命令查看的已暂停后台作业继续运行，`bg %1`指定 `jobs` 中序号

**od**：十六进制查看工具，`od -c file`

**pstree**：查看进程关系

**kill**：` kill -l`查看信号

**netstat**：`-ano`显示网络状态，监听

## 常用命令

**查看某个文件的绝对路径**： `pwd|awk '{print $1"/file_name"}'`

**查看版本**：`cat /proc/version`

**显示linux内核版本信息**：`uname -asrm                                                                                                                                     `

**查看目录及子目录磁盘使用情况**：`du -sh directory`

**查找指定进程格式**：`ps -ef | grep xx`

**查看分区挂载情况**：`df`

**编译链接线程库**：`-lpthread`

**安装deb文件**：`sudo dpkg -i`

**本地监听某端口**：`nc -l port`

**深入查看头文件定义**：`find /usr/include | grep xxx.h`

**记录某文件出现多少次该单词**：`grep -o "xxx" file.txt | wc -l`

**删除某环境变量**：`unset xx`

**更改文件夹用户及用户组**：`chown -R username:groupname directory_path`

**链接**

```bash
ln # 硬~
ln -s # 软~
```

**压缩**

```bash
tar -zvcf a.tar.gz a # 压缩
tar -zvxf a.tar.gz  # 解压

zip -r a.zip ./* # 压缩
unzip -d /xxx a.zip # 解压

gzip -d xx.gz # 解压
```

**命令行命令**

```Bash
!!               # 直接替换为上一次使用的命令
Ctrl + R         # 回溯历史操作
readelf -S xxx   # 查看程序.bss段地址
cd -             # 返回到上一次工作目录
```

## 技巧

若不需要`-a`这些参数, 可以使用`--`

```bash
cat $(some_command) # 可以直接获取命令返回结果内容
find xxx -type f | xargs cat # xargs
```

查找标准库结构体

```bash
grep -r -A 10 "struct name" /usr/include # 额外显示10行
```

查看局域网 IP：`ipconfig`，查看公网出口 IP：`curl cip.cc` 或 `ip138.com`

## 具体命令

### netstat

```Bash
 netstat -plant
 -p: --programs，与链接相关程序名和进程的PID
 -l: --listening，显示所有监听的端口
 -a: --all，显示所有链接和监听端口
 -n: 进制使用域名解析功能。链接以数字形式展示(IP地址)，而不是通过主机名或域名形式展示
 -t: 所有的 tcp 协议的端口
```

### find

```Bash
find . -name xxx -type d # d 表示 目录
find . -path '**/test/*.py' -type f # f 表示 文件

find . -name "*.tmp" -exec rm {} \;
# -exec rm {} \; 表示对每个找到的文件进行rm操作 
# {} 是一个占位符，表示当前找到的文件。find 命令会用找到的文件的完整路径替换 {}
# \; 表示 -exec 操作的结束, \ 是用来转义 ; 的， shell 中 ; 通常是一个命令分隔符
```

### lsof

列出当前系统打开文件，包括网络连接、设备

```Bash
# 列出4444端口监听的进程
lsof | grep ":4444 .LISTEN"
```

### ssh

```Bash
ssh-keygen -o -a 100 -t ed25519
# -o: 使用新的OpenSSH私钥文件格式
# -a 100: 键派生函数迭代次数
# -t ed25519: 生成的密钥类型, ed25519-一种椭圆曲线签名算法
```

会生成公私钥对`id_xxx`及`id_xxx.pub`在`.ssh`中

```Bash
cat ~/.ssh/id_xxx.pub | ssh a@x.x.x.x tee .ssh/authorized_keys
# 公钥传入远程服务器
ssh -i key xxx@ip
```

出现密钥变更

```bash
ssh-keygen -R x.x.x.x # 删除相关信息
ssh user@x.x.x.x # 重新连接
```

`scp`是ssh的子命令

```Bash
# 远程文件传输
scp -i secret_key -r local_file user@x.x.x.x:remote_file_location # 本地到远程
scp -r user@x.x.x.x:remote_file local_destination # 远程到本地
```

`rsync`同样可以传输文件，用于备份+镜像，只对差异文件更新，快速

```Bash
rsync -avP local_file user@x.x.x.x:destination # 本地到远程
# -a: 递归复制  -v: 显示详细信息  -P: 允许断点续传, 显示传输进度信息
```

**windows主机vscode免密ssh登录到服务器**

A 把公钥给 B，使得A可远程免密登录B

```bash
# windows 下
ssh-keygen -t rsa
cat id_rsa.pub # 将其公钥放入 Linux 服务器的 ~/.ssh/authorized_keys 中

ssh username@ip
ssh root@ip
scp username@remote_host:/path/to/remote/file /path/to/local/destination # 拉取文件到本地
```

### strace

```Bash
strace -e lstat ls -l > /dev/null
# 使用 strace 只跟踪 ls -l 命令中的 lstat 系统调用, 丢弃输出到/dev/null
```

### awk

```Bash
awk '{print $2}' file # 输出每行第 2 个字段
awk '$1 == 1 && $2 ~ /^c.*e$/ {print $0}' file # 第 1 列为 1, 第 2 列满足以c开头以e结尾, $0 输出当前行
```

### grep

```Bash
xxx | grep 'xxxx'
xxx | grep -E "1|2" # 正则: 含1或2
grep -r "xxx" /etc # 查找文件中内容
```

### sed

流编辑器，用于处理文本，引号内为正则表达式

```Bash
cat xxx | sed 's/^.*hello(haha)?[ab][^,]/g'
# s: 替换操作
# /: 分隔符
# ^: 匹配行的开头
# .*: 任意数量字符(除换行符)
# ()?: ?表示()中内容可以出现 0 或 1 次
# []: 匹配包含内容中的任何一个字符
# [^,]: 表示匹配除 , 外任何字符
# //: 替换成空字符串, 删除匹配内容
# g: 表示全局替换(global), 替换所有匹配的字符, 若没有g则替换一个

cat xxx | sed -E 's/(ab|bc)*\s*[0-9.]+[0-9]+$//g'
# -E: 表示使用扩展, 使得可以用()而不需要用\来对()转义
# ()*: 匹配0或多次连续的()内的内容 
# |: 表示或者
# \s*: 0个或多个空白字符
# [0-9.]+: 匹配一个或多个数字或点(IP地址)
# [0-9]+: 匹配一个或多个数字(端口)
# $: 匹配行的结尾
cat xxx | sed -E 's/x(hello)?xxx(.*)xx/\2/'
# (.*): 不仅匹配内容，还将其存储在捕获组中, 后续可用 \number 引用
# 将匹配到的内容用(.*)中的内容替换
```

### screen

用于后台挂载

```bash
screen -S xxx # 新建
screen -r xxx # 进入
screen -ls # 列举

# screen 中滑动
ctrl + A, [
# screen 中跳出
ctrl + A, ctrl + D
```



## shell

可以用`shellcheck`命令检查shell脚本错误

**基础例子**

```Bash
foo=bar
echo $foo # bar 也可在$foo外加入双引号, 效果一致
unset foo # 环境中删除 foo 变量
export PYTHONPATH="$DIR:$PYTHONPATH"

exec python "$DIR/main.py" "$@" # exec 执行命令
```

**函数**

```Bash
# a.sh 文件内容
a() {
    mkdir -p "$1"
    cd "$1"        # $1 指第1个参数
} 

# shell 中定义函数并直接执行
source a.sh
a xxx # 执行 a 中定义的函数
```

**基础变量**

```Bash
$(date)  # 日期
$0       # 当前脚本名称
$#       # 提供的参数数量
$$       # 正在运行命令的PID
$@       # 表示所有的参数, 包含$1, $2, ..., 用于遍历
$?       # 存储上一条命令的退出状态, 命令执行成功为0, 失败为非0
```

**循环**

```Bash
for file in $@; do
    grep foobar "$file" > /dev/null 2> /dev/null
    # 在提供的file中寻找字符串foobar
    # > 标准输出重定向到 /dev/null 丢弃
    # 2 > 将标准错误重定向到 /dev/null 丢弃
done
```

**条件**

```Bash
if [[ "$?" -ne 0 ]]; then
# -ne 不等于
    some_commands
fi
```

**匹配**

```Bash
xxx*     # *匹配任意
xxx?     # ?匹配一个字符
xx{1,2}  # 自动补充为xx1, xx2, 也可用多个{}做成笛卡尔积
xx{a..c} # 自动补全为xxa, xxb, xxc
```

## vim

**格式设置**

```bash
:set cindent shiftwidth=4
:set tabstop=2
```

**打开两个文件**：`Vim file1 file2 -O`

**寄存器**

1. 使用`"`指定寄存器，包括`a-z`
2. `"bdd`删除当前行到寄存器b中，`:reg a`查看寄存器a内容
3. 复制专用寄存器`"0`

**宏**

用于批处理，录制：`q{register}`开始录制到寄存器，`q`结束录制

回放：`@{register}`回放命令

在命令模式下：`:normal @a`全选文本内容后执行a寄存器中命令

### Normal

**字符前插入**：`i`；**字符后插入**：`a`

**行首插入**：`I`；**行末插入**：`A`

**换行插入**：`o`；**行上另起一行插入**：`O`

**移动**：`hjkl`左下上右，`w`移动到下一个单词开头，`b`回到上一个单词开头

**撤消**：`u`，**取消撤消**：`ctrl + R`

**快速回跳到原位**：`ctrl+o`

**删除**：`x`删除后一个字符，`daw`删除一个单词，`d`和`x`可搭配数字执行多次：`3x` or `3daw`

**查找**：`/`或`?`进行前向或反向搜索，`n/N`跳转到下一个或上一个匹配，`*`或`#`进行当前单词前向和后向匹配

**复制**：`y`，`yy`复制一行，`y2w`复制2个单词，**剪切**：`x`，**粘贴**：`p`

**水平移动**：`0`移动到行首第一个字符，`$`移动到行尾

**垂直移动**：`()`句子间移动，`{}`段落间移动

**修改**：`r`替换一个字符，`s`替换并进入Insert模式，c搭配：`ct"`删除`""`内的内容

**行间搜索移动**：`f{char}`移动到char字符上，用`;`和`,`搜索**下一个**和**上一个**，`t{char}`移动到char前一个字符，`F{char}`反过来搜前面的char字符

**页面移动**：`gg/G`移动到文件开头/结尾，`H/M/L`跳转到屏幕开头/中间/结尾；`ctrl+u`, `ctrl+f`上下翻页；`zz`把屏幕置为中间

> 使用`ci`加上一个 `'` 或 `<` 或 `"` 或 `《` 都可以删除以此符号包含的文本并进行替换输入

**重复之前的操作**：`.`

**光标设置**

1. `m{a-z}` 文件内标记，文件内跳转，设置标记名为a到z中一个
2. `m{A-Z}` 标记文件，不同文件间跳转

**光标跳转**

1. ``{mark}` 跳转到标记位置
2. `'{mark}` 跳转到标记位置所在行的首字母

**文本对象操作**

```bash
[number]<command>[text object]
```

- number次数
- command命令，`d`删除，`c`替换，`y`复制
- text object文本对象，`w`单词，`s`句子，`p`段落

可以用`a`或`i`加上字符`(, <, {, [, ", ``等选择包括中的内容

```bash
# 删除100行后数据
100G
dG
```



### Command

**每行开头加{结尾加}**：`:%s/^/{/ | s/$/}/`

**显示行号**：`:set nu`

**全局替换**：`:% s/被替换单词/替换为的单词/g`

**替换命令**：`:[range]s[ubstitute]/{pattern}/{string}/[flags]`

- range：范围，`:10,20`表示10-20行，`%`表示全部
- pattern：要替换的模式，string替换后文本`/`为空
- flags：`g`全局，`c`确认（替换前会进行确认），`n`报告匹配到的次数而不替换

**回到上一个命令**：`: + Ctrl + P`

**显示当前文件名**：`:r! echo %`

**显示当前全局路径**：`:r! echo %:p`

```Bash
:%!xxd     # 查看文件十六进制编码
:%!xxd -r  # 返回/取消
```

**跳转到第n行**：`:n`

**删除**：`:1, xxd`删除1-xx行，`:xx, $d`删除xx到最后一行

**Buffer切换**

- `:ls`列举当前缓冲区

- `:b n`跳转到第n个缓冲区

- `:bpre` `:bnext` `:bfirst` `:blast` `:b buffer_name`来切换

- `:e file_name`打开新的文件进入缓冲区编辑

**Window切换**

左右分屏：`vs`或`ctrl + w + v`

上下分屏：`sp`或`ctrl + w + s`

切换窗口：`ctrl + w + w/h/j/k/l` 分别为 循环切换，左，下，上，右窗口

**标签页tab**

- `:tabe file_name`新标签页打开文件

- `ctrl + w + T`当前窗口移到新标签页

- `:tabc`关闭当前标签页及其中所有窗口

- `:tabo`只保留活动标签页

- `:tabn {N}`切到N标签页

- `:tabn`切到下一标签页

- `:tabp`切到上一标签页

### Visual

Normal模式按`v`进入，`V`选择行，`ctrl+v`选择方块

`viw`：选中当前单词，`vaw`：选中当前单词及后空格

**代码左右移**：`V & Shift + < >`

### Insert

**删除上一个字符**：`ctrl+h`

**删除上一个单词**：`ctrl+w`

**删除当前行光标前内容**：`ctrl+u`

**跳转到最后一次编辑的地方并进入Insert模式**：`gi`

**补全**：`ctrl + n` 和 `ctrl + p`补全单词，`ctrl + n`和`ctrl + p`上下移动选择

## Makefile

**格式**

`\`用于将一行分解为多行

```makefile
# COMMAND 命令生成TARGET, 其依赖于DEPENDEDS, DEPENDEDS改变, TARGET也重新生成, 后续依赖项也可作为TARGET规则嵌套
<TARGET ...>: <DEPENDEDS ...>
    COMMAND
```

**模式规则**

```makefile
<targets ...>: <target-pattern>: <prereq-patterns ...>
# targets: 目标文件
# target-pattern: 目标集模式，%匹配任意文件名
# prereq-patterns: 依赖集模式

$(OBJS):%.o:%.c # 通过命令将.c依赖均生成.o作为OBJS
```

**自动变量**

```Makefile
$+				# 所有依赖文件
$@				# 目标文件名
$<				# 第一个依赖文件名
$^				# 依赖项中所有不重复文件
$?				# 依赖中所有被修改过的文件
$*				# 目标文件名(不包含扩展名)
$(object)		# 使用object对应变量
```

```makefile
$(shell pwd)	# 获取相对路径
```

**预定义变量**

```makefile
CFLAGS	# 编译选项
OBJS	# 依赖文件
TARGET	# 目标文件
CC		# 编译器
RM		# 删除
DIRS	# 目录
```

**伪目标**

```Makefile
.PHONY: all clean # 伪目标, 强制执行
```

**清理**：使用`make clean`

```makefile
clean:
    @-rm $(DIR_TARGET)*
    # @:不回显命令; -:忽略错误, 中断执行; *:目录下所有文件
```

**函数**

```makefile
$(wildcard pattern)					# 返回满足pattern的文件列表
$(patsubst pattern, replacement, text)	# 将text字符串满足pattern的替换为replacement
$(foreach var, list, text)	# list中逐一取出到var, 执行text表达式
```

**运行**

```bash
make -j12 # 多线程执行不同构建任务
```



## GDB

调试代码，加入参数

```bash
gdb --args ./a.out xxx1 xxx2
```

**命令**

```bash
list 1 # 输出第1行开始的源代码
display xx # 每次运行输出xx的值
whatis variable # 查看变量类型
ptype variable # 查看变量类型结构
bt # 调用路径
```

## 分析

**寻找命令系统层源码**

- `https://command-not-found.com/`网址获取命令所在apt包名
- `https://packages.ubuntu.com/`或`https://www.gnu.org/software/`中下载包源码
- `apt source [package_name]`方法直接获取打过补丁的方法

## 操作

添加用户

```bash
sudo useradd -m xx
sudo usermod -aG root xx
sudo passwd xx
sudo usermod -aG sudo xx
chsh -s /bin/sh xx
```

## mac

**Brew 安装旧版本方法**

1. `formulae.brew.sh/`网址搜索`hugo`
2. 进入`Formula code: xxx.rb on GitHub`
3. 点击`History`找到对应版本，查看文件
4. 点击`Raw`获取该文件地址，`wget`下载下来
5. 安装

```bash
brew unlink hugo
brew install hugo.rb
```


