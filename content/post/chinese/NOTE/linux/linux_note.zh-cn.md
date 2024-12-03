---
title: "LINUX笔记"
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
    - 运维

typora-root-url: ..\..\..\..\..\static
---

## 一些命令

若不需要`-a`这些参数, 可以使用`--`

**数据处理**

```Bash
R --slave -e 'x <- scan(file="stdin", quiet=TRUE); summary(x)'
# --slave: 抑制消息、提示
# -e: 直接执行表达式
# 从标准输入到x, 并计算显示数据的汇总信息
gnuplot -p -e 'set boxwidth 0.5; plot "-" using 1:xtic(2) with boxes'
# -p: 保持图形打开
# -e: 直接执行命令
# 宽度0.5, "-"从标准输入读取数据
# using 1:xtic(2): 第1列-条形高度, 第2列-x轴刻度标签  boxes条形图
```

**性能分析**

```Bash
perf stat stress -c 1
# perf: 性能分析和调试工具
# stat: 收集显示性能统计信息
# stress: 负载生成工具
# -c: CPU负载核心数
perf report # 生成和查看性能数据的报告
# 精准测试命令执行时间工具
hyperfine --warmup 3 'fd -e jpg' 'find . -iname "*.jpg"' # 比较 fd 和 find
# --warmup 3: 预热执行三次后再测试
```

## 简单命令

**tree：**列举所有文件，类似于`ls -R`，递归列举文件

**tldr：**连接 `command` 可以列举使用该命令的用法

**journalctl：**查看和管理 systemd 的日志

**wc：**`wc -l`，统计文件行数

**sort：**排序，`sort-nk1,1`，`-n`为按数值大小排序，`-k1,1`排序键从第1列到第1列

**unique：**`unique -c`，统计相邻且相同的行出现的次数，`-c`在每行前加入次数

**paste：**`paste -sd,` 多行以逗号分隔合并为单行，`-s`串联，`-d`指定分隔符

**bc：**`bc -l`，计算器运算

**tee：**从标准输入读取数据，并将数据同时写入到一个或多个文件和标准输出

**jobs：**显示终端运行或挂起的后台作业

**nohup：**使得一个进程在用户登出或会话终止后仍然继续运行

**bg：**将已暂停的后台作业继续运行，`bg %1`指定 `jobs` 中序号

**alias：**命令别名，`alias ll="ls -lah"`及直接`alias command`查看命令别名意义

**htop：**进程查看器和系统监视器

**time：**获取命令执行的真实、用户、系统时间

**tac：**最后一行开始，逐行向上显示内容

**du：**显示目录及子目录磁盘使用情况，`du -h directory`，`-h`表示人类可读

**curl：** 可查看公网ip地址

**ps：**`ps -ef | grep xx`查找指定进程格式

**查看某个文件的绝对路径**： `pwd|awk '{print $1"/file_name"}'`

**查看版本**：`cat /proc/version`

**显示操作系统信息**：`uname -a`

**查看磁盘使用情况**：`du -sh`

## netstat

```Bash
 netstat -plant
 -p: --programs，与链接相关程序名和进程的PID
 -l: --listening，显示所有监听的端口
 -a: --all，显示所有链接和监听端口
 -n: 进制使用域名解析功能。链接以数字形式展示(IP地址)，而不是通过主机名或域名形式展示
 -t: 所有的 tcp 协议的端口
```

## find

```Bash
find . -name xxx -type d # d 表示 目录
find . -path '**/test/*.py' -type f # f 表示 文件

find . -name "*.tmp" -exec rm {} \;
# -exec rm {} \; 表示对每个找到的文件进行rm操作 
# {} 是一个占位符，表示当前找到的文件。find 命令会用找到的文件的完整路径替换 {}
# \; 表示 -exec 操作的结束, \ 是用来转义 ; 的， shell 中 ; 通常是一个命令分隔符
```

## locate

```Bash
locate filename
# 根据 mlocate.db 数据库查找
sudo updatedb
# 用于更新数据库
```

## lsof

列出当前系统打开文件，包括网络连接、设备

```Bash
lsof | grep ":4444 .LISTEN"
# 列出4444端口监听的进程
```

## ssh

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

`scp`是ssh的子命令

```Bash
# 远程文件传输
scp -i secret_key -r local_file user@x.x.x.x:remote_file_location # 本地到远程
scp -r user@x.x.x.x:remote_file local_destination # 远程到本地
```

`rsync`同样可以传输文件

```Bash
rsync -avP local_file user@x.x.x.x:destination # 本地到远程
# -a: 递归复制  -v: 显示详细信息  -P: 允许断点续传, 显示传输进度信息
```

## strace

```Bash
strace -e lstat ls -l > /dev/null
# 使用 strace 只跟踪 ls -l 命令中的 lstat 系统调用, 丢弃输出到/dev/null
```

## xargs

```Bash
echo "file1 file2 file3" | xargs rm
# 将标准输入中的数据转换为命令行参数，并将这些参数传递给指定的命令
```

## awk

```Bash
awk '{print $2}'
# 输出每行第 2 个字段, 默认将空格作为分隔符
awk '$1 == 1 && $2 ~ /^c.*e$/ {print $0}'
# 第 1 列为 1, 第 2 列满足以c开头以e结尾, $0 输出当前行
```

## grep

```Bash
xxx | grep 'xxxx' > ans.txt
ll -a | grep -E "1|2" # 用正则显示含1或含2的目录
```

## sed

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

**命令行命令**

```Bash
!!               # 直接替换为上一次使用的命令
Ctrl + R         # 回溯历史操作
readelf -S xxx   # 查看程序.bss段地址
cd -             # 返回到上一次工作目录
```

**匹配**

```Bash
xxx*     # *匹配任意
xxx?     # ?匹配一个字符
xx{1,2}  # 自动补充为xx1, xx2, 也可用多个{}做成笛卡尔积
xx{a..c} # 自动补全为xxa, xxb, xxc
```

## vim

`Vim file1 file2 -O`可打开两个文件

显示当前文件名：`:r! echo %`

显示当前全局路径：`:r! echo %:p`

```Bash
:%!xxd     # 可以用于查看c代码的十六进制编码
:%!xxd -r  # 返回/取消
```

**补全**

- `ctrl + n` 和 `ctrl + p`补全单词，`ctrl + n`和`ctrl + p`上下移动选择补全内容
- `ctrl +x ctrl + f`补全文件名
- `ctrl + x ctrl + o `补全代码，需使用`:filetype on`，查看`:set filetype + 回车`

**寄存器**

使用`"`指定寄存器，包括`a-z`，即`"bdd`删除当前行到寄存器b中

`:reg a`查看寄存器a内容

复制专用寄存器`"0`，系统剪贴板`"+`

**宏**

用于批处理，录制：`q{register}`开始录制到寄存器，`q`结束录制，回放：`@{register}`回放命令

在命令模式下：`:normal @a`全选文本内容后执行a寄存器中命令

### Normal模式

字符前插入：`i`；字符后插入：`a`；换行插入：`o`；行末插入：`A`；行首插入：`I`；行上另起一行插入：`O`

移动：`hjkl`左下上右，`w`移动到下一个单词开头，`b`回到上一个单词开头

行间搜索移动：`f{char}`移动到char字符上，用`;`和`,`搜索**下一个**和**上一个**，`t{char}`移动到char前一个字符，`F{char}`反过来搜前面的char字符

水平移动：`0`移动到行首第一个字符，`$`移动到行尾

垂直移动：`()`句子间移动，`{}`段落间移动

页面移动：`gg/G`移动到文件开头/结尾，`ctrl+o`快速返回，`H/M/L`跳转到屏幕开头/中间/结尾；`ctrl+u`, `ctrl+f`上下翻页；`zz`把屏幕置为中间

删除：`x`删除一个字符，`daw`删除一个单词，`d`和`x`可搭配数字执行多次：`3x` or `3daw`

修改：`r`替换一个字符，`s`替换并进入Insert模式，c搭配：`ct"`删除`""`内的内容

> 使用`ci`加上一个 `'` 或 `<` 或 `"` 或 `《` 都可以删除以此符号包含的文本并进行替换输入

查询：`/`或`?`进行前向或反向搜索，`n/N`跳转到下一个或上一个匹配，`*`或`#`进行当前单词前向和后向匹配

复制：`y`，`yy`复制一行，`yiw`复制一个单词，剪切：`x`，粘贴：`p`

`.`表示重复之前的操作

`ctrl+o`：回跳到原位

**光标设置**

1. `m{a-z}` 文件内标记，文件内跳转
2. `m{A-Z}` 标记文件，不同文件间跳转

**光标跳转**

1. ``{mark}` 跳转到标记位置
2. `'{mark}` 跳转到标记位置所在行的首字母

**文本对象操作**

```
[number]<command>[text object]
```

- number次数
- command命令，`d`删除，`c`替换，`y`复制
- text object文本对象，`w`单词，`s`句子，`p`段落

可以用`a`或`i`加上字符`(, <, {, [, ", ``等选择包括中的内容

### Command模式

查看文件二进制：`:%!xxd`

取消二进制显示——`:%!xxd -r`

显示行号：`:set nu`

全局替换：`:% s/被替换单词/替换为的单词/g`

替换命令：`:[range]s[ubstitute]/{pattern}/{string}/[flags]`

- range：范围，`:10,20`表示10-20行，`%`表示全部
- pattern：要替换的模式，string替换后文本`/`为空
- flags：`g`全局，`c`确认（替换前会进行确认），`n`报告匹配到的次数而不替换

`Ctrl + P`：回到上一个命令

**Buffer切换**

`:ls`列举当前缓冲区，`:b n`跳转到第n个缓冲区，`:bpre` `:bnext` `:bfirst` `:blast` `:b buffer_name`来切换，`:e file_name`打开新的文件进入缓冲区编辑

**Window切换**

左右分屏：`vs`或`ctrl + w + v`，上下分屏：`sp`或`ctrl + w + s`

切换窗口：`ctrl + w + w/h/j/k/l` 分别为 循环切换，左，下，上，右窗口

**标签页tab**

`:tabe file_name`新标签页打开文件，`ctrl + w + T`当前窗口移到新标签页，`:tabc`关闭当前标签页及其中所有窗口，`:tabo`只保留活动标签页

`:tabn {N}`切到N标签页，`:tabn`切到下一标签页，`:tabp`切到上一标签页

### Visual模式

Normal模式`v`进入，`V`选择行，`ctrl+v`选择方块

`viw`：选中当前单词，`vaw`：选中当前单词及后空格

1. 先按Esc 键，确认是在命令的状态下
2. 按V 键
3. 再按Shift + < ，这是将代码往左**移动**的；Shift + > 是将代码往右边**移动**的。

### Insert模式

`ctrl+h`删除上一个字符，`ctrl+w`删除上一个单词，`ctrl+u`删除当前行光标前内容

`ctrl+[`切换为Normal模式，`gi`快速跳转到最后一次编辑的地方并进入Insert模式

## 配置

bash的配置在`~/.bashrc`中

git的配置在`~/.gitconfig`中

vim的配置在`~/.vimrc`中

## 压缩

```bash
tar -zvcf a.tar.gz a # 压缩
tar -zvxf a.tar.gz  # 解压

zip -r a.zip ./* # 压缩
unzip -d /xxx a.zip # 解压
```

