# Python


## 环境

### pip

**手动安装包**

```bash
python3 setup.py install
```

**pip 安装**

```python
pip list #列出当前已安装的所有模块
pip install --upgrade xxx # 升级xxx模块
pip uninstall xxx # 卸载xxx模块
pip install xxx.whl # 使用whl文件直接安装xxx
```

## 基本操作

**查看版本**

```python
>>> sys.version
'3.10.2 (tags/v3.10.2:a58ebcc, Jan 17 2022, 14:12:15) [MSC v.1929 64 bit (AMD64)]'
>>> sys.version_info
sys.version_info(major=3, minor=10, micro=2, releaselevel='final', serial=0)
```

**帮助方法**

```python
import module
dir(module) # 查看模块中可用对象
dir(__builtins__)
help(module.func) # 查看使用方法
```

**globals()**：当前作用域内所有全局变量和值的字典

**locals()**：当前作用域内所有局部变量和值的字典

**变量名区分大小写**

```python
x = 3
y = x # 允许多个变量指向同一个值
z = 3
id(x) == id(y) == id(z) # True 123 123 123

x += 6 # 其中一个变量修改后，其内存地址变化，但不影响另一个变量
# 修改变量指向的内存地址，先取出x的值，加6，将结果存放于新的内存中，将x指向该新内存空间
id(x) == id(y) # False 135 123
```

**关键字：**

```python
>>> import keyword
>>> keyword.kwlist
['False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue', 'def', 'del', 'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if', 'import', 'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield']
```

**输出**

```python
print('xxx', file = fp, end = ' ') # 重定向到文件中, 输出内容不换行
```

### 函数方法

`id()`：返回对象的唯一标识符（内存地址），整数

`input()`：输入操作，`x = input("请输入：")`

`eval()`：将字符串作为表达式进行求值并返回结果，`eval(expression, globals=None, locals=None)`

`ord()`：对应字符的 ASCII 或者 Unicode 数值，`ord('a')`

`chr()`：当前整数对应的 ASCII 字符，`chr(0x30)`

`filter()`：返回序列中使函数值为 True 的元素

```python
res = filter(function or None, sequence)
print(list(res))
```

`reduce()`：对序列元素累积计算

```python
n = [1,2,3,4]
print(reduce(lambda a, b: a + b, nums)) # 10
```

`reversed()`：返回逆序后的列表或元组

`round()`：四舍五入，保留小数点后 2 位，`round(x, 2)`

### 方法例子

快速搭建一个 web 服务

```bash
python -m http.server 80
```

### 库

**math**

`math.sqrt()`：返回平方根

**datetime**

```python
Today = datetime.date.today() # 今天
Today.timetuple().tm_yday # 今天是今年的第几天
Today.replace(year=2023) # 替换日期中的年
now = datetime.datetime.now() # 现在
now + datetime.timedelta(days=5) # 5天后的日期时间
```

**random**

```python
x = [random.randint(0,100) for i in range(1000)] # 随机取1000个在(0,100)范围内的整型数
random.shuffle(xlist) # 打乱顺序
```

随机字符串

```python
import string
import random
x = string.ascii_letters + string.digits + string.punctuation
# 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
y = [random.choice(x) for i in range(1000)]
```

**collections**

计数

```python
# 使用defaultdict类
frequences = defaultdict(int)
for item in z:
	frequences[item] += 1
frequences.items()

# 使用Counter类
frequences = Counter(z)
frequences.items()
frequences.most_common(1)
```

## 类型

### 数字

**复数**

```python
x + yj # j表示虚部

a.real # 实部
a.imag # 虚部
a.conjugate() # 共轭复数
```

**进制**

- 十六进制：0x 开头
- 八进制：0o 开头
- 二进制：0b 开头

**浮点数**

```python
print(f"{x:.2f}") # x 小数点后2位
```

### 元组

元组（tuple）为不可变序列类型，一旦创建后其内容就不能被修改，元组访问处理速度比列表更快

```python
>>> t = (1, 2, 3)
>>> del t
# del删除元组本身而不是其中元素，del删除了变量t的引用，释放了元组占用的内存

>>> a = 3, # 单个元素时需要加入逗号
>>> a
(3,)

tuple() # 将序列转换为元组
```

### 矩阵

**矩阵转置**

```python
# 列表推导式
matrix = [[1,2,3,4],[5,6,7,8],[9,10,11,12]]
[[row[i] for row in matrix] for i in range(4)]
>>> [[1,5,9],[2,6,10],[3,7,11],[4,8,12]]

# zip, list实现
list(zip(*matrix))
```

### 字典

**创建**

```python
dict(zip(keys, values)) # keys和values都是列表
dict(key1=value1, key2=value2)
dict.fromkeys(['xx','xx','xx']) # 给定键，创建内容为None的字典
```

**获取指定键的值**

```python
dict.get(key, default=None)
# key:要查找的键
# default:如果指定键的值不存在，返回该默认值
```

**获取列表**

```python
dict.items() # "键-值对"列表
dict.keys() # 键列表
dict.values() # 值列表
```

```python
s = {'a':1, 'b':2, 'c':3}
d, e, f = s.items() # d: ('a', 1)
d, e, f = s # d: 'a'
d, e, f = s.values() # d: 1
```

**更新**

将字典 2 的键值对添加到当前字典对象，若存在相同键，以字典 2 值为准进行更新

```python
Dict1.update({'a':'a','b':'b'})
```

**有序字典**

```python
import collections
x = collections.OrderedDict()
```

### 列表

> - 删除列表元素时，自动对列表内存进行收缩，移动列表元素以保证所有元素之间没有空隙，元素索引都发生改变

**创建**

```python
list((1,2,3))
list(range(1,10,2))
list('xxx') # ['x','x','x']
```

**计数**

```python
list = ['a','b','c','a']
list.count('a') # 2
```

**切片**

```python
a[i:j:step] # 从下标i到j-1, 每step提取一个
```

- 切片返回的是列表元素的浅复制，其中一个改变另一个不改变

- 与列表对象的直接赋值不一样，直接赋值时两个列表指向同一块内存，其中一个改变另一个也改变

**添加**

```
list.append(x)
```

**删除**

```python
list.remove(x) # 删除首次出现的指定元素
del x[i]
```

**排序**

```python
alist.sort(key=None, reverse=False) # key: 用于排序的关键字 reverse=True为逆序
alist.sort(key=lambda x:len(str(x)) # 自定义排序
```

返回新列表，不对原列表进行修改

```python
sorted(persons, key=lambda x:(x['name'], -x['age'])) # 按姓名升序，年龄降序
from operator import itemgetter
sorted(phonebook.items(), key=itemgetter(1)) #按字典中元素值排序
```

**常用功能**

```python
list.extend(L) # 将列表L中所有元素添加到列表尾部
list.insert(index, x) # 在列表指定位置index处添加元素x
list.pop([index]) # 删除并返回列表对象指定位置的元素，默认为最后一个元素
list.clear() # 清空
list.index(x) # 返回第一个值为x的元素的下标
list.reverse() # 原地翻转
list.copy() # 返回列表对象的浅复制
```

使用`*`乘法创建的是已有对象的引用，一旦更改，相应引用也更改

```python
>>> x = [[None] * 2] * 3
>>> x
[[None, None], [None, None], [None, None]]
>>> x[0][0] = 5
>>> x
[[5, None], [5, None], [5, None]]
```

**成员资格判断**

```python
x in list # True or False
```

**列表推导式**

```python
new_list = [expression for item in iterable if condition]
# expression:计算新列表中的每个元素的值
# item:可迭代对象中的每一个元素
# iterable:可迭代对象
# condition:条件过滤列表中对象
```

```python
a = [1, 2, 3, 4, 5]
b = [x * x for x in a if x % 2 == 0]
print(b)   # 输出 [4, 16]
```

**列表转字典**

```python
a = ['a','b','c']
b = ['ab','bc','ca']
dict(zip(a,b)) # {'a': 'ab', 'b': 'bc', 'c': 'ca'}
```

**内置函数**

```python
cmp(序列1,序列2) # >返回1，<返回-1，=返回0

alist = [1,2,3]
blist = [4,5,6]
clist = zip(a, b)
list(clist) # [(1,4),(2,5),(3,6)]

for idx, value in enumerate(alist):
    print(idx, value)
```

### 集合

无序可变序列，同一集合的元素之间不允许重复

```python
a = {3,5}
a.add(7) 		# {3,5,7}
a.pop()  		# 3
a.remove(7) 	# {5}
a.clear()		# {}

a_set = set([1,2,3])
```

**运算**

```python
# 并集
a | b
a.union(b)
# 交集
a & b
a.intersection(b)
# 差集
a-b
a.difference(b)
# 对称差
a ^ b
a.symmetric_difference(b)
# 比较集合大小
a < b
#测试是否为子集
a.issubset(b)
```

### 字符串

- 字符串和元组属于不可变序列，不能通过下标方式修改其中元素值
- **短字符串**：长度 ≤20，内存中只有一个副本，共享副本

**判断函数**

```python
string.isalnum() # 至少有一个字符且所有字符都是字母或数字
string.isalpha() # 至少有一个字符且所有字符都是字母
string.isdecimal() # 只包含十进制数字(整数)
string.isdigit() # 只包含数字(整数)
string.islower() # 包含至少一个区分大小写的字符，都是小写
string.isupper() # 包含至少一个区分大小写的字符，都是大写
string.isnumeric() # 只包含数字组成，只针对unicode对象
string.lower()	 # 转换为小写
string.upper()	 # 转换为大写
string.cpitalize() # 字符串首字母大写
string.title()	 # 每个单词首字母大写
string.swapcase() # 大小写互换
string.isspace() # 只由空格组成
string.startswith("xxx") # 以什么开始
string.endswith("xxx") # 以什么结束

str = u"1234"
```

**格式化字符串**

```python
a = 3.6674
'%7.3f' %a # '  3.667' 保留小数点后三位，并在总共占据7个字符的位置上填充空格
"%d:%c" %(65, 65) # '65:A'
```

![image-20230531183959686](python.assets/image-20230531183959686.png)

**转义字符**

```python
\ddd	# 3位八进制对应的字符
\xhh	# 2位十六进制数对应的字符
```

**操作**

```python
s.find('xx')	# 查找'xx'在s中首次出现的位置
s.rfind('xx')	# 查找'xx'串在s中最后一次出现的位置
s.index('x')	# 'x'在s中首次出现的位置
s.rindex('x')	# 'x'在s中最后一次出现的位置
s.count('xx')	# 统计'xx'出现次数
s.replace('x', 'b') # 将x都转换为b
```

**填充**

```python
'Hello'.center(8,'=')	#=Hello==
'Hello'.ljust(8,'-')	#Hello---
'Hello'.rjust(8,'-')	#---Hello
```

**字符映射**

```python
table=''.maketrans('abc', 'uvw')
s="python is very good, haha"
s.translate(table)	#python is very good, huhu"
```

**分割**

```python
s.split(",") # 以 , 分割
s.split(",", 1) # 只分割一次
s.rsplit(",", 1) # 从右往左分割
```

分割为元组

```python
text.partition("-")
text.rpartition("-")
```

**连接**

```python
words = ["a", "b"]
"-".join(words)
```

**删除前后连续出现的指定字符**

```python
# 默认为空格
s.strip()
s.lstrip()
s.rstrip()
s.strip("x")
```

## 数据结构

### 堆

优先队列是堆结构的一个重要应用，堆是一个二叉树，每个父结点的值都小于或等于子节点的值

```python
import heapq
heap = []
for n in data:
	heapq.heappush(heap, n) # 建立堆
heapq.heappop(heap)	# 弹出最小元素,堆会自动重建
heapq.heapify(alist) # 将列表转化为堆
heapq.heapreplace(heap, n) # 弹出myheap的最小值，然后替换为n，加入n，重新构建堆
heapq.nlargest(3, heap)	# 返回前3个最大元素
heapq.nsmallest(3, heap)  # 返回前3个最小元素
```

### 队列

```python
import queue
q = queue.Queue()
a = queue.LifoQueue(5)	  # 后进先出队列
b = queue.PriorityQueue(5) # 优先级队列
a.put(xx)
```

## 基础语法

### 运算

**除**

`/` 和 `//` 分别表示除法和整除运算

**乘**

```python
[1,2,3]*2 # [1,2,3,1,2,3]
** # 幂运算
```

**矩阵相乘运算法@**

```python
>>> import numpy
>>> x = numpy.ones(3)
>>> x
array([1., 1., 1.])
>>> m = numpy.eye(3) * 3
>>> m
array([[3., 0., 0.],
       [0., 3., 0.],
       [0., 0., 3.]])
>>> x @ m
array([3., 3., 3.])
```

### 条件

```python
if xx:
	xx
elif xx:
	xx
else:
	xx
```

### 循环

```python
for var in iter:
	xxx

while xxx:
	xxx
```

### 函数

不定长参数，可以接受任意数量的参数

```python
def x(*v):
	...
x(1,2,3,4)
x(1,2)
```

**序列解包**

调用函数时，在实参前加上`*`，将序列中元素值依次传递给相同数量形参

```python
# * 序列解包
*range(4),4 # (0,1,2,3,4)
args = [1,2,3]
result = add(*args) # 等价于 add(1, 2, 3)

# ** 字典解包
{'x': 1, **{'y': 2}} # {'x': 1, 'y': 2}
```

### 异常处理

```python
try:
	xxx
except Exception as e:
	print(e)
    print(e.__traceback__.tb_frame.f_globals["__file__"])   # 发生异常所在的文件
    print(e.__traceback__.tb_lineno)                        # 发生异常所在的行数
```

### 条件表达式

```python
def Join(List, sep=None):
	return (sep or ',').join(List)
Join(['1','2','3']) # '1,2,3'
Join(['1','2','3'], ':') # '1:2:3'
```

### lambda 表达式

声明匿名函数

```python
f = lambda x,y,z: x+y+z
print(f(1,2,3)) # 6

L=[1,2,3,4,5]
print(map((lambda x:x+10), L)) # [11,12,13,14,15]
```

## 高级语法

### 正则表达式

| 模式           | 描述                                                           |                                                         |
| -------------- | -------------------------------------------------------------- | ------------------------------------------------------- |
| \b             | 匹配一个单词边界，指单词和空格间位置                           | er\b 匹配'nerer'中的 er<br>\bi\b 匹配'i am i h'中的 i   |
| \B             | 与\b 含义相反                                                  |                                                         |
| `\\b`          | 表示一个单词边界                                               | `r'\b'`和`'\\b'`表示一个匹配模式                        |
| \d             | 匹配任意数字                                                   |                                                         |
| \D             | 匹配任意非数字                                                 |                                                         |
| \              | 表示位于\之后的为转义字符                                      |                                                         |
| .              | 匹配除换行符以外任意单个字符                                   |                                                         |
| \w             | 匹配字母数字以及下划线                                         |                                                         |
| \W             | 匹配非字母数字以及下划线                                       |                                                         |
| (?! re)        | 前向否定界定符，当所含 re 表达式不在字符串当前位置匹配时成功   | `I(?!\w)` 表示 I 后面不是单词字符的位置                 |
| (?<!re)        |                                                                | `(?<!\w)I`表示 I 前面不是单词字符的位置                 |
| (?:re)         |                                                                | (?:[\w])I(?:[\w])匹配一个单词中间有一个 I               |
| re+            | 匹配 1 个或多个表达式                                          | (\w+)表示匹配一个或多个字母或数字字符，使用括号将其分组 |
| re\*           | 匹配 0 个或多个表达式                                          |                                                         |
| re{n, }        | 匹配 n 个前面表达式                                            | o{2,}匹配 2 个及以上的 o                                |
| \1...\9        | 匹配第 n 个分组的内容                                          |                                                         |
| \s             | 匹配任意空白字符，空格                                         |                                                         |
| \S             | 匹配任意非空字符                                               |                                                         |
| [...]          | 表示一组字符，单独列出                                         | [amk]匹配'a','m'或'k'                                   |
| [^...]         |                                                                | [^abc]匹配任意除'a','b','c'外的字符                     |
| [a-z]          | 匹配任何小写字母                                               |                                                         |
| [A-Z]          | 匹配任何大写字母                                               |                                                         |
| (pattern){m,n} | 允许模式重复 m~n 次                                            |                                                         |
| .+?            | 表示匹配一个或多个字符（除换行符外的任意字符），使用非贪婪模式 |                                                         |

**中文字符**

```python
[\u4e00-\u9fa5] # 从Unicode编码U+4E00到U+9FA5之间的所有字符
```

### 类和对象

- **可以用 del 显式删除对象**
- **`_xxx`** ：保护变量，不能用 `from module import *` 导入，只有类对象和子类对象能访问这些变量
- **`__xxx__`** ：系统定义的**特殊成员名字**
- **`__xxx`** ：**类中私有成员，只有类对象自己能访问**，子类对象不能访问到该成员，对象外部通过`对象名._类名__xxx`特殊方式访问

```python
#基类
class Person(object):
    def __init__(self, name=""):
        self.setName(name)

    def setName(self, name):
        if not isinstance(name, str):
            print("name must be string")
            return
        self.__name = name
#派生类
class Student(Person):
    def __init__(self, name=""major='Computer'):
        #调用基类构造方法初始化基类的私有数据成员
        super(Student, self).__init__(name)
        #super()函数是一个用于调用父类方法的特殊函数。
        #返回一个超类的代理对象，可以用来调用父类的方法，而无需显式指定父类的名称
        self.setMajor(major) #初始化派生类的数据成员
    def setMajor(self, major):
        if not isinstance(major, str):
            print("major must be a string")
            return
        self.__major = major
```

**定义三维向量加乘**

```python
class VectoR:
    def __init__(self, x=0, y=0, z=0):
        self.X = x
        self.Y = y
        self.Z = z
    def __add__(self, n):
        r = VectoR()
        r.X = self.X + n.X
        r.Y = self.Y + n.Y
        r.Z = self.Z + n.Z
        return r
    def __mul__(self, n):
        r = VectoR()
        r.X = self.X * n
        r.Y = self.Y * n
        r.Z = self.Z * n
        return r
```

**实例化**

```python
class X:
	xx
x = X()
```

**isinstatnce()**：测试一个对象是否为某个类的实例

```python
isinstance(x, X) # True
```

> 类方法

①**公有方法**

- 可以访问属于类和对象的成员，通过对象名直接调用，不能通过类名访问，通过类名调用实例方法需要为 self 显式传递对象名

②**私有方法**

- 以"\_\_"开始，可以访问属于类和对象的成员
- 不能通过对象名直接调用，只能在属于对象的方法中通过 self 调用

③**静态方法**

- 可以通过类名和对象名调用，不能直接访问属于对象的成员，只能访问属于类的成员

④**类方法**

- 可以通过类名和对象名调用，不能直接访问属于对象的成员，只能访问属于类的成员

### 爬虫

#### requests

```python
#发送请求
r = requests.get()
r = requests.post()

#传递参数
payload = {'a':'1','b':'2'}
params = payload

#响应内容
r.text
#二进制响应内容
r.content

#响应状态码
r.status_code
```

#### bs4

```python
# 解析内容
from bs4 import BeautifulSoup
soup = BeautifulSoup(html_doc)

#浏览内容
soup.title
soup.title.string

#正则使用
soup.find_all(name='x',attrs={'xx':re.compile('xxx')})
```

#### re

**re.match()**

```python
re.match(pattern, string, flags=0) # 返回一个匹配的对象，否则返回None
# pattern匹配的正则表达式
# string要匹配的字符串
# flags:标志位，用于是否区分大小写，多行匹配等
```

```python
re.match('www','wwwhh').span() # span返回元组(起始,结尾)=>(0,3)
re.match('')
```

```python
import re

line = "Cats are smarter than dogs"

matchObj = re.match( r'(.*) are (.*?) .*', line, re.M|re.I)

if matchObj:
   print "matchObj.group() : ", matchObj.group()
   # Cats are smarter than dogs
   print "matchObj.group(1) : ", matchObj.group(1)
   # Cats
   print "matchObj.group(2) : ", matchObj.group(2)
   # smarter
```

**re.search()**

```python
re.search(pattern, string, flag=0) #扫描整个字符串并返回第一个成功的匹配
```

- re.match 只匹配字符串的开始，若字符串开始不符合正则表达式，则匹配失败，函数返回 None

- re.search 匹配整个字符串，直到找到第一个匹配

**re.sub()**

```python
xxx = re.sub(pattern, repl, string, count=0, flags=0)
#repl:替换的字符串(可为函数),string:要被替换的原始字符串
#count模式匹配后替换的最大次数,默认0表示替换所有匹配
```

**re.compile()**

```python
pattern = re.compile(pattern[, flags]) #生成一个正则表达式对象
#re.I 忽略大小写
#re.L 表示特殊字符集 \w, \W, \b, \B, \s, \S 依赖于当前环境
#re.M 多行模式
#re.S 即为 . 并且包括换行符在内的任意字符（. 不包括换行符）
#re.U 表示特殊字符集 \w, \W, \b, \B, \d, \D, \s, \S 依赖于 Unicode 字符属性数据库
#re.X 为了增加可读性，忽略空格和 # 后面的注释
```

```python
pattern.match('xxx')
pattern.search('xxx')
pattern.findall(string[,pos[,endpos]])#匹配找到正则表达式所匹配的所有子串
```

**re.escape()**

```python
# 将字符串中所有特殊正则表达式字符转义
escape(string)
```

**子模式**

使用()表示一个子模式，圆括号内的内容作为一个整体出现，可以使用`group(n)`方法匹配第 n 个子模式

#### urllib

```python
urllib.request # 打开、读取url
urllib.error	# 包含抛出异常
urllib.parse	# 解析URL
urllib.robotparser # 解析robots.txt文件
urllib.request.urlopen() # 发起请求
urllib.request.urlretrieve() # 下载文件
urllib.request.Requests() # 定制请求头
```

### 生成器

- 包含**yield**语句的函数可以用来创建生成器
- 调用该函数不执行函数体，返回生成器对象
- 每次调用`next()`或`__next__()`时，从上次 `yield 处继续执行

```python
def f():
	a, b = 1, 1
	while True:
		yield a
		a, b = b, a+b

a = f()
for i in range(10):
	print(a.__next__(), end=' ')
	#1 1 2 3 5 8 13 21 34 55
```

**生成器表达式**

> 格式：`(expression for item in iterable if condition)`

```python
forbidden = "aeiou"
word = "hello"
res = any(char in forbidden for char in word) # True
```

any：遍历逐个取生成器表达式的值，若有单词中任何一个字母是属于禁止的都返回`true`

### AI

#### pyplot

```python
plt.hist(x) # 直方图
```

#### numpy

广播机制：shape 不相等时会复制调整使得运算通过

```python
np.array([[1, 2]])   # 1*2矩阵
np.array([[1], [2]]) # 2*1矩阵
# n 个中括号即 n 维矩阵

a = np.random.randn(5, 1) # 随机生成 5*1 矩阵

tensor_type.numpy() # array([[xx]], dtype=float32 将Tensor类型转换为np数组

np.matmul(a, b) # 矩阵乘法 或 a @ b
np.exp(V) # V中每个元素i: 求e^i
np.log(V)
np.abs(V) # 绝对值
np.maximum(V, 0)
np.sum(A)
A.sum(axis=0) # 垂直方向求和 axis=1 水平求和
AT = A.T # 矩阵转置
# [2, ] [2, 1] 区别
[1 2] # 秩为1的数组
[[1]
 [2]] # 2*1的矩阵

[::3, ::2] # 每 3 行一跳，每 2 列一跳
```

#### pytorch

```python
# 使用 conda 安装 GPU 支持的 torch
conda install cuda -c nvidia/label/cuda-12.4.0
nvcc -V # 验证
conda install pytorch torchvision torchaudio pytorch-cuda=12.4 -c pytorch -c nvidia
```

#### Conda

```python
conda create -n test python=x.x.x
source activate base
conda activate test
```

#### TensorFlow

使用TensorFlow构建神经网络模式

```Python
model = Sequential([Dense(units = 153, activation = 'sigmoid'), # 全连接层 layer1
                    Dense(units = 21, activation = 'sigmoid')]) # layer2
# activation: linear, relu, sigmoid, softmax

x = np.array([[xx, xx], [xx, xx]])
y = np.array([xx, xx])

model.compile(loss=BinaryCrossentropy()) # 损失函数
# BinaryCrossentropy 适用于二元分类0或1: 逻辑回归 二元交叉熵函数
# MeanSquaredError 适用于回归: 预测数值 
# SparseCategoricalCrossentropy  适用于SoftMax多分类 稀疏范畴交叉熵函数 得到N个值中的一个值

model.fit(x, y, epochs=100) # fit:实现反向传播  epochs: 梯度下降/迭代次数

model.predict(x_new)
```

SoftMax / Sigmoid中：

```Python
# 前面的Dense最后一层activation使用'linear'输出中间值
model.compile(loss=SparseCategoricalCrossentropy(from_logits=True))
# 损失值不标准化为概率, 使得数字更准确, SoftMax操作交给TensorFlow的损失函数计算

# 预测
logits = model(X) # SoftMax输出z1-zN, 即非概率   Sigmoid输出z, 非概率
f_x = tf.nn.softmax(logits) # tf.nn.sigmoid(logits) 将中间值单独调用函数转为概率
```


