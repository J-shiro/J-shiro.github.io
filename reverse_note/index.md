# REVERSE


## 基础知识

除了逆向外也可以尝试**爆破**

```c
#include <stdio.h>
int main(){
    int cipher;
    for(int i=0;i<0xffffffff;i++){
        cipher = i;
        //加密异或等操作
    }
    if (cipher==20241212153){
        printf("flag1:%x\n",i);
    }
}
```



### Windows

`kernel32.dll`：控制系统内存管理、数据输入输出、中断处理，当Windows启动时，其驻留在内存中特定的写保护区域，使别的程序无法占用该内存区域

`user32.dll`：用户界面相关应用程序接口，包括Windows处理、基本用户界面

`gdi32.dll`：Windows GDI图形用户界面相关程序，绘制图形、显示文字

句柄（handle）：唯一整数值，标志程序中不同对象和同类对象中的不同实例

#### 反编译

- **线性扫描(Linear Sweep)**：简单顺序扫描文件分析，均分析为代码，objdump, OllyDbg, x64dbg
- **递归下降(Recursive Traversal)**：控制流根据call指令调用关系分析，IDA pro

#### 约定

变数名称**前缀表示类型**

- **`lp`**：Loing Pointer
- **`h`**：Handler
- **`dw`**：DWORD

函数名称后可能有**大写字母**

- **`A`**：字符串参数使用ANSI
- **`W`**：字符串参数使用UNICODE（Wide character）
- **`EX`**：扩展（Extended）

**调用约定**

- x86 32位
  - `__cdecl`：参数从右向左依次压入栈，调用完毕后，调用者caller负责清理参数，返回值位于EAX
  - `__stdcall`：（Win32 API）参数从右向左压入栈，调用完毕后，被调用者负责清理参数，返回值位于EAX
  - `__thiscall`：参数从右向左压入栈，类方法的`this`指针通过ECX传递给被调用者，若参数个数确定，则参数全部压入栈后`this`指针入堆栈；若参数个数不确定，调用者清理堆栈
  - `__fastcall`：函数第一个和第二个DWORD参数通过ECX和EDX传递，其他参数从右向左压入栈，被调用函数清理堆栈
- 清理栈帧指参数使用了栈则栈帧会发生变化，需要使用`add rsp, 0x??`来清理，push x次，32位下add x*0x4，64位下add x*0x8
- x86-64
  - **Microsoft x64**：前四个参数放入RDI、RSI、RDX、RCX，（Windows下前四个参数让RCX、RDX、r8、r9）剩下参数从右到左压入栈，调用者caller负责清理堆栈
  - **SystemV x64(SysV)**：Linux与MacOS上使用，比Microsoft多两个寄存器，使用RDI、RSI、RDX、RCX、R8、R9，剩下参数从右向左压入栈中，调用者caller负责清理堆栈
- **局部变量**：放于栈上

#### **Eflags**

- ZF（Zero Flag）：零标志
- PF（Parity Flag）：奇偶标志
- AF（Adjust Flag）：辅助标志
- OF（Overflow Flag）：溢出标志
- SF（Sign Flag）：符号标志
- DF（Direction Flag）：方向标志
- TF（Trap Flag）：追踪标志
- IF（Interrupt enable Flag）：中断允许标志

#### Syscall

Windows 的 syscall number 随版本更新会变更，一般呼叫**API**

#### SEH机制

**Structured Exception Handling**，结构化异常处理

- VC++及Windows的异常处理机制，可利用`/0`等方式触发异常

- 以链的形式存在，第一个异常处理器中若未处理相关异常，异常会传递到下个异常处理器直到得到处理

- ```C++
  typedef struct _EXCEPTION_REGISTRATION_RECORD
  {
      PEXCEPTION_REGISTRATION_RECORD Next; // Next值为FFFFFFFF表示最后一个节点
      PEXCEPTION_DISPOSITION Handler; // 当前异常处理回调函数的地址
  } EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;
  ```

<img src="/img/reverse_note.zh-cn.assets/image-20241022224820682.png" alt="图片无法加载" />**线程信息块TIB**（Thread Information Block or TEB）

```C++
typedef struct _NT_TIB {
     struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList; //异常的链表

     PVOID StackBase;
     PVOID StackLimit;
     PVOID SubSystemTib;

     union {
         PVOID FiberData;
         DWORD Version;
     };
 
     PVOID ArbitraryUserPointer;
     struct _NT_TIB *Self;
} NT_TIB;
```

**调用**

```c++
// Visual C++
__try{compound-statement} __except(filter-expression){compound-statement}
__try{compound-statement} __finally{compound-statement}
```



### Linux

```Bash
file <somefile> # 查看文件类型

strings <something> # 打印文件中可见字符串
strings -n <min-len> <something> # 打印最短长度为min-len的可见字符串
strings <something> | grep "xx"

objdump -M intel -d <binary> # intel格式展示反汇编结果

strace # 查看 binary 执行时的 system call 和 signal
ltrace # 查看 binary 执行时的 library call
```

**可执行程序报错**：linux版本可能不匹配，尝试高版本打开

```bash
./a.elf: /lib/x86_64-linux-gnu/libstdc++.so.6: version `GLIBCXX_3.4.32' not found (required by ./a.elf)
```



### 数学

**乘法逆元**： $a\cdot a^{-1}\equiv 1(mod\quad p)$

```Python
# 求 a 乘法逆元
from gmpy2 import invert
inv = invert(a,p)
```

逆向下面公式

```C
// a1[k] 有限域 (0x00 ~ 0xff) 即 0 ~ 255 加密
for(int j = 0; j < 12; ++j)
    a1[j] = a1[j] * 17 + 113;
    
// 整除 17 会损失数据, 不可 /17
// 逆向解密 求 17 在 mod 256 的乘法逆元: 241
for(int j = 0; j < 12; ++j)
    a1[j] = (a1[j] - 113) * 241
```

### 计算机组成

VA：虚拟地址

RVA：（Relative Virtual Address）相对虚拟地址，相对于镜像基址的位置，即VA = ImageBase + RVA

- Entry Point RVA - .text section RVA = Entry Point file offset - .text section file offset

1. 八个比特（bit）称为一个字节（byte）
2. 两个字节称为一个字（word）——16bits
3. 两个字称为一个双字（dword）——32bits
4. 两个双字称为一个四字（qword）——64bits

**位运算**

```C
// 基础 优先级 not > and > or > xor
or |  // 00=0 01=1 10=1 11=1
xor ^ // 00=0 01=1 10=1 11=0   a^a=0 0^a=a a^b^a=b
and & // 00=0 01=0 10=0 11=1 自己与自己相与得自己
nor   // 与or相反
nand  // 与and相反
not   // 0=1 1=0

// 位与
x & 1 // 若为0:偶数, 若为1:奇数

// 负数计算 (-25 & 0xff) 转换
```

**移位**

```C
<< n  <===>  乘2^n

v1 = v2 | (v3 << 16) // v3左移16位成为高16位
// v1 = 0xaabbccdd 则 v3 = 0xaabb, v2 = 0xccdd
```

**数据类型大小**

- short：2字节
- char：1字节
- int：4字节
- double：8字节
- long：8字节

**python中将负数表示为无符号32位或64位整数**

```Python
unsigned_value = (negative_value + (1 << 64)) & 0xFFFFFFFFFFFFFFFF # 转化为64位
```

### 汇编

```Assembly
jc    ;CF==1执行
jo    ;OF==1执行
jz    ;ZF==1执行
```

`nop`为0x90

```assembly
movzx ; 将源操作数值复制到目标寄存器后将高位清零得到32位

xor edx, eax; 结果存在edx中
```

x86-64架构的SIMD寄存器，处理单指令多数据操作：`xmm0`-`xmm15`可以存储128位数据，IDA中显示不了`xmm`寄存器值

```assembly
movaps xmm0, ds:xmmword_XXXX ; 将该地址128位数据移到xmm0中, xmm0中存4个32位整数

# xmmword_XXXXX xmmword 3000000020000000100000000h
# xmm0: [0x1, 0x2, 0x3, 0x4]
```

```assembly
movd xmm0, ecx ; 将ecx 32位整数移到xmm0中, 其余96位填充为0
pshufd xmm1, xmm0, 0 ; 从xmm0取第0个元素复制到xmm1中，其余填充为0
```

```assembly
# xmm1 = [0x00, 0x01, 0x02, 0x03]
# xmm0 = [0x15151515, 0x0, 0x0, 0x0, 0x0]

padd xmm1, xmm0 ; 相加 
; [0x00+0x15, 0x01+0x15, 0x02+0x15, 0x03+0x15]
andps xmm1, xmm0 ; 按位与
; [0x00&0x15, 0x01&0x15, 0x02&0x15, 0x03&0x15]
xorps xmm1, xmm2 ; 按位异或
; [0x00^0x15, 0x01^0x15, 0x02^0x15, 0x03^0x15]
```

```assembly
packuswd xmm1, xmm1 ; 16位无符号整数打包到一个8位无符号整数
# xmm1 = [0x0000ffff, 0x00010001, 0x00020002, 0x00030003]
# xmm1 = [0xffff, 0x0001, 0x0002, 0x0003]
```

**Intel**

```Assembly
mov rax, 0x80
xor rbx, rcx
mov rax, QWORD PTR [rbx+rcx*4]
```

**AT&T**

```Assembly
mov $0x80, %rax
xor %rcx, %rbx
mov (%rbx, %rcx, 4), %rax
```

**struct**

<img src="/img/reverse_note.zh-cn.assets/172845173251511.png" alt="图片无法加载" />

1. 分配 0x18 bytes 内存空间，内存空间起始位置存在 rbp-0x8
2. 将 rbp-0x8 的值存于 rax，即 rax 是 ms 的基址
3. ms->a 的偏移为 0x0，ms->b的偏移为 0x8，ms->c 的偏移为 0x10
4. 1+8+4 = 13 bytes 实际用了 24 bytes

### C

```C
strncmp(const char *str1, const char *str2, size_t n)
// 比对str1和str2开头n个字符

strcpy(char *dest, const char *src)
// 将src复制到dest

memcpy(dest_addr, src_addr, bytes_num)
// 从 src_addr 拷贝 bytes_num 个字节数据到 dest_addr

memset(arr, 0, sizeof(arr));
// 将 arr 指针指向的内存块的sizeof(arr)所有字节指定为0

scanf("%s", buf); // 存在溢出操作, 假设输入15个字节, 会自动将第16个字节设为\0
scanf("%15s", buf); // 指定输入字节

fgets(x, 32, stdin); // IDA中可能将x数组分为多个变量，实际可能均为x, 但代码显示的x实际为x[0]
```

**文件操作**

```C
fseek(FILE *stream, long int offset, int whence)// 设置流的文件位置为给定的偏移
// 文件流, 偏移, 添加偏移量的位置(0:开头, 1:指针位置, 2:结尾)

fputc(int char, FILE *stream) // 将char指定的字符写入指定的流指针处
fprintf(ILE *stream, const char *format, ...) // 格式化字符串输出到流

a = _acrt_iob_func(1i64) // 将标准输出流stdout的文件指针给a，可通过a向标准输出流写数据

fgets(char *str, int n, FILE *stream);
// 从文件流读入 n-1 个字符到 str, 第 n 个为\0
```

**宏**

```C
LODWORD(v4) = 0    //初始化低32位为0
HIDWORD(v4) = 0    //初始化高32位为0
SHIDWORD(v4)       //取高32位并作为有符号整数
```

数据类型：`LL`即`long long int`

**其他**

```C
setlocale(int category, const char *locale); //设置或读取位置相关信息
```

**格式化字符串**

```C
printf("%x", a); // 十六进制
```

**C逆向代码**

```C
char password_enc[] = {0x49, 0x4B};
char password[47];
for (int i = 0; i < 46; i++){
    password[i] = password_enc[i] ^ 0x24;
}
password[46] = 0;         // 使用0字符来截断掉%s的无尽输出
printf("%s\n", password);
```

**格式转换相关**

```C
char Str[48]; // 假设已输入
//  strlen(const char *Str) [Str是指向数组第一个字符的指针]
if ( strlen(Str) == 12 ){} // 12是指12字节, 即Str: 'abcdefghijkl'
process(Src); // void process(unsigned int *a1)
// 此时Str将被解析为无符号整数 > 32位即4字节, 所以此时进入process后
// 'abcd'->0x61,0x62,0x63,0x64->小端存储 ->0x64636261
// a[] 3个整数: [0x64636261, 0x68676665, 0x6c6b6a69]
// 假设操作后 0x64636261 变为 0x68676665, 该值传回a[0]时, a[0]换为char时表示'efgh' 
```

### C++

`0xCC` 是一种填充字节，通常用于调试表示**未初始化**的内存区域

Name Mangling：附加修饰函数名，用于辨识参数不同的同名函数

命令行使用`c++filt <name>`来获取原始的函数名

或gdb上使用`set print asm-demangle on`

**IDA相关**

```C++
__do_global_ctors() // 编译器生成, 初始化全局和静态对象

a = 20i64 // a = 20 且 i64 指定为带符号的64位整数

std::ostream::operator<<(v1); // 输出
```

**Windows API**

```C
DWORD GetCurrentThreadId(void); // 获取当前线程的标识符
```

### 可执行文件

#### PE文件

PE文件（Portable Executable）：32位【PE32】，64位【PE+或PE32+】

- 可执行：`exe, scr`
- 库：`dll, ocx, cpl, drv`
- 驱动程序：`sys, vxd`
- 对象文件：`obj`

<img src="/img/reverse_note.zh-cn.assets/17284517325131.png" alt="图片无法加载" />

**DOS头**

<img src="/img/reverse_note.zh-cn.assets/17284517325142.png" alt="图片无法加载" />

**DOS存根**

向下兼容，用DOSBox执行PE会输出红色框中字符串

<img src="/img/reverse_note.zh-cn.assets/17284517325143.png" alt="图片无法加载" />

**NT头**

<img src="/img/reverse_note.zh-cn.assets/17284517325144.png" alt="图片无法加载" />

**映射**

<img src="/img/reverse_note.zh-cn.assets/17284517325145.png" alt="图片无法加载" />

**节Sections**

- `.text`：代码段
- `.idata`：放 import tables
- `.data`：初始化数据
- `.bss`：未初始化数据
- `.reloc`：relocation 信息
- `.rsrc`：资源数据
- `.rdata`：只读数据
- `.tls`：Thread Local Storage，线程局部存储数据

##### IAT

(Import Address Table)，存储在 `.idata section` 内的表

- 程序载入前相当于`INT`，指向 `IMAGE_IMPORT_BY_NAME`
- 程序载入后存储外部引入函数的位置

<img src="/img/reverse_note.zh-cn.assets/17284517325146.png" alt="图片无法加载" />

##### EAT

(Export Address Table)

<img src="/img/reverse_note.zh-cn.assets/17284517325147.png" alt="图片无法加载" />

**应用EAT来做GetProcAddress**

1. 从 module image base 取得指定 API address
2. 从optional header 的 DataDirectory[0] 取得EAT
3. 遍历AddressOfNames，寻找指定API名称
4. 透过AddressOfNameOrdinals得到ordinal
5. 从AddressOfFunctions得到API RVA，避免直接呼叫GetProcAddress

##### PEB

（Process Environment Block）

<img src="/img/reverse_note.zh-cn.assets/17284517325148.png" alt="图片无法加载" />

**PEB断链：将特定的module隐藏（x86-64）**

1. 从 gs:[0x60] 取得 PEB
2. 从 PEB 取得 Ldr
3. 通过 Ldr 内的 InLoadOrderModuleList 遍历所有  LDR_DATA_TABLE_ENTRY 结构
4. 找到指定的 LDR_DATA_TABLE_ENTRY 后，将其从三个 linked list 中删除

**应用PEB来做GetModuleHandle**

1. 取得特定的 module image base(x86-64)
2. 从 gs:[0x60] 取得 PEB
3. 从 PEB 取得 Ldr
4. 通过 Ldr 内的 InLoadOrderModuleList 遍历所有  LDR_DATA_TABLE_ENTRY 结构
5. 比对 BaseDllName 得到 DllBase，避免直接呼叫 GetModuleHandle

##### DLL

- （Dynamic Link Library）导出函数给程序使用
- DLL的main为**DllMain**，载入、卸载时会执行

```C++
BOOL WINAPI DllMain(
//BOOL: 返回类型        WINAPI: 调用约定
    HINSTANCE hinstDLL,  // 指向加载 DLL 的实例的句柄的类型
    DWORD fdwReason,     // 调用函数原因
    LPVOID lpvReserved )  // 保留
{
    switch( fdwReason ) 
    {
        case DLL_PROCESS_ATTACH: 
            break;// 进程附加事件,当进程加载这个DLL时执行一次性初始化操作

        case DLL_THREAD_ATTACH:
            break;// 线程附加事件,线程从操作系统创建并且该DLL已加载时执行初始化操作

        case DLL_THREAD_DETACH:
            break;// 线程分离事件

        case DLL_PROCESS_DETACH:
            if (lpvReserved != nullptr)
            {
                break;// 进程未终止，不执行清理
            }
            break;// 清理工作
    }
    return TRUE;  // DLL_PROCESS_ATTACH成功
}
```

EXE文件在终端运行，不要直接双击

#### **ELF**文件

```Bash
readelf -S program # 查看elf文件的section
readelf -a xxx     # 全部显示
```

**节**：

- .text节：程序代码指令
- .rodata节：保存只读数据，只能在text段找到.rodata节
- .plt节：过程链接表(Procedure Linkage Table)，包含动态连接器调用从共享库导入的函数所需的代码
- .data节：存在于data段中，保存了初始化的全局变量数据
- .bss节：存于data段中，保存未进行初始化的全局数据，初始化为0，程序执行可进行赋值
- .got.plt节：全局偏移表-过程链接表，.got节保存全局偏移表，.got和.plt节一起提供了对导入的共享库函数的访问入口，由动态连接器在运行时进行修改
- .dynstr节：动态链接字符串表，存放了一系列字符串，空字符作为终止符

**断点**

- 软件断点：`int 3`|`0xcc` 执行触发程序异常：`breakpoint_`，或产生其他异常如`0xce`
- 硬件断点：调试寄存器DR0~DR3设定地址，用DR7设定状态，最多4个
  - 读/写/执行某精准地址产生异常
- 内存断点：设置地址不可访问/写属性，读/写/执行该内存时产生异常，调试器判断并接管异常
  - 改变某分页属性，与`VirtualProtect`函数有关
  - 以一整个分页为单位的断点
- 条件断点：满足特定条件，暂停执行

### 大小端序

字符存储为小端序，所以编写脚本计算时需要将其**倒序**

栈上是小端序存储的

### Python

```Python
import itertools

choices = ["1", "2"]
combinations = list(itertools.product(choices, repeat=7))
# 7位, 每一位可以为 choices 中的任何一个, 生成所有可能值

[f"{num:02x}" for num in int_array] # 整型数组以十六进制输出, 不足用0补足
```

- `ord()`: **字符** 转换为对应的 **ASCII 码值**
- `chr()`: **ASCII 码值** 转换为对应的 **字符**

**转换**

可以尝试用CyberChef转换，output中的**魔法棒**

```Python
binary_data = bytes.fromhex(content)
# 字节字符串 "0x89" "0x50" 转换为真字节 b'\x89' b'P'

hex_data = binary_data.hex() 
# 真字节b'\x89' 转换为字符串"89", 有时需要binary[::-1]

hex_type = hex(int(binary_data.hex(), 16))
# 真字节b'\x89' 转换为十六进制字符串'0x89'

val = val.rstrip('h')
hex_value = int(val, 16) # 十六进制字符 "0xabc" 直接转整型 2748
binary_value = format(hex_value, '08b')
# 十六进制字符串 "FFh" "D8h" 转换为对应的8位二进制数 '11111111' '11011000'

byte_val = char_val.encode() # 字符串'2024' 转换为字节 b'2024'
```

**数据处理**

```Python
data = '''xjowefg, feiwow
    ewioa,  efils , fefe # 杂乱的数据'''

# 清理逗号等
hex_values = [val.strip() for val in data.replace('\n', ',').split(',')]

# 每行输出10个
for i in range(0, len(hex_values), 10):
    print(', '.join(hex_values[i:i+10]))
```

**类**

```python
class A:
    def __str__(self):
    # __xx__魔术内置方法，一般python解释器自动调用
        return str(self)
    # 静态方法: 用于创建类的实例，分配内存创建对象
    def __new__(cls, *args, **kwargs):
        return super(A, cls).__new__(cls, *args, **kwargs)
    
    @property # 方法转换为同名的只读属性 instance.aaa来访问
    def aaa(self):
        return self.aaa

A1 = package.A()
```

**map**

```python
map(function, iterable) # 对iterable中的每个元素应用function
```

**pip**

安装指定版本的包会将原先的包给卸载，代替为指定版本

**进程subprocess**

```python
import ctypes
def start_suspended_process(proc_name): # 启动并挂起进程
    creation_flags = 0x14
    # CREATE_SUSPENDED=0x4: 子进程创建立即挂起
    # CREATE_NEW_CONSOLE=0x10: 创建新的控制台窗口
    process = subprocess.Popen(proc_name, creationflags=creation_flags)
    print("子进程已启动并挂起")
    return process.pid

def resume_process(pid): # 恢复进程
    try:
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.DebugActiveProcess(pid)
        print(f"进程 {pid} 已恢复.")
    except OSError as e:
        print(f"恢复进程时发生错误: {str(e)}")
```



### JAVA

```Bash
java -jar xx.jar # 运行java文件
```

**类型**

`Byte`: java.lang中一个类，封装byte

`byte`: 基本数据类型，整型数据1字节

**格式**

```Java
public class Main {
  public static void main(String[] args) {
      xx;
  }
}
```

**输入输出**

```Java
// 输出
System.out.println("hello"); 

// 输入
Scanner scanner = new Scanner(System.in);
String flag = scanner.next(); // 输入一行
```

**数据转换**

```Java
// 字符串 转换为 UTF-8字节
String s = "hello";
byte[] by = s.getBytes(StandardCharsets.UTF_8); // by[i]输出为第i+1个字符的ASCII码值

// byte 转换为 Byte
Byte byte_ = Byte.valueOf(by[0]); 
byte_.byteValue() // 取值
```

**异常**

```Java
Exception[] exceptions = { 
    (Exception)new BuDaoLePaoException(), 
    (Exception)new DxIsNanTongException()
};
try {
    xxx
} catch (BuDaoLePaoException ex0) {
    xxx
} catch (DxIsNanTongException ex1){
    xxx
} catch (Exception e) {
    throw new RuntimeException(e);
} 
```

### 寄存器

x86中寄存器：EBP、ESP、EIP、EAX、EBX、ECX、EDX、EDI、ESI

x86-64中寄存器：RBP、RSP、RIP、RAX、RBX、RCX、RDX、RDI、RSI、R8~R15

## 工具

### PE-bear

### 010Editor

### GDB

**查看格式**

```
x/nfu <addr>
x: examine
n: 个数
f:显示方式
    x:十六进制 d:十进制 u:十进制无符号 o:八进制 t:二进制
    a:十六进制 i:地址格式 c:字符格式 f:浮点数
u:地址单元长度
    b:单字节 h:双字节 w:四字节 g:八字节
```

针对汇编`cmp eax, DWORD PTR [rbp-0x94]`查看地址中内容

```Bash
b *xxx # 通过objdump确定设置断点的地址
x/wx $rbp-0x94 # gdb中查看内容
x/sw $eax # eax中内容以字符串形式显示
```

命令

```Bash
disassemble func # 查看函数反汇编

info registers # 查看寄存器地址
```

### IDA

**取IDA数据时，小端序取，4个4个倒过来取**

函数窗口：`ctrl+F`搜索函数

导入函数窗口：`Imports`窗口，导入的一些函数

添加反汇编注释：`option > general > Display disassembly line parts > Auto comments`

反汇编窗口字体调整：`option > font`

十六进制窗口编辑：`F2`，`F2`保存

函数窗口中`shift+F5`打开应用库模块列表，继续按`insert`键打开可用库模块列表，进行导入

使用`d`可以将数据改变大小从byte转换为2bytes-word，4bytes-dword，8bytes-qword

或者右键设置`Array`，改变数组显示

`undefine`可以将识别错误的代码取消，然后右键将字节转换为相应类型

清除指针类型用于重新定义结构体：右键 > `Reset pointer type`

`db, dw, dd, dq `分别代表 **1, 2, 4, 8** 字节

一般直接 `shift + F12` 找字符串窗口，对应字符位置`ctrl + x` 找到函数

```
db 2 dup(14h)`表示 define byte定义字节，2个`14h
```

查看机器码：`Options `> `General `> `opcode`

**应用**：

**变量为64位，8字节，则在栈中需要8字节空间**

```C
int v1[] = {2, 0, 2, 4};
func((__int64)v1); // 表示将v1的地址转为64位整数
*(_DWORD *)(v1 + v2) + v3; // v1数组偏移v2的地址处取一个32位整数(dword)值 与v3相加

*(_QWORD *)List // 读取 List 的前 64 位数据
(_DWORD)v4 // 取低32位

(result >> 32) & 0xFFFFFFFF  // 取高32位
(result)       & 0xFFFFFFFF  // 取低32位

unsigned int v4;
__int64 a1;
*(_DWORD *)(a1 + 4i64 * (v4 & 3));
// v4 & 3(11) 即取低两位, 确保为 0,1,2,3, a1表示某内存区域首地址
// 4i64为一个4字节, 作为a1偏移的单位, 即a1偏移0|1|2|3个4字节的位置取一个DWORD32位

__halt(); // 暂停处理器
unsigned _int8 // 无符号8位整型
int // 32位整型
.data:0000000140022000 array  db 0A3h, 69h, 96h, 26h, 0BDh, 78h, 0Bh, 3Dh, 9Dh, 0A5h
.data:0000000140022000                                  ; DATA XREF: main_0+202↑o
.data:000000014002200A        db 28h, 62h, 34h dup(0)

// 此处存储一般为 0x269669a3, 0x3d0b780b, 0x6228a59d
```

**插件**：

`Ctrl + 3`：呼出插件

- **Findcrypt**：IDA9中成功，IDA7.5, 7.7, 8.3中都不显示

  - `edit` > `Plugins` > `Findcrypt`：可以找到`MD5, DES, CRC`等

- **E-Decompiler**：IDA7.5，对易语言进行分析插件

  - `ida.cfg`文件解除`Block_CJK_Unified_Ideographs`前的注释

  - `ida.dll`文件用IDA64打开，搜索`[](),`，将有下划线一行nop掉

  - ```c
    if ( !v8 || !strchr(" [](),*&", v11) )
          {
            if ( v10 - v9 < 8 || strncmp(v10 - 8, "operator", 8ui64) )
            {
    LABEL_23:
              *v10 = '_'; // nop!
    ```

  - 装入插件可显示中文函数及易语言反编译

- **Scyllahide**：反反调试工具，IDA7.5，注意要明确调试代码是**32**位还是**64**位！！

  - 反调试报错：`XXXXXXXX:unknown exception code 0 (exc.code 0, tid XXXXX)`
  - 64位调试32位程序使用Scyllahide后会报错
  - 设置扩展参数

  <img src="/img/reverse_note.zh-cn.assets/image-20241022105920446.png" alt="图片无法加载" />

  - 运行`ScyllaHideIDAServerx86.exe`，并开始动态调试，可绕过debug检测

**快捷键**：

`A`：转换为字符串（ASCII）

`R`：转换为char型

`C`：转换为代码（code）

`ctrl+shift+w`：IDA不提供撤消，使用快照功能【`file > take database snapshot`】

`ctrl+E`：函数窗口对函数进行编辑

`X`：查看函数的交叉引用，如何被引用

`Y`：修改局部变量类型

`;`：汇编界面添加注释

`/`：伪代码界面添加注释

`Ctrl + P`：函数跳转

`Alt + T`：搜索文本字符串

`Shift + F2`：脚本执行窗口

`F6`：回到最近操作的窗口

`Ctrl + x`：对变量输入，可以获取哪个函数使用了这个变量

**动态调试**

选择Load WIndows debugger调试器，设置断点在某一代码行，需要在`Debugger`中打开`Use source-level debugging`

<img src="/img/reverse_note.zh-cn.assets/17284517325159.png" alt="图片无法加载" />

`F7`: 单步步入

`F8`: 单步步出

`F9`: 直接跳到下一个断点

`Ctrl + F7`: 直到返回跳出函数

可以点击寄存器区的寄存器箭头前往hex程序区

想查看某变量变化：`右键` > `Add Watch`

**断点**

- 可下多个断点，F9直接跳转；
- 内存断点，对数据段进行断点，每次读写该区域将会提示并停止：`点击数据所在地址` > `F2` > `设置是否读写 + 设置Size(可观察数组)`

**远程调试(如windows调试linux下文件)**

1. IDA pro安装目录下的`dbgsrv`文件夹下选择调试的程序linux_server
2. 在相应远程linux主机设置权限并执行linux_server
3. IDA选择Remote Linux debugger，`Debugger > Process options`，设置远程Linux IP地址

`__debugbreak()`：在代码中引入断点，系统会提示用户运行调试器

### Ghidra

`Symbol Tree`中包含`Functions`, `Classes`等，在`m`中有main函数

**查看函数调用关系**：`Window` > `Function Call Graph`

**变量重命名**：`右键` > `Rename Variable`，快捷键`l`

**点亮所有变量**：鼠标中键

**注释**：`右键` > `Comments`

**改函数签名**：`右键` > `Edit Function Signature`

**改数字的进制**：右键

### Frida

可用于调试hook Windows的exe可执行文件进程

pip安装出现：`拒绝访问。`，以管理员身份运行

```bash
pip install frida==16.4.10 # 16.5.1 win10报错不支持, win11可以
pip install frida-tools
```



### DIE

（Detect It Easy）查壳工具

### Peid

### Exeinfo PE

查壳工具

### OllyDbg

只适用32位，不再更新

`F2`：下断点

`F4`：运行到光标位置

`F7`：单步步入

`F8`：单步步过

`F9`：运行，到断点处

`F12`：暂停运行程序

重新开始：`x`图标 + `<<`图标

插件 > 中文搜索引擎 > 搜索 ASCII：找字符串

查看函数调用：右键 > 查看调用树

双击代码和注释都可直接进行修改

**查找数据并修改**：数据窗口 > `Alt + M`打开Memory map > `Ctrl + B`进行搜索 > 右键可以修改，需要进行保存【右键复制到可执行文件】 > 保存文件

**跳出循环**：右键 > 断点 > 运行到选定位置

**工具栏窗口**：

1.日志窗口(L) 2.模块窗口(E):查看每个模块的内存基址

3.内存窗口(M):查看每一个模块的段,所占用的内存区域

4.线程窗口(T):线程信息

5.窗口(W):查看程序的窗口句柄,窗口名,风格样式,回调函数等信息

6.句柄(H)

7.反汇编窗口( C)

8.补丁窗口(/)

9:**堆栈窗口(K)**:可查看调用堆栈,调试时堆栈回溯：`右键` > `显示调用`

10.断点窗口(B):显示所有的F2断点

11.参考( R)

12.run跟踪窗口(…)

### x64dbg

适用于32位和64位调试

| 反汇编显示区   | 寄存器显示区 |
| -------------- | ------------ |
| 内存数据显示区 | 栈显示区     |

- **运行到用户代码 点击**
- `Az`图标：查看字符串

循环箭头按键：为重新运行

右箭头按键：直接运行

快捷键：

`ctrl+G`：跳转到目标地址/表达式

`F2`：下断点

`F4`：运行到光标位置

`F7`：单步步入

`F8`：单步步过

`F9`：运行

**空格修改汇编代码**

可以右键修改十六进制代码：修复错误时将字节改为**90**(**nop**)

可以对代码转到对应的内存空间位置：右键 > 在内存布局中转到

搜索命令：右键 > 所有用户模块 > 命令，如寻找`pushad`

### GNU Binary Utilities

### GDB/PWNDBG

```Bash
set var $寄存器 = expr #修改寄存器的值
set {type}address = expr #给存储在address地址的变量类型为type的变量赋值
Fin：运行当前函数直到结束
```

### UPXshell

在Windows下进行UPX脱壳

### Jadx

APK分析工具

获取反编译后的JAVA原码且可视化，能打开文件格式：`.apk, .dex, .jar, .class, .smali, .zip, .aar, .ars`

### jd-gui

反编译jar包，获取JAVA源码

### ILSpy

用于`dll`文件的逆向，可以查看`Program`程序代码

### Z3-Solver

- `pip install -i ``https://pypi.tuna.tsinghua.edu.cn/simple`` z3-solver`指定镜像源安装
- 一般输入的是字符串，但最终将字符串转换为了数值进行计算，最终获取数值还需要转换回字符串，注意参与计算的数值之间的顺序（小端序，如何输入）
- Linux下运行

```python
from z3 import *
from libnum import *

# 定义变量
v1 = BitVec('v1', 64)
v2 = BitVec('v2', 64)

solver = Solver()
# 加入表达式
solver.add((v1 & v2 ^ (v1 | ~(v1 + v2)) & v2 & v1) != 0xdeadbeef)

if solver.check() == sat:
    result = solver.model()
    print(result) # 获取所有结果
    v1_val = int(result[v1].as_long())
    print(v1_val) # 获取单个结果
    
    print(n2s(v1_val)[::-1]) # 逆序转换为字符串
```



### QEMU

```Bash
# 创建虚拟磁盘
qemu-img create -f raw hello.img 10G
```

运行riscv程序

```bash
sudo apt install qemu-user
chmod +x ./elf
qemu-riscv64 ./elf
```



## 算法

### TEA系列

均会使用特征值$\delta$：**0x9e3779b9**，在IDA中可能使用补码表示：**0x61c88647**，可使用python：

**`hex(0xffffffff -  0x61c88647 + 1)`** **得到 0x9e3779b9**

#### TEA

Tiny Encryption Algorithm，使用Feistel分组加密框架，64轮迭代，原文以8字节(64位)为一组，密钥16字节(128位)，具体实现过程：

<img src="/img/reverse_note.zh-cn.assets/172845173251510.png" alt="图片无法加载" />

**汇编判断**：花指令

```assembly
mov ecx, xxx
shl ecx, 4
add ecx, xxx
mov edx, xxx
add edx, xxx
xor ecx, edx
mov eax, xxx
shr eax, 5
```

**加解密实现**

```C
#include <stdint.h>

// 无论是64位还是32位都可以使用uint32_t

//加密函数
void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;
    uint32_t delta=0x9e3779b9; // 固定值
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (i=0; i < 32; i++) { // 实际64轮, 此处一次循环两轮
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }
    v[0]=v0; v[1]=v1;
}

//解密函数 循环内颠倒顺序
void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i; // sum是32次循环的delta之和
    uint32_t delta=0x9e3779b9;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (i=0; i<32; i++) {
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }
    v[0]=v0; v[1]=v1;
}

int main()
{
    // 短数据加解密
    uint32_t v[2]={1,2},k[4]={2,2,3,4};
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("加密前原始数据：%u %u\n",v[0],v[1]);
    encrypt(v, k);
    printf("加密后的数据：%u %u\n",v[0],v[1]);
    decrypt(v, k);
    printf("解密后的数据：%u %u\n",v[0],v[1]);
    
    // 长数据加解密
    char data[] = "password123456789";
    uint32_t key[] = {0x11111111,0x22222222,0x33333333,0x44444444};

    for (size_t i = 0; i < strlen(data)/8; i++) encrypt((uint32_t*)&data[i*8], key);
    printf("加密后：%s\n", data);

    for (size_t i = 0; i < strlen(data)/8; i++) decrypt((uint32_t*)&data[i*8], key);
    printf("解密后：%s\n", data); 
    
    return 0;
}
```

#### XTEA

Delta值可以更改，**tea**取 key 的时候是固定下标取的，现在通过**计算**取

```C
#include<stdio.h>
#include<stdint.h>
 
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]){
        unsigned int i;
        uint32_t v0=v[0],v1=v[1],sum=0,delta=0x9E3779B9;
        for(i=0;i<num_rounds;i++){
                v0+=(((v1<<4)^(v1>>5))+v1)^(sum+key[sum&3]);
                sum+=delta;
                v1+=(((v0<<4)^(v0>>5))+v0)^(sum+key[(sum>>11)&3]);
        }
        v[0]=v0;v[1]=v1;
}
 
void decipher(unsigned int num_rounds,uint32_t v[2],uint32_t const key[4]){
        unsigned int i;
        uint32_t v0=v[0],v1=v[1],delta=0x9E3779B9,sum=delta*num_rounds;
        for(i=0;i<num_rounds;i++){
        v1-=(((v0<<4)^(v0>>5))+v0)^(sum+key[(sum>>11)&3]);
        sum-=delta;
        v0-=(((v1<<4)^(v1>>5))+v1)^(sum+key[sum&3]);
        } 
        v[0]=v0;v[1]=v1;
}
 
int main(){
// 输入十六进制, 可能需要倒序2个2个输入如: 0x12345678 , 用 0x78563412 输入
        uint32_t v[2]={1,2}; 
        uint32_t const k[4]={2,2,3,4};
        unsigned int r=32;                                //这里是加密轮数，自己设置 
        printf("加密前原始数据：%u %u\n",v[0],v[1]); // 更改为%x显示十六进制
        encipher(r,v,k);
        printf("加密后原始数据：%u %u\n",v[0],v[1]);
        decipher(r,v,k);
        printf("解密后原始数据：%u %u\n",v[0],v[1]); // 字符ASCII范围 < 0x7f | 127
        return 0;
}
```

#### XXTEA

<img src="/img/reverse_note.zh-cn.assets/172845181249123.png" alt="图片无法加载" />

原字符串长度可以不是**4**的倍数，明文分成若干固定长度块，每个块加密后，拼接

```C
#include <stdio.h>
#include <stdint.h>
#define DELTA 0x9e3779b9
#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))
// 混淆操作, 密码学扩散原理, xxtea特征

void xxtea(uint32_t *v, int n, uint32_t const key[4]){
    uint32_t y, z, sum;
    unsigned p, rounds, e; 
    // 加密
    if (n > 1){
        rounds = 6 + 52 / n; // 循环轮数
        sum = 0;
        z = v[n - 1];
        do{
            sum += DELTA;
            e = (sum >> 2) & 3;// e: sum>>2
            for (p = 0; p < n - 1; p++){
                y = v[p + 1];
                z = v[p] += MX; // 本质上还是双整形加密,用v[p]和v[p+1]对v[p]加密
                // v[p] += MX;
                // z = v[p];
            }
            y = v[0];
            z = v[n - 1] += MX; // 一轮加密的最后用v[n-1]和v[0]对v[n-1]加密
        } while (--rounds);
    }
    // 解密
    else if (n < -1){
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do{
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--){
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}

int main(){
    uint32_t v[2] = {1, 2};
    uint32_t const k[4] = {2, 0, 2, 4}; // 128位
    int n = 2;// n的绝对值为v长度，取正表示加密，取负表示解密

    printf("%#10x %#10x\n", v[0], v[1]);
    xxtea(v, n, k); // n>0为加密
    printf("%#10x %#10x\n", v[0], v[1]);
    xxtea(v, -n, k); // n<0为解密
    printf("%#10x %#10x\n", v[0], v[1]);
    return 0;
}
```

### md5

有4个固定的32bit值

### SM4

- 分组密码，4组，分组长度128位，密钥长度128位，加解密算法相同，轮密钥使用次序相反，32轮非线性迭代
- 轮密钥 rK 有32个，32位为单位，每一次迭代为一轮F函数
- $X_{i+4}=F(X_i,X_{i+1},X_{i+2},X_{i+3},rK_i)=X_i ⊕ T( X_{i+1}⊕X_{i+2}⊕X_{i+3}⊕rK_i)$

<img src="/img/reverse_note.zh-cn.assets/172845181249224.png" alt="图片无法加载" />

**F函数中的T函数**

T：合成置换，可逆变换，由非线性变换$\tau$和线性变换$L$复合而成：$T()=L(\tau())$

1. 非线性变换 A 到 B，A 和 B 均为32位，$\tau$由4个并行S盒构成【固定的256字节的数组】

$B =（b_0,b_1,b_2,b_3）= τ(A)=(Sbox(a_0),Sbox(a_0),Sbox(a_0),Sbox(a_0))$

查表规则：有 F 行 F 列，输入的32位可表示为2个十六进制数，一个做行一个做列找值替换

<img src="/img/reverse_note.zh-cn.assets/172845181249225.png" alt="图片无法加载" />

1. 线性变换 B 到 C，均为32位，此处为**循环左移**

$C = L(B) = B ⊕(B<<<2)⊕(B<<<10) ⊕(B<<<18) ⊕(B<<<24)$

**轮密钥扩展**

密钥128位，$MK=(MK_0,MK_1,MK_2,MK_3)$，轮密钥由密钥生成

系统参数：$FK=(FK_0,FK_1,FK_2,FK_3)$，固定参数：$CK=(CK_0,CK_1,\cdots ,CK_{31})$

<img src="/img/reverse_note.zh-cn.assets/172845181249326.png" alt="图片无法加载" />

<img src="/img/reverse_note.zh-cn.assets/172845181249327.png" alt="图片无法加载" />

- $(K_0,K_1,K_2,K_3)= (MK_0⊕FK_0, MK_1⊕, FK_1, MK_2⊕FK_2, MK_3⊕FK_3)$
  - $rK_i=K_{i+4}=K_i⊕T’(K_{i+1}⊕K_{i+2}⊕K_{i+3}⊕CK_i)\quad\quad [i=0,\cdots,31]$

$T'$即将 $T$ 中的 $L$ 替换为 $L'$：$L'(B)=B\oplus (B\lt\lt\lt 13)\oplus(B\lt\lt\lt 23)$

**解密**

由于$X_{i+4}=F(X_i,X_{i+1},X_{i+2},X_{i+3~}rK_i)=X_i ⊕ T( X_{i+1}⊕X_{i+2}⊕X_{i+3}⊕rK_i)$

所以$X_i=F(X_{i+4},X_{i+1},X_{i+2},X_{i+3},rK_i)=X_{i+4} ⊕ T(X_{i+1}⊕X_{i+2}⊕X_{i+3}⊕rK_i)$

将密文逆序，轮密钥也逆序，解密流程即加密流程的逆序

源代码链接借鉴：`https://cloud.tencent.com/developer/article/2158867`

```C
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define u8 unsigned char
#define u32 unsigned long

/******************************定义系统参数FK的取值****************************************/
const u32 TBL_SYS_PARAMS[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

/******************************定义固定参数CK的取值****************************************/
const u32 TBL_FIX_PARAMS[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279};

/******************************SBox参数列表****************************************/
const u8 TBL_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48};

// 4字节无符号数组转无符号long型
void four_uCh2uLong(u8 *in, u32 *out){
    int i = 0;
    *out = 0;
    for (i = 0; i < 4; i++)
        *out = ((u32)in[i] << (24 - i * 8)) ^ *out;
}

// 无符号long型转4字节无符号数组
void uLong2four_uCh(u32 in, u8 *out){
    int i = 0;
    // 从32位unsigned long的高位开始取
    for (i = 0; i < 4; i++)
        *(out + i) = (u32)(in >> (24 - i * 8));
}

// 左移，保留丢弃位放置尾部
u32 lmove(u32 data, int length){
    u32 result = 0;
    result = (data << length) ^ (data >> (32 - length));
    return result;
}

// 秘钥处理函数,先使用Sbox进行非线性变化，再将线性变换L置换为L'
u32 func_key(u32 input){
    int i = 0;
    u32 ulTmp = 0;
    u8 ucIndexList[4] = {0};
    u8 ucSboxValueList[4] = {0};
    uLong2four_uCh(input, ucIndexList);
    for (i = 0; i < 4; i++){
        ucSboxValueList[i] = TBL_SBOX[ucIndexList[i]];
    }
    four_uCh2uLong(ucSboxValueList, &ulTmp);
    ulTmp = ulTmp ^ lmove(ulTmp, 13) ^ lmove(ulTmp, 23);
    return ulTmp;
}
// 加解密数据处理函数,先使用Sbox进行非线性变化，再进行线性变换L
u32 func_data(u32 input){
    int i = 0;
    u32 ulTmp = 0;
    u8 ucIndexList[4] = {0};
    u8 ucSboxValueList[4] = {0};
    uLong2four_uCh(input, ucIndexList);
    for (i = 0; i < 4; i++){
        ucSboxValueList[i] = TBL_SBOX[ucIndexList[i]];
    }
    four_uCh2uLong(ucSboxValueList, &ulTmp);
    ulTmp = ulTmp ^ lmove(ulTmp, 2) ^ lmove(ulTmp, 10) ^ lmove(ulTmp, 18) ^ lmove(ulTmp, 24);
    return ulTmp;
}

// 加密函数, 加密任意长度数据，一次循环16字节，不足部分补0凑齐16字节整数倍
// len:数据长度(任意长度) key:密钥(16字节) input:明文 output:密文
void encode_fun(u8 len, u8 *key, u8 *input, u8 *output)
{
    int i = 0, j = 0;
    u8 *p = (u8 *)malloc(50);  // 50字节缓存区
    u32 ulKeyTmpList[4] = {0}; // 存储密钥的u32数据
    u32 ulKeyList[36] = {0};   // 用于密钥扩展算法与系统参数FK运算后的结果存储
    u32 ulDataList[36] = {0};  // 用于存放加密数据
    
    /***************************开始生成子秘钥********************************************/
    four_uCh2uLong(key, &(ulKeyTmpList[0]));
    four_uCh2uLong(key + 4, &(ulKeyTmpList[1]));
    four_uCh2uLong(key + 8, &(ulKeyTmpList[2]));
    four_uCh2uLong(key + 12, &(ulKeyTmpList[3]));
    ulKeyList[0] = ulKeyTmpList[0] ^ TBL_SYS_PARAMS[0];
    ulKeyList[1] = ulKeyTmpList[1] ^ TBL_SYS_PARAMS[1];
    ulKeyList[2] = ulKeyTmpList[2] ^ TBL_SYS_PARAMS[2];
    ulKeyList[3] = ulKeyTmpList[3] ^ TBL_SYS_PARAMS[3];
    for (i = 0; i < 32; i++) {// 32次循环迭代运算, 5-36为32个子秘钥
        ulKeyList[i + 4] = ulKeyList[i] ^ func_key(ulKeyList[i + 1] ^ ulKeyList[i + 2] ^ ulKeyList[i + 3] ^ TBL_FIX_PARAMS[i]);
    }
    /***************************生成32轮32位长子秘钥结束**********************************/
    
    for (i = 0; i < len; i++) // 将输入数据存放在p缓存区
        *(p + i) = *(input + i);
    for (i = 0; i < 16 - len % 16; i++) // 将不足16位补0凑齐16整数倍
        *(p + len + i) = 0;
    for (j = 0; j < len / 16 + ((len % 16) ? 1 : 0); j++) {
    // 循环加密,将加密后数据保存, 若16字节则进行一次, 17字节补0至32字节后进行加密两次
        /*开始处理加密数据*/
        four_uCh2uLong(p + 16 * j, &(ulDataList[0]));
        four_uCh2uLong(p + 16 * j + 4, &(ulDataList[1]));
        four_uCh2uLong(p + 16 * j + 8, &(ulDataList[2]));
        four_uCh2uLong(p + 16 * j + 12, &(ulDataList[3]));
        // 加密
        for (i = 0; i < 32; i++){
            ulDataList[i + 4] = ulDataList[i] ^ func_data(ulDataList[i + 1] ^ ulDataList[i + 2] ^ ulDataList[i + 3] ^ ulKeyList[i + 4]);
        }
        /*将加密后数据输出*/
        uLong2four_uCh(ulDataList[35], output + 16 * j);
        uLong2four_uCh(ulDataList[34], output + 16 * j + 4);
        uLong2four_uCh(ulDataList[33], output + 16 * j + 8);
        uLong2four_uCh(ulDataList[32], output + 16 * j + 12);
    }
    free(p);
}

// 解密函数, 与加密函数基本一致, 秘钥使用的顺序不同
// len:数据长度 key:密钥 input:密文 output:明文
void decode_fun(u8 len, u8 *key, u8 *input, u8 *output){
    int i = 0, j = 0;
    u32 ulKeyTmpList[4] = {0}; // 存储密钥的u32数据
    u32 ulKeyList[36] = {0};   // 用于密钥扩展算法与系统参数FK运算后的结果存储
    u32 ulDataList[36] = {0};  // 用于存放加密数据
    
    /*开始生成子秘钥*/
    four_uCh2uLong(key, &(ulKeyTmpList[0]));
    four_uCh2uLong(key + 4, &(ulKeyTmpList[1]));
    four_uCh2uLong(key + 8, &(ulKeyTmpList[2]));
    four_uCh2uLong(key + 12, &(ulKeyTmpList[3]));
    ulKeyList[0] = ulKeyTmpList[0] ^ TBL_SYS_PARAMS[0];
    ulKeyList[1] = ulKeyTmpList[1] ^ TBL_SYS_PARAMS[1];
    ulKeyList[2] = ulKeyTmpList[2] ^ TBL_SYS_PARAMS[2];
    ulKeyList[3] = ulKeyTmpList[3] ^ TBL_SYS_PARAMS[3];
    for (i = 0; i < 32; i++) // 32次循环迭代运算, 5-36为32个子秘钥
    {
        ulKeyList[i + 4] = ulKeyList[i] ^ func_key(ulKeyList[i + 1] ^ ulKeyList[i + 2] ^ ulKeyList[i + 3] ^ TBL_FIX_PARAMS[i]);
    }
    /*生成32轮32位长子秘钥结束*/
    for (j = 0; j < len / 16; j++) { // 进行循环加密,并将加密后数据保存
        /*开始处理解密数据*/
        four_uCh2uLong(input + 16 * j, &(ulDataList[0]));
        four_uCh2uLong(input + 16 * j + 4, &(ulDataList[1]));
        four_uCh2uLong(input + 16 * j + 8, &(ulDataList[2]));
        four_uCh2uLong(input + 16 * j + 12, &(ulDataList[3]));
        // 解密
        for (i = 0; i < 32; i++){
            ulDataList[i + 4] = ulDataList[i] ^ func_data(ulDataList[i + 1] ^ ulDataList[i + 2] ^ ulDataList[i + 3] ^ ulKeyList[35 - i]); // 与加密唯一不同: 轮密钥使用顺序
        }
        
        /*将解密后数据输出*/
        uLong2four_uCh(ulDataList[35], output + 16 * j);
        uLong2four_uCh(ulDataList[34], output + 16 * j + 4);
        uLong2four_uCh(ulDataList[33], output + 16 * j + 8);
        uLong2four_uCh(ulDataList[32], output + 16 * j + 12);
    }
}

// 无符号字符数组转16进制打印
void print_hex(u8 *data, int len){
    int i = 0;
    char alTmp[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (i = 0; i < len; i++){
        printf("%c", alTmp[data[i] / 16]);
        printf("%c", alTmp[data[i] % 16]);
        putchar(' ');
    }
    putchar('\n');
}

int main(void){
    u8 i, len;
    u8 encode_Result[50] = {0}; // 加密输出缓存区
    u8 decode_Result[50] = {0}; // 解密输出缓存区
    
    // 16字节的密钥
    u8 key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
                  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}; 
    
    // 18字节明文
    // u8 Data_plain[18] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,
    //                      0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23 };
    // 32字节明文
    // u8 Data_plain[32] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    //                      0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
    //                      0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    //                      0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    // 16字节明文
    u8 Data_plain[16] = {0x01, 0x23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    len = 16 * (sizeof(Data_plain) / 16) + 16 * ((sizeof(Data_plain) % 16) ? 1 : 0); // 扩充后的字节数
    
    // 加密
    encode_fun(sizeof(Data_plain), key, Data_plain, encode_Result); // 数据加密
    for (i = 0; i < len; i++)
        printf("%x ", *(encode_Result + i));
    // 解密，注：解密函数的输入数据长度应为扩展后的数据长度(必为16的倍数)
    decode_fun(len, key, encode_Result, decode_Result);
    for (i = 0; i < len; i++)
        printf("%x ", *(decode_Result + i));
    return 0;
}
```



### RC4

对称加密算法，包括**初始化算法**（KSA)和**加密算法**

<img src="/img/reverse_note.zh-cn.assets/172845181249328.png" alt="图片无法加载" />

**初始化过程**

```C
#include<stdio.h>
void rc4_init(unsigned char*S, unsigned char*key, unsigned long Len)
{
        int i = 0;
        char T[256] = { 0 };
        unsigned char tmp = 0;
        
        // 初始化 S 和 T 
        for (i = 0; i < 256; i++){
                S[i] = i;
                T[i] = key[i%Len]; // Len 为 key 的长度
        }
        
        // 初始排列 S
        int j = 0;
        for (i = 0; i < 256; i++)
        {
                j = (j + S[i] + T[i]) % 256; // 开始混淆
                tmp = S[i]; 
                S[i] = S[j]; // 交换s[i]和s[j]
                S[j] = tmp;
        }
}
```

**加解密过程**

```C
void rc4_crypt(unsigned char*S, unsigned char*Data, unsigned long Len_Data)
{ // 加解密同一函数
        int i = 0, j = 0, t = 0;
        unsigned long k = 0; // 明文索引
        unsigned char tmp;
        for (k = 0; k < Len_Data; k++) // Len 明文长度
        {
                // 生成密钥流，利用密钥流和明文进行加密
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                tmp = S[i];
                S[i] = S[j]; // 交换 S[x] 和 S[y] 
                S[j] = tmp;
                t = (S[i] + S[j]) % 256;
                Data[k] ^= S[t]; // S_box 和明文 xor 加密
        }
}
```

**调用**

```C
int main(){
    // system("chcp 65001"); // 防止终端乱码
        
    unsigned char S[256]={0}; // S_box
    unsigned char key[]= "xxxxxx"; // char key[256] = {0}
    // scanf("%s",key);
    // 赋值： unsigned __int8 data[] = {27, 155, 251, 25, 6, 106};
    unsigned char data[] = {0xa7, 0x11};
    // scanf("%s",data);
    
    // unsigned long length = strlen(key);
    unsigned long length = sizeof(key) - 1;
    unsigned long data_size = sizeof(data);
    rc4_init(S,key,length);
    
    rc4_crypt(S,data,data_size);
    printf("%s",data);
    return 0;
}
```

**CyberChef**

```
input: 0xA7, 0x1A, 0x11
# Find/Replace , {Global match, Case insensitive, Dot matches all}
# Find/Replace \n {Global match, Case insensitive, Dot matches all}
# From Hex Auto
# RC4 
```

**python**

```python
from Crypto.Cipher import ARC4

def rc4_decrypt(ciphertext):
    key = b'flag.fromserver'
    rc4 = ARC4.new(key)
    decrypted_data = rc4.decrypt(ciphertext)
    return decrypted_data
```

### DES



### Base算法

密码+编码

#### base64

基于64个可打印字符来表示二进制数据，6个bit为一个单元

## 代码混淆

### 脏字节

在汇编中加入`db 232`

<img src="/img/reverse_note.zh-cn.assets/172845181249329.png" alt="图片无法加载" />

### 花指令

<img src="/img/reverse_note.zh-cn.assets/172845181249330.png" alt="图片无法加载" />

```Assembly
mov eax, $
add eax, 12
jmp eax    ;跳转到寄存器中的地址
```

需要在汇编查看可疑跳转，IDA F5无法看出

### SMC技术

**Self Modifying Code**：自解码代码，程序中的部分代码加密，并插入解密代码，当程序需要运行源代码时，调用解密函数解密该部分代码，再跳转执行，阻止静态分析

**Windows**

```C++
// API函数，允许应用程序改变内存页的保护属性
BOOL VirtualProtect(
    LPCVOID lpAddress,    // 内存页起始地址
    SIZE_T dwSize,        // 内存页大小
    DWORD flNewProtect,   // 新保护属性 PAGE_EXECUTE_READWRITE=0x40
    PDWORD lpfloldProtect // 存储旧的保护属性
};
    
VirtualProtect((char *)&loc_401040, 0xCCu, 0x40u, (PDWORD)(v)); // 使得401040开始0xcc的内存可读可写可执行
```

修改会在IDA中发现：

```c
__asm { outsd }
__indword(0x98u);
__asm { retf }
```

```c
*(a - 40), *(a - 36), *(a - 32) // 一般为四个字节当一个整型计算
```

**IDAPython**

操作：`File > Script command > run`

```python
import idc
addr = 0xabcdef  # 是开始操作的起始地址
for i in range(531): # 直接末尾地址-起始地址
    b = get_bytes(addr + i, 1)
    idc.patch_byte(addr + i, ord(b) ^ 0x90) # 具体变化操作
```

**IDC**

```c
static xor(){
	auto addr = 0xabcdef;
	auto i = 0;
	for(i=0;addr+i<0xfedcba;i++){
		PatchByte(addr+i,Byte(addr+i)^0x90);
	}
}
```

**动调解决**



### 反调试

函数声明 

```C
long ptrace(enum __ptrace_request requête, pid_t pid, void *addr, void *data);
```

**PTRACE_TRACEME: 子进程标记**

**PTRACE_ATTACH: 父进程附加**

**PTRACE_CONT: 继续执行**

绕过：通过动态调试修改RIP直接跳到main函数 或 patch/nop反调试函数

### OLLVM

**Obfuscator-LLVM，原理：通过修改“LLVM-IR”完成，本质是一个LLVM-PASS——一套IR代码优化脚本**

<img src="/img/reverse_note.zh-cn.assets/172845181249331.png" alt="图片无法加载" />

**控制流平坦化**

将基本控制流并列，由**主分发器**来决定执行顺序

<img src="/img/reverse_note.zh-cn.assets/172845181249332.png" alt="图片无法加载" />

**指令替换**

基本运算公式复杂化

```Plain
混淆前: a=b+c    >>     混淆后: a=b+r, a=a+c, a=a-r
混淆前: a=b|c    >>     混淆后: a=(b&c)|(b^c)    //b, c均为整数时
```

**虚假控制流**

将原本顺序执行转为条件执行，条件为“永真式”导致不会执行虚假块，但IDA会进行控制流分析

<img src="/img/reverse_note.zh-cn.assets/172845181249333.png" alt="图片无法加载" />

永真式：`(((x - 1) * x) & 1) == 0`

## maze

迷宫问题

- 内存中布置一张地图(#和*显示)
- 用户输入限制在少数几个字符范围内(方向w/s/a/d等)
- 一般只1个迷宫入口、1个迷宫出口(多走法时代价最小 ---> 算法问题)

**迷宫初始化**

```Python
rows, cols = 10, 10
array = [['0' for _ in range(cols)] for _ in range(rows)]
```

**回溯算法**

- 深度优先算法DFS：栈
- 广度优先算法BFS：队列

### DFS

```Python
import sys # 设置递归深度
sys.setrecursionlimit(20000)

# x行 y列
def check(map, x, y): # 检查是否为0
    if (x >= 0) and (x <= max_x) and (y >= 0) and (y <= max_y):
        return map[x][y] == 0
    else:
        return False

def gen_nex(map, x, y): # 当前位置四周的情况
    all_dir = []
    if check(map, x - 1, y):
        all_dir.append((x - 1, y, 'w'))
    if check(map, x + 1, y):
        all_dir.append((x + 1, y, 's'))
    if check(map, x, y - 1):
        all_dir.append((x, y - 1, 'a'))
    if check(map, x, y + 1):
        all_dir.append((x, y + 1, 'd'))
    return all_dir

def check_success(map, x, y):
    if x == 54 and y == 74: # 判断出口
        return True
    else:
        return False

def print_info(map, x, y, path, file_path):
    with open(file_path, 'a') as f:
    # 地图
        for row in map:
                f.write(''.join(str(cell) for cell in row) + '\n')
        f.write('\n')  # 用于分隔每次递归的地图
    # 坐标
        f.write(str(x) + " " + str(y)+'\n')
    # 路径
        f.write(path+"\n")

def dfs(maze, x, y, path):
    map = maze.copy()    # 这里用将maze复制给map，避免修改掉原地图。
    if x!=54 or y!=74:
        map[x][y] = 1
    if check_success(map, x, y):
        # print_path(path, 'b.txt')
        return True

    next_point = gen_nex(map, x, y)
    for n in next_point:
        pathn = path + n[2]       # 将all_dir列表中的元组的第三个值，即方向传给pathn
        print_info(map, x, y, pathn, 'a.txt')
        if dfs(map, n[0], n[1], pathn):        # 这里开始递归 用all_dir的元组第一二个值和pathn作为参数，进行当前位置的又一次深度优先遍历
            return True
    return False

dfs(maze, 1, 1, "begin:")

# 使用之后仍需要判断是否正确, 比如: dwds > dd, dwwdss > dd
```

## 壳

<img src="/img/reverse_note.zh-cn.assets/172845181249334.png" alt="图片无法加载" />

### 压缩壳

#### UPX

开源、压缩壳，原文件需要40kb以上才能加壳，可通过strings查看UPX字符串

脱壳原理为**ESP定律**（即堆栈平衡定律），可以在linux中使用：

```Bash
upx -d file #进行脱壳
```

或在Windows下使用**UPX shell**直接解压缩，UPX shell解压缩可能导致文件无法运行

```Python
# 在upx目录下 脱壳
./upx.exe -d file
```

**x96dbg**：F8 > 寄存器窗口 > ESP > 在内存窗口中转到

**Ollydbg**：只能调试32位

**使用OD进行UPX手动脱壳**

第一条指令一般为pushad，将寄存器值存入栈中，保存上下文

<img src="/img/reverse_note.zh-cn.assets/172845181249435.png" alt="图片无法加载" />

F8单步执行，此时寄存器ESP值发生改变

<img src="/img/reverse_note.zh-cn.assets/172845181249436.png" alt="图片无法加载" />

寄存器窗口 > ESP > HW break[ESP] 或 [数据窗口中跟随] 转到内存视图 > 此处ESP地址设置断点-硬件访问

<img src="/img/reverse_note.zh-cn.assets/172845181249437.png" alt="图片无法加载" />

F9运行到断点处，上图`003B750F`的上一行为`popad`，当执行到popad时，将会恢复ESP，此时将会触发硬件断点，中断

发现一个大跳转`jmp UPX`，于是F4到jmp代码处 > F8步入

<img src="/img/reverse_note.zh-cn.assets/172845181249438.png" alt="图片无法加载" />

<img src="/img/reverse_note.zh-cn.assets/172845181249439.png" alt="图片无法加载" />

出现了正常的函数开头和结尾，即找到OEP

**进行dump完成脱壳**：

1. **插件 > OllyDump > 脱壳在当前调试的进程 > 获取EIP作为OEP > 脱壳【由于不是windows XP会失败】**
2. **右键 > 用OllyDump脱壳调试进程 > 脱壳**

**x64dbg+手动脱壳**

打开文件先查看系统断点，`F9`运行进入断点处，有多个`push`操作

#### ASPack

### 加密壳

#### ASProtect

#### Armadillo

#### EXECryptor

#### Themida

#### VMP

dll中加入了VMP壳：`VMProtect`

**爆破脚本**：爆破exe文件

```C++
#include<iostream>
#include<Windows.h>

void BF(){
	HMODULE h = NULL;
    h = LoadLibraryA("xx.dll");
    
    typedef int(*func_in_dll)(char*, size_t);
    char* flag = (char*)malloc(16); // 15内容+'\0'
    // 初始化
    flag[0] = 'x';
    flag[15] = '\0';
    func_in_dll func = (func_in_dll)GetProcAddress(h, "func_in_dll");
    // 爆破
    ... if(func(flag, 15)){
        printf("%s\n", flag);
        return;
    }
    CloseHandle(h);
}
```



### 混淆壳

### 虚拟机壳

## 脱壳

单步跟踪寻找OEP（original entry point，原始入口点），寻找大型跳转

### API定位

**Microsoft Visual C/C++ 6**

- `VC6`写的代码，直接定位到`GetVersion`下断点
- x64dbg中：`视图` > `模块`，`GetVersion`在`Kernel32.dll`中，运行，在栈中找调用函数
- OEP在GetVersion上文

### ESP定律

od载入程序有pushad指令可用其脱壳

## Windows API

**堆API**

```C++
HeapCreate(flOptions, dwInitialSize, dwMaximumSize)
// 堆分配选项, 堆的初始大小, 堆的最大大小

HeapAlloc(hHeap, dwFlags, dwBytes)
// 指向堆的句柄, 堆分配选项, 分配字节数

HeapFree(hHeap, dwFlags, lpMem)
// 释放的堆的句柄, 堆释放选项, 指向要释放内存块的指针

HeapDestroy(hHeap)
// 销毁的堆的句柄
```

**用户API**

```C++
MessageBoxA(hWnd, lpText, lpCaption, uType)
// 消息框所有者窗口的句柄, 显示信息, 对话框标题, 对话框内容和行为(中止,重试,忽略,确认,取消) 
```

**调试API**

```C++
IsDebuggerPresent()
// 当前进程在调试器上下文中运行，返回非0; 否则为0
```

**调用库API**

```c
libr = LoadLibraryA("xxx.dll");
// 将指定模块加载到调用进程地址空间

addr = GetProcAddress(libr, "fun_or_vari");
// 从指定动态链接库dll导入函数或变量地址

CloseHandle(libr);
// 关闭对象的有效句柄
```



## 安卓

jadx打开文件后，`AndroidManifest.xml`文件中包括**配置信息**等

`APK`文件若PC模拟器无法打开，则直接尝试手机安装打开，版本问题

## .Net

### C#

## python

**Cython**

`whl`文件格式`xxx-1.14-cp312-cp312-win_amd64`中cp312表示python的版本：python-3.12，需要使用对应的python版本进行安装

```python
pythonx -m pip install xxx.whl # 使用python指定的对应pip安装

import xxx # 安装后直接导入
help(xxx) # 可以查看信息
```

## VM

维护opcode操作码表模拟虚拟机操作，`switch`对于不同的码进行相应操作，一般来说都是对**单字符**进行处理（友好出题人，先使用IDA动态调试跟踪操作

**Frida插桩测试**

```javascript
var number  = 0
function main()
{
     var base  =  Module.findBaseAddress( "test.exe" ) // 获取目标进程的基地址 
     // console.log( "base:" ,base)
     if (base){
         Interceptor.attach(base.add( 0x1044 ), { // 该地址为opcode idx+1
                 onEnter: function(args) {
                     number += 1 // 进行插桩 每当程序运行到该地址 number + = 1
                 }
         });
 
         Interceptor.attach(base.add( 0x113f ), { // 结束
             onEnter: function(args) {
                 // send(number) // 配合python自动化脚本
                 console.log( "end!" ,number)
             }
         });
     }
}
setImmediate(main); // 异步调用
```

此时在输入不同值时会出现不同number，且输入正确number会增加，可利用此进行侧信道爆破

**侧信道爆破**

```python
# -*- coding: UTF-8 -*-
import subprocess
import frida

def is_right():
    global new_number,number
    if new_number > number: # number增加则猜测正确，更新
        number = new_number
        return True
    else:
        return False

def on_message(message, data): # 处理从注入的 JavaScript 脚本中发送回来的消息
    global new_number
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
        new_number = message['payload']
    elif message['type'] == "error":
        print(message["description"])
        print(message["stack"])
        print(message["fileName"],"line:",message["lineNumber"],"colum:",message["columnNumber"])
    else:
        print(message)
        pass        

printable = "`!\"#$%&'()*+,-./:;<=>?@[]^_{|}~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
number = 709 # 测试脚本输出的number值
new_number = 0
flag = "xxxctf{"

jscode = open("h00k.js","rb").read().decode()

for index in range(len(flag),54):
    for i in printable:
        process = subprocess.Popen("test.exe", # 启动程序
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True)
        tmp_flag = (flag+i).ljust(53,"A")+"}" # 54 - 1
        print(tmp_flag)
        print("try index:",index ,"chr :",i)

		# 附加frida脚本到目标进程
        session = frida.attach("test.exe")
        script = session.create_script(jscode) # 在目标进程里创建脚本
        script.on('message', on_message) # 注册消息回调
        script.load() # 加载创建好的javascript脚本

        process.stdin.write(tmp_flag) # 写入
        output, error = process.communicate() # 获取输出
        if(i == '`'):
            number = new_number
        elif(is_right() == True):
            flag +=i
            print(flag)
            break
        process.terminate()
```

最后一个字符还需要再次爆破

```python
import subprocess
flag = 'flag{xxxx }'

for i in range(32,128):
    process = subprocess.Popen("test.exe",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True)
    
    input_data = flag.replace(" ",chr(i))
    
    process.stdin.write(input_data)
    print(input_data)
    output, error = process.communicate() # 读取进程的输出

    if ("Invalid" not in output.strip()):
    	print('Output:', output.strip())
    
    if error:
        print('Error:', error.strip())
    process.terminate()
```

## 易语言

- 运行exe文件寻找逻辑：找**点击**类似的函数，分析输入经过的过程
- 易语言加密算法可选DES和RC4，RC4与标准算法结果相同，直接RC4解即可，**DES算法和其他标准算法产生结果不同**

**DES算法解密**

```python
# 易语言特定解法，加密过程Key值每一个Byte都被按位倒转
from Crypto.Cipher import DES

def reverse_bytes(b): # 翻转字节串
    assert type(b) == bytes
    ba = bytearray(b) # 字节串转换为可变字节数组
    for i in range(0, len(b)):
        ba[i] = int(format(b[i], '0>8b')[::-1], 2)
        # format(b[i], '0>8b') 将第i字节变为8位二进制01串
    return bytes(ba)

def get_new_key(key): # 新密钥生成函数
    ba = bytearray(8) # 长度为8字节数组
    i = 0
    for b in key:
        ba[i] = b ^ ba[i]
        i = i + 1 if i < 7 else 0 # 0-7
    return bytes(ba)

def remove_len(d):
    assert type(d) == bytes
    return d[4:]

def e_des_decrypt(raw, key):
    des = DES.new(reverse_bytes(get_new_key(key)), DES.MODE_ECB)
    t = des.decrypt(raw)
    return remove_len(t)
```




