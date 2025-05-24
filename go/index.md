# GO




- Google开发，高性能，高并发，静态编译，垃圾回收，标准库丰富，跨平台

## 环境

**编译运行**

`GOPATH`下包含目录`bin`(存放编译后的二进制文件)、`pkg`(存放编译后的库文件)、`src`(存放源码文件)

```bash
go build xx.go # 编译型语言
go run xx.go # 运行
go get -u github.com/xx/xxx # 获取外部包

go env -w GO111MODULE=auto # 视情况而定
go mod init dir_name # 初始化
```

**结构**

```go
package main
import xx
func main(){
	xxx
}
```



## 库

### os

```go
file,err := os.Create("xxx") // 创建文件

os.Exit(0)//跳出程序
```

### time

```go
now = time.Now() // 当前时间
// 年月日时分秒
now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second()
```

**时间持续**：`time.Duration()`

```go
time.Sleep(time.Duration(n) * time.second) // 停止n秒
```

**时间运算**

```go
now.Add(time.Duration(2) * time.Hour) // 加2小时
now.Sub(xx) // 减
now.Equal(xx) // 是否相同
t.Before(u) // t是否在u前
t.After(u) // t是否在u后
```

**定时器**

```go
ticker = time.Tick(time.Second) // 一秒间隔的定时器
<-ticker // 从定时器接收值
```

**获取时间戳**

```go
time.Unix()
```



### net

**http**

```go
http.Handle("/", http.FileServer(http.Dir("."))) // 根路径创建文件服务器
http.ListenAndServe(":8080", nil) // 启动HTTP服务器
```

**tcp**

```go
server, err := net.Listen("tcp", "127.0.0.1:1080") // tcp监听
client, err := server.Accept()
port := binary.BigEndian.Uint16(buf) // 端口接受
dest, err := net.Dial("tcp", "x:x:x:x:aaa") // 建立tcp连接
```



### math

```go
math.Pi
math.Sin(xx)
a := math.MaxInt32 // 初始化最大值
```



## 基本结构

### 数组

- 值类型，可修改数组成员，长度不可变
- `[n]*T`：指针数组，`*[n]T`：数组指针

**创建**

```go
a := [count]int{1,2}
// count数量的int数组，{}为具体数据，若写[...]编译器自动计算长度
// 若不包含数字，会导致直接给其赋值失败，只能append作为切片操作

// 索引值
var langArray = [...]string{1:"Golang",3:"Python",7:"Java"}
```

**遍历**

```go
for index,value := range Array
```

**交换元素**

```go
a, b = b, a // 可用于逆置
```

**二维数组**

```go
matrix2 := [][3]int{
	{1, 2, 3},
	{4, 5, 6},
	{7, 8, 9},
}
```



### 切片

- 可变长，引用类型，切片间不能比较，不能使用`==`，唯一比较方法是和**nil**比较
- nil切片没有底层数组，长度容量都为0

**初始化**

```go
var var_name []T // T:元素类型，未申请内存
var c = []bool{false,true}

//基于数组得到切片
a := [5]int{55,56,57,58,59}//数组
b := a[1:4]

d := make([]int,5,10)// 元素个数5，容量10
```

**返回**

```go
return []int{i, j} //创建一个包含两个整数元素的整数切片
```

**增加**

底层数组不能容纳新增元素时，切片容量按照1,2,4,8,16的规则自动进行扩容

```go
slice = append(slice, element1, element2...) //返回一个新的切片，赋值给原始切片来更新，添加到切片末尾
slice = append(slice, slice...) //合并两个切片，修改函数内的局部变量而非外部传入的原始切片。
```

**创建**

```go
slice := make([]dataType, length, capacity)
//长度为length、容量为capacity,容量表示切片底层数组的大小，当切片长度达到容量时，底层数组会扩展
```

**取切片**

```go
q = q[:len(q)-1]	//取第一个到倒数第二个
q = q[:len(q)]		//取第一个到最后一个
```

**删除元素**

```go
a := []string{"a","b","c","d"}
a = append(a[0:2],a[3:]...) // 删除"c"
```

**切片容量**

```go
cap() // 获取切片容量
```

**复制切片**

将一个切片的数据复制到另一个切片空间中，区别于赋值，其中一个改变不影响另一个

```go
copy(destSlice, srcSlice []T) // 返回的int为实际复制的元素个数
c := make([]string, len(s))
copy(c, s)
```



### 字符串

**创建**

```go
str := "" // 字符串是不可变的，即一旦创建，就不能更改其内容
```

```go
// 多行字符串
s := `first
	second
`
```

**连接**

```go
//连接要赋值给新的字符串
str1, str2 := "1", "2"
ans := str1 + str2
```

**切片操作**

```go
tmp := s[i : i+len(p)]
//用于从字符串 s 中截取一个子串，起始索引为 i，长度为 len(p)
```

**字符串切片拼接**

```go
s := []string{"1", "2"}
ans := strings.Join(s, "+") // 1+2
```

**分割**

```go
s := "1x2x3"
p := strings.Split(s, "x") // ["1","2","3"]
```

**查找**

```go
strings.Index(s, "a") // "a"第一次出现位置
strings.LastIndex(s, "z") // "z"最后一次出现位置
```

**子串**

```go
t, x, s := "ABC", "A", "AB"
strings.ContainsRune(t, x)	// 判断t中是否包含x
strings.Contains(t, s)	// 判断t是否包含子串s
```

**前后缀**

```go
// 返回bool类型
has := strings.HasPrefix(s, "pre")
has := strings.HasSuffix(s, "suf")
```

**计数**

```go
strings.Count(s, "a")
```

**重复**

```go
strings.Repeat(str, n) // 重复n次
```

**替换**

```go
strings.Replace(src_str, old_sub_str, new_sub_str, n) // n替换次数, 负数表示替换所有匹配子串
```

**大小写**

```go
strings.ToLower(a)
strings.ToUpper(a)
```



### 类型

- 整型无法强制转换为布尔类型（默认为false）

**自定义类型**

```go
type TypeName underlyingType // 将 TypeName 定义为底层underlyingType类型
```

**结构体类型**

- 实例化才分配内存，占用一块连续内存
- 字段大写表示公开，小写表示私有

```go
type Person struct {
    string // 匿名字段，每种数据类型只能有一种, x.string输出
    Age int
    x another_struct_type // 结构体嵌套
}

type hp struct{ sort.IntSlice }
//在结构体定义了一个匿名字段，类型是 sort.IntSlice，即hp可以使用sort.IntSlice的方法
//sort.IntSlice实现了sort.Interface 接口
```

**初始化**

```go
p := person{
	name: "jshiro",
	age: 18,
}
```

**结构体方法**

```go
func (p person) check(age int) bool {
	return p.age == age
}

a.check(12) // a为实例对象
```

**结构体指针**

```go
var a = new(person) // a的类型为*person结构体指针
(*a).name = "haha" //调用赋值 或 a.name = "haha"
```

**取结构体地址进行实例化**

```go
x := &person{}
x.name = "hh"
```

**自定义构造函数**

```go
func newPerson(name, city string,age int8) *person{
	return &person{
		name: name,
		city: city,
		age: age,
	}
}
```

**结构体标签Tag**

- Tag携带元信息，可在运行时通过反射读取，用于序列化或数据库交互
- 在结构体字段后方定义，反引号包裹

```go
type A struct{
	Name string `json:"name" db:"name_db" xml:"name_xml"`
}

p := Person{Name: "h"}
// 获取反射值对象
v := reflect.ValueOf(p)
t := v.Type() // main.Person

// 遍历
for i := 0; i < v.NumField(); i++{
    field := t.Field(i)
    // field.Name : Name
    // field.Tag.Get("json") : name
    // field.Tag.Get("db") : name_db
}
```





## 数据结构

**空：`nil`**

### 链表

结构体：

```go
type ListNode struct {
    Val int
    Next *ListNode
}
```

**创建头结点**指向链表head：

```go
prev := &ListNode{Val: 0, Next: head} 


// 创建一个新的链表头节点，并用一个指针指向头节点
dummy := &ListNode{}
current := dummy//最终返回d.next
```

创建**空结点**

```go
var prev *ListNode //空结点
```

判断初始链表  **空**  或  **一个结点**  ：

```go
if head == nil || head.Next == nil{
	return head
}
```

判断：

```go
if q != nil && q.Next != nil{
	xxx
}
```



### 哈希表

- map，映射，无序，引用类型，必须初始化才可使用
- 默认初始值nil，make函数分配内存

**创建**

```go
hashTable := map[int]int{}		//键值都为int型的空哈希表，初始值都为0
mp := map[string][]string{}		//键为string字符串，值为[]string，字符串切片
// make(map[keyType]valueType)   键值对
//使用make时不能指定数量
mp := map[rune]bool{} // 使用 rune 作为键类型，表示 Unicode 字符
//取字符串中字符
mp

//创建键值对映射加入hash表h中
temp := map[string]int{ip.String(): port}
hp = append(hp, temp)

// 初始化
a = make(map[KeyType]ValueType,[cap]) //cap表示map的容量
b := map[int]bool{
    1: true,
    2: false,
}//声明同时初始化
```

**删除**

```go
delete(map, key)	//删除哈希表map中的键为key的键值对
```

**添加**

```go
a["XXX"] = 100 // 添加键值对
```

**遍历**

```go
for k, v := range Map{}
```

**判断键是否存在**

```go
value, ok := scoreMap["xx"]
// ok返回true存在，值返回给value；false不存在，value为0
```

**链表中用法**

```go
mp := map[*ListNode]struct{}{}
//此时主要留键，需要的是结点而不是结点中的值，所以*ListNode
//值为空结构体

//之后的赋值
mp[head] = struct{}{}
```

**元素为map类型的切片**

```go
var mapSlice = make([]map[string]int,2,2) // 长度，容量 [nil nil]
mapSlice[0] = make(map[string]int, 4)//初始化
mapSlice[0]["XXX"] = 100 //[map[XXX:100] map[] map[] map[]]
```

**值为切片类型的map**

```go
var sliceMap = make(map[string][]int,8)//只完成map初始化
sliceMap["xxx"] = make([]int,8)//完成对切片的初始化
sliceMap["xxx"][0] = 100 //xxx:[100 0 0 0 0 0 0 0]
```



### 堆

**定义**

```go
type hp struct{ sort.IntSlice }//定义堆类型
```

**less**

```go
func (h hp) Less(i, j int) bool { return a[h.IntSlice[i]] > a[h.IntSlice[j]] }
//(h hp)是一个方法的接收者声明，表明Less方法是hp类型的方法
//方法内部，h是当前调用该方法的hp类型的实例，h可访问当前实例的属性和方法
//比较 hp 类型中两个元素的大小，规则是根据切片 a 中元素的大小进行比较。
```

**push**

```go
func (h *hp) Push(v interface{}) { h.IntSlice = append(h.IntSlice, v.(int)) }
//(h *hp)是指方法绑定到 hp 类型指针的实例上
//方法内部需要修改实例内容，所以用指针
//用于向hp类型的切片添加一个元素
//v interface{} :方法接收一个空接口类型的参数 v，即任意类型的值。
//v转化为int类型追加到h类型实例切片中，v.(int)为类型断言，只能用于接口类型
```

**pop**

```go
func (h *hp) Pop() interface{} {
    a := h.IntSlice; 			//获取 hp 类型中嵌套的 sort.IntSlice 实例
    v := a[len(a)-1]; 			//获取切片中最后一个元素
    h.IntSlice = a[:len(a)-1]; 	//删除切片中最后一个元素
    return v 					//返回被弹出的元素
}
//hp类型弹出一个元素，最后一个元素取出，切片缩短一个元素，返回被取出的元素
```

**创建**

```go
q := &hp{make([]int, k)}
//&hp{} 创建一个 hp 类型的实例，并返回实例的指针
//长度为 k 的 int 类型切片，并将其作为初始化值赋给 sort.IntSlice
```

**初始化**

```go
heap.Init(q)
//将实现了 heap.Interface 接口的堆初始化
//sort.Interface 接口定义了一组用于排序的方法，其中包括 Len、Less 和 Swap。而 heap.Interface 接口在此基础上扩展，添加了 Push 和 Pop 方法，使得实现了 heap.Interface 接口的类型可以被用作堆数据结构。
```



## 基础操作

### 条件

**if-else**

```go
if xxx {
	xxx
} else if xxx {
    xxx
} else {
    xxx
}
```

**switch**

```go
switch a { // 也可删除a, 直接在case中写if-else判断的条件
case 1:
	xxx
default:
	xxx
}
```



### 循环

**for range**

```go
for i, x := range nums // range遍历nums数组, i为当前元素的索引, x为当前元素的值
for k, v := range maps // range遍历maps映射, k:键, v:值

for i, ch := range s[:sLen-pLen] //遍历字符串s的前sLen-pLen个字符
```

**for**

```go
// for 初始语句; 条件表达式; 结束语句 任意一个都可省略
for i:=0; i < len(mp); {
	i++
}
//遍历可能变化的数组

//m中的值为bool型，直到m[key+1]为false，循环停止
for m[key+1] {
    key++
}
```

### 格式化输出

```go
fmt.Println(xx,xx) // 输出后换行
```

**查看数据类型**

```go
fmt.Printf("%T", str)
// %b:二进制, %o:八进制, %x:十六进制, %#v:结构体名+结构体, %.2f:2位浮点数, %p:地址值, %v:数据值, %s:字符串, %+v: 字段名+值
```

**格式化**

```go
fmt.Fprintf(out, "there's '%s'\n", s)
fmt.Errorf("%w", err) // 错误输出
```



### 输入输出

从程序的**标准输入中读取**内容

```go
scanner := bufio.NewScanner(os.Stdin)//声明创建 bufio.NewScanner 类型的变量 scanner

for scanner.Scan() {	//循环读入下一行，并移除行末换行符，读到一行返回true，无内容返回false
	fmt.Println(scanner.Text())//读取的内容
    fmt.Print(scanner.Bytes())//扫描到的字节序列
}
```

**文件中读取内容**

```go
f,err := os.Open("xx.txt")
fileread := bufio.NewScanner(f)
```

**设置扫描器缓冲区大小**

```go
scanner.Buffer(nil, math.MaxInt32)
//第一个参数：表示用于存储扫描器缓冲区的字节切片， nil表示不使用自定义缓冲区
//第二个参数：缓冲区最大容量
```

```go
xxx.Flush()
//将缓冲区中的数据刷新到底层的 io.Writer 接口对象中，确保数据被写入到底层的存储介质中（文件中）
```

**创建带有缓冲区的写入器**

```go
func NewWriter(w io.Writer) *Writer
```

**读取用户输入**

```go
// 循环读
reader := bufio.NewReader(os.Stdin)
for {
    input, err := reader.ReadString('\n')
    input = strings.TrimSpace(input) // 清理输入
}

ver, err := reader.ReadByte() // 一字节一字节读
```

**输入**

```go
n,m,_ := fmt.Scan(&a, &b, &c)

var n int
fmt.Scanf("%d\n", &input) // 扫描用户输入
```

**ACM方式输入，已知行数**

```go
var t,a,b int
fmt.Scanln(&t)
for i:=0;i<t;i++{
    fmt.Scanln(&a,&b)
    fmt.Println(a+b)
}
```

**读取**

```go
buf := make([]byte, 4)
io.ReadFull(r, buf) // 从r读取数据直到buf填满
```



### 数字解析

```
f, _ := strconv.ParseInt("12", 10, 64) // 进制: 10, 0 表示自动推测, 精度: 64
n1, err := strconv.Atoi("123") // 123
```



### 文件

**打开文件**

```go
file = os.Open("./xx.txt")
file, err := os.OpenFile("a.txt", os.O_CREATE|os.O_WRONLY, 0644)
// O_WRONLY只写, O_CREATE不存在则创建, O_RDONLY只读, O_TRUNC存在则清空, O_APPEND追加
defer file.Close()
```

**文件写入**

```go
writer := bufio.NewWriter(file)
writer.WriteString("hello") // 将内容写入缓冲区
writer.Flush() // 将缓冲区内容写入磁盘
```

**文件读取**

```go
var tmp = make([]byte, 128) // 字节切片存储
n, err := file.Read(tmp) // 读取到tmp中
```

**处理读取结束**

```go
if err == io.EOF{ // 当把文件读完，End Of File
	break
}
```

**逐行读取**

```go
reader := bufio.NewReader(file)
line, err := reader.ReadString('\n') // 读取一行直到\n
```

**数据复制**

```go
_, _ = io.Copy(dest, reader) // 将reader中数据复制到dest中, 阻塞直到完成或错误
```



### 错误处理

**err**

```go
func xxx(xx) (xxx, err error) {
	return xx, nil // 无错误
	return nil, errors.New("error_information") // 错误
}
```

**panic/recover模式**

- `recover`只在`defer`调用的函数中有效，panic将会异常退出

```go
func b() {
    // defer 确保 b函数结束前执行该匿名函数
	defer func() { // defer需要在可能panic前出现, 捕获并处理panic
		err := recover() // recover必须和defer一起使用, 捕获panic引发的错误
        if err != nil { // 未panic:返回nil, panic:返回panic参数
			fmt.Println("func b error")
		}
	}()
	panic("panic in b") // 模拟错误情况
}
```

```go
panic(err) // 抛出异常
```



### 函数

a是func变量类型，可赋值`b := a`

```go
// ... 表示可变参数，切片类型，参数可为函数类型: func(type) type
func fun_name(arg1 type, arg2 ...type) (ret1 type, ret2 type){ // 返回值可只写类型
	return xxx, xxx
}
```

**匿名函数**

- 无函数名，实现回调函数/闭包

```go
func(args)(ret_value){
	xxx
}() // 括号表示立即执行
```

### 闭包

闭包 = 函数 + 引用环境 = 函数 + 外层变量的引用

```go
func a(name string) func() { // 定义函数，返回值是函数
	return func() {
		fmt.Println("hello",name)
	}
}
func main() {
	r := a("Jshiro")
	r() // hello Jshiro
}
```

### 接收者

- 方法是一种作用于特定类型变量(Receiver接受者)的函数，接受者类似于其他语言中的`this`与`self`
- 接收者类型是指针类型，则改变后会改变原值；值类型，则改变后不会改变原值，操作的是副本

```go
// String 方法为Person类型定义了一个接收者方法
// p 是接收者变量，Person 是接收者类型，接收者变量一般为接收者类型的首字母小写
func (p Person) String(args) string {
	return fmt.Sprintf("Name: %s, Age: %d", p.Name, p.Age)
}
```

### 指针

- 指针不能进行偏移和运算，安全指针，函数传参是值拷贝
- 修改变量值可创建指向该变量地址的指针变量，传递数据使用指针

**定义**

```go
var ptr *int // 指向int类型变量的指针
```

**赋值访问**

```go
a := 10
ptr = &a // 变量a的地址赋给指针ptr
*ptr // 访问变量a
```

**函数**

```go
// 函数内
func addOne(x *int) {
    *x = *x + 1 // 通过指针修改外部变量的值
}

// 函数外
a := 10
addOne(&a)
```



## 基础用法

**"comma, ok" 惯用法**

```go
value, ok := myMap[key]// ok是bool值，value是key对应的值
if ok {
    // 键 key 存在于 myMap 中，可以使用 value 进行操作
} else {
    // 键 key 不存在于 myMap 中
}
```

```go
if _, exists := mp[x]; !exists {
    //若x不存在于mp中
}
```

**获取进程信息**

```go
os.Args // 获取运行参数, 第一个为可执行程序路径
os.Getenv("PATH") // 获取环境变量
os.Setenv("A", "B") // 设置环境变量

// 命令执行
buf, err := exec.Command("grep", "127.0.0.1", "/etc/hosts").CombinedOutput()
if err != nil{
    panic(err)
}
```

**数据类型转化**

```go
s := []byte(str)	//将字符串转化为字节切片
str := string(s)		//字节转化为字符串
high := int(num[0]) - 48	//以索引方式取字符串单个字符，为byte型，转换为数字
```

**多变量赋值**

```go
left, right, n := 0, 0, len(nums)
```

**字母表数组**

```go
var pCount [26]int	//统计字母数量
pCount[s[i]-'a']++	//字符串s
```

**声明变量**

```go
var scount, pcount [26]int
//声明多个变量
var (
    a = xxx
    b = xxx
)
// 函数内部
a := 10
// 初始化
var a int = 10
// 匿名变量 不占用命名空间，不分配内存
_
```

**声明常量**

```
const con = 1 // 定义时必须赋值
```

**位运算符**

```
&, |, ^, <<, >>
```

**延迟执行**

```go
// 延迟处理语句按defer逆序执行: 先xx2后xx1
defer xx1
defer xx2
```

**匿名函数**或**闭包**

```go
x := func() bool{
	xxx
}
```

创建函数赋值给x，x为函数类型变量

- **长度**

```go
len(nums)	//nums为数组，则为数组长度
len(mp) 	//mp是哈希表，为键值对的数量
```

- **切片排序**

```go
sort.Slice(s, func(i, j int) bool { return s[i] < s[j]})	//升序

sort.Ints(nums)//对整数切片进行升序排序,会修改传入的切片
sort.Ints(a[:])
sort.Strings() //用于对字符串切片进行排序
```

- **排序接口**

```go
type Interface interface {
    Len() int           // 返回集合中的元素个数
    Less(i, j int) bool // 报告索引 i 的元素是否应排在索引 j 的元素之前
    Swap(i, j int)      // 交换索引 i 和 j 处的元素
}
```

- **max函数实现**

```go
func max(arg ...int) int {
    res := arg[0]
    for _, v := range arg {
        if v > res {
            res = v
        }
    }
    return res
}
```

- **随机整数**

```go
rand.Intn(100) //随机0~99
```

- **分配内存**

```go
// new
var a *int
a = new(int) // *a对应该类型的默认值:0
*a = 100 // 修改变量
```

```go
// make 只用于slice、map、chan的内存创建, 返回引用类型本身
var b map[string]int
b = make(map[string]int,10)
b["xxx"] = 100
```



## 基础知识



### 拷贝

- **copy**  和  **"="复制**

1. copy复制 比 等号复制 **慢**
2. copy复制为**值复制**，改变原切片的值不会影响新切片
3. 等号复制为**指针复制**，改变原切片或新切片都会对另一个产生影响



- **append**

1. 值传递，切片本身是一个 struct 结构，参数传递时会发生值拷贝
2. 使用append的切片的**底层数组相同**，所以建议append追加后的新切片赋值给原切片
3. 或使用**copy函数**



**深拷贝**和**浅拷贝**

浅拷贝：

- 对于**值类型** 是**完全拷贝一份相同的值**

- 对于**引用类型** 是**拷贝其地址**，也就是拷贝的对象修改引用类型的变量同样会影响到源对象

深拷贝：

- 任何对象被完完整整拷贝一份
- 拷贝对象与被拷贝对象**不存在任何联系，不会互相影响**

## 高级操作

### 序列化

**JSON序列化(JavaScript Object Notation)**

- 保存JS对象的方式，`"key1": value1, "key2": value2`
- go语言数据 —> JSON格式字符串

```go
import "encoding/json"

data,err := json.Marshal(c1) // 序列化后，前端可直接识别
// 打印时:data为16进制编码, string(data)可见字符串
```

**反序列化**

- JSON格式字符串—> go语言数据

```go
jsonStr:=`{"Title":"H","Students":[{"ID":0,"Name":"stu0"},{"ID":1,"Name":"stu1"}]}`
var c2 class
err = json.Unmarshal([]byte(jsonStr), &c2) // 字节数据, 传入指针才能更改
```

### 接口

- 一种抽象类型，同一类型可有多个接口，接口可嵌套

**定义接口**

```go
type interface_name interface {
	func1(args) string
    Serve(c context.Context, conn network.Conn) error
	...
}
```

**实现接口**

```go
type Person struct {
	Name string
}

func (p Person) interface_name() string { // 值接收者
	xxx
}
func (a *Animal) interface_name() string { // 指针接收者
	xxx
}
```

**空接口**

没有定义任何方法的接口，空接口类型的变量可以存储任意类型的变量

```go
var x interface{}
x ="hello"
x = 10
x = false // 皆可
```

**类型断言**

```go
if str, ok := x.(string); ok {
    fmt.Println("x is a string", str)
} else {
    fmt.Println("x is not a string")
}
```

### 网络编程

```go
client := &http.Client{}
var data = strings.NewReader(`{"key1":"value1"}`)
req, err := http.NewRequest("POST", "url", data) // 创建请求
req.Header.Set("Key", "value")
resp, err := client.Do(req) // 发起请求
defer resp.Body.Close()
bodyText, err := io.ReadAll(resp.Body) // 读取请求响应
```

### 并发

- `go`启动新goroutine线程，环境在多个goroutine间多路复用，

```go
for { // 主函数循环可继续执行，不会阻塞
    go func(xx)
}
```

**可取消上下文**

```go
ctx, cancel := context.WithCancel(context.Background()) 
// 创建可取消的子上下文ctx及取消函数cancel, cancel()可放于goroutine中, 可取消ctx, 基于ctx的上下文也取消

<-ctx.Done() // 等待上下文取消，关闭通道
```



## 算法方法

### 子串

两层循环

```go
for start := 0; start < len(a); start++{
	for end := start; end > 0; end--{
		//每一个子串的操作
	}
}
```

### 滑动窗口

单调队列+双端队列，队列维护数组的索引，保证索引对应数组的元素单调

### 动态规划

找子问题，可以连接前面的问题的关系

### 轮转

- (i + 轮转数) % 数组长
- 先逆置，再对前k个逆置，对后m个逆置

### 反转链表

```go
//pre 结点Next初始化为nil，即空结点

for cur != nil{
    next = cur.Next      // 将 next 指向当前节点的下一个节点
    cur.Next, pre, cur = pre, cur, next // 反转当前节点的指针方向，同时更新 pre
}
//最终pre为头
```

## 开发

### 中间件

```go
// 预处理 + 后处理, 路由上可注册多个Middleware
func Middleware (args..){
	// pre-handle
	Next()
	// after-handle
}
```


