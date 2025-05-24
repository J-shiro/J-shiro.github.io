# C++


## 环境

### 编译

- `gcc`主要编译C语言，对于C++代码只编译而不自动链接C++标准库，需要使用`-lstdc++`指定
- `g++`专门编译C++代码，自动链接C++标准库

```bash
./a.out <infile> outfile # 文件重定向, infile文件中为输入
```



## 基础

### 关键字

**extern**：只声明变量，由外部定义

**explicit**：禁止隐式转换，即不自动将 int 转换为 string

**类型限定词**

- **volatile**：告诉编译器变量可能会被程序外部影响并改变，不进行优化
- **mutable**：只在类的成员变量中使用，mutable 成员可在 const 成员函数中修改

### 宏

**int型最大值最小值**

```c++
INT_MAX, INT_MIN // limits.h
```

**预定义宏**

```c++
__LINE__ ; // 程序编译时当前行号
__FILE__ ; // 程序编译时当前文件名
__TIME__ ; // 被编译时间
```



### 域

显示访问全局变量：`::a`

### 类

类的成员变量：`xxx_`

参数：`xxx`

**友元类**

类B的所有成员函数都是类A的友元函数，能存取类A的私有成员和保护成员

```C++
class A
{
    public:
        friend class B;
};
```

## 类型

**引用**：必须初始化





### 模板

```c++
template<typename T>
inline T const& func(T const &arg){
	return T;
}

template<typename type> ret-type func-name(parameter list); // 函数模板
template<class type> class class-name{};// 类模板 type 是占位符类型名

// 调用
cout << func<int>(1);// 不输入<int>由编译器自己判断
```

同样适用于类，类模版实例化需输入`<type>`告诉编译器类型

### 数组

```c++
// 动态分配数组
int* array = new int[num];   // 不初始化为0
int* array = new int[num](); // 初始化为0

delete[] array;

// 创建静态数组
int arr[num];
```

### 矩阵

二维数组，(n+1) * (m+1) 矩阵

```c++
vector<vector<bool>> f(n + 1, vector<bool>(m+1), -1);
//矩阵f, n+1 行, 每行初始化为vector<bool>(m+1) 即 m+1 列, 每个初始化为-1
```



### 结构体

**定义**

```c++
struct animal {
	int num;
	
	animal(int n): num(n){} //构造函数
    bool operator < (animal a) const{ // 重载函数
        return xxx;
    }
};

animal a(1);
```

```c++
const int N = 1000;
struct Q {
  int x;
  int y;
} que[N];

que[idx] = {t.x, t.y};
```



### 字符串

**原始字符串**：`R"(xxxx)"`，可以插入任何字符串而不作任何转义

- 库类型`std::string`，可变长字符序列

动态分配

```c++
// 动态分配一个空字符串对象
std::string *error = new std::string("");


```

**初始化**

```c++
string s("Hello");
string s1("hello", 3); // hel
string s2("hello", 2, 2); // start, size : ll
string s3(5, 'a'); // aaaaa
string s4({'a','b','c'}); // abc
```

```c++
s1.assign(s2); // s1 = s2
s1.assign("h"); // s1: h
s1.assign("hello", 3); // s1: hel
s1.assign(3, 'x'); // s1:"xxx"
s1.assign({'a','b'}); // s1: "ab"
```

**长度**

```c++
int n = s.size(); // s.length()
int c = s.capacity(); // 存储空间大小

s.reserve(num); // num < capacity 不改变, > capacity 则容量改变
s.shrink_to_fit(); // 压缩存储空间大小

s.resize(20, 'x'); // 重置大小为20, 不够填充'x', 默认0
```

**迭代器访问**

```c++
for(string::iterator it = str.begin(); it != str.end(); ++it){
	*it = ' '; // 更改值
}

string n;
for(char &itr : n){
    itr--; // 字符减一
}
```

**取值**

```c++
s.front(); // 第一个字符
s.back(); // 最后一个字符
```

**插入**

```c++
s.insert(s.begin(), ' '); // 开头插入空格
s.insert(2, 3, 'x'); // 在索引2处插入3个'x'
s.insert(3, "hello"); // 在索引3处插入"hello"

s.push_back('z'); // 末尾加入元素
s.append("xx"); // 末尾加入string字符串

string str = str1 + str2; // 拼接
```

**获取一行字符串**

```c++
while(getline(cin, str)); // 字符串中可包含空格
getline(cin, s, ';'); // 停止界定符
```

**转换为cstring**

```c++
str = "abc";
str.c_str(); // "abc\0"
str.data(); // "abc"
```

**number转换为string**

```c++
s = to_string(8); // 2.3e7
```

**string转换为number**

```c++
s = "190";
int i = stoi(s); // 190

s = "190 hello";
size_t pos;
i = stoi(s, &pos); // i:190 pos=3指向非number
// stol:to long, stod: to double, stof: to float
```

**查找**

```c++
size_t found = str.find("xx"); // 找不到返回string::npos, 找到返回下标
found = s.find("u", 2, 4); // 从索引2开始找字符串前4的子串

s.find_first_of("abc");
s.find_first_not_of("abc");
s.find_last_of("abc");
```

**删除**

```c++
// 去除字符串前后空格
str.erase(0, str.find_first_not_of(" ")); // 找不到返回string::npos
str.erase(str.find_last_not_of(" ") + 1);

str.erase(start, size);
str.erase(itr, itr+5);
str.pop_back();

str.clear(); // 清空元素
```

**交换**

```c++
s1.swap(s2); // 交换2个字符串
swap(str[0], str[2]); // 交换2个字符
```

**替换**

```c++
str.replace(2, 3, "re"); // 从索引2开始的3个元素更改为"re"
str.replace(2, 3, 4, 'y'); // 从索引2开始的3个元素被替换插入4个'y'
replace(str.begin(), str.end(), 'e', ' '); // 替换字母
```

**比较**

```c++
if(str >= "10"); // 代表数字字符串可直接比较

// 相等返回0, 不匹配的第一个字符值低或字符匹配但字符串短<0, 不匹配第一个字符值大或字符串长>0
int ret = s1.compare(s2);
s1.compare(start, num, s2); // s1从start开始与s2比较num个字符
```

**子串**

```c++
sub_str = str.substr(2, 3); // 从索引2开始的3个字符拷贝
```

**拷贝**

```c++
s = "abcdefg"
char buf[20];
size_t len = s.copy(buf, 3); // buf: abc, len=3
len = s.copy(buf, 4, 2); // buf: cdef, len=4 从索引2开始拷贝4个
```



### 链表

**结构体**

```c++
typedef struct ListNode
{
    int val;
    ListNode *next;
    ListNode(int x) : val(x), next(nullptr) {}
    ListNode() : val(0), next(nullptr) {}
    ListNode(int x, ListNode *next) : val(x), next(next) {}
};

void printLinkList(ListNode *head)
{
    ListNode *current = head;
    while (current != nullptr)
    {
        std::cout << current->val << " -> ";
        current = current->next;
    }
    std::cout << "nullptr" << std::endl;
}

ListNode *initLinkList(int arr[], int n)
{
    if (n == 0)
    {
        return nullptr;
    }

    ListNode *head = new ListNode(arr[0]);
    ListNode *current = head;

    for (int i = 1; i < n; ++i)
    {
        current->next = new ListNode(arr[i]);
        current = current->next;
    }

    return head;
}
```

**类**

```c++
class ListNode {
public:
    int val; // 节点的值
    ListNode *next; // 指向下一个节点的指针

    ListNode(int x) : val(x), next(nullptr) {} // 构造函数
    ListNode(int x){
        xxxx;
    }
};
```

**创建**

```c++
ListNode *temp = new ListNode(0), *cur = temp;	//虚拟头结点temp, cur指向temp

cur->next = new ListNode(l->value);			   	//创建一个新链表
```

**判断指针是否为尾**

```c++
while(ptr->next)
```

**倒数第n个结点**

快慢指针，使两指针移动相差n，快指针到结尾，则慢指针在倒数第n+1个结点



## 数据结构容器

### 数组

**动态数组vector**

**定义**

```c++
vector<type> name;

vector<int> pos(128, -1);// 初始化ASCII码共128个元素，每个元素值为-1

vector<pair<int,int>> tint; //每组为一对int型的数组
tint.emplace(xx, xx);
// 取数 tint[i].first, tint[i].second ...
vector<int> a({1,2,3});
```

**比较**

```c++
vector<int> xx(25, 0);
vector<int> yy(25, 0);

xx == yy; // 可直接比较
```

**判空**

```c++
vector.empty()
```

**元素个数**

```c++
vector.size()
```

**增删**

```c++
vector.push_back({xx,xx,xx})
vector.pop_back()
```

**清空**

```c++
vec.clear()
```

**拷贝构造**

```c++
vector<type> vec2(vec);
```

**设置大小及内容**

```c++
vec.resize(size, 0); // 0为填充数据
```

**交换两个vector容器内容**

```c++
vec2.swap(vec);
```

**首元素**

```c++
vector<int>::iterator it = vector.begin()// 返回迭代器
```

**尾元素**

```c++
vector.end()// 返回置迭代器，最后元素的下一个位
```

首尾半开放：**[begin, end)**

**迭代器**

```c++
vector<type>::iterator it;
cout << *it << endl; //取值
```

**取数**

```c++
vec[1]
vec.at(1) // 若越界会抛出异常
```

**遍历访问**

```c++
for (auto it : vec)
    cout << it << endl;
// 遍历，it不需要提前声明，vec为vector<type>
```

**修改**

```c++
int *p = &vec[0]; // 赋值p为第一个值的内存地址
p[1] = 6; // 改变vec值
```

**静态数组array**

```c++
array<int, 3> a = {1,2,3};
a.begin();
a.end();
a.size();
a.swap();
```

**动态内存**

```c++
double * pvalue = NULL;

pvalue = new double; // 堆上分配 double 类型空间，地址赋值给 pvalue
delete pvalue; // 释放单个对象

pvalue = new char[20]; // 数组分配， pvalue 指向一个数组
delete [] pvalue; // 释放数组对象

// 对象
Type_name* my_TypeArray = new Type_name[4];
delete [] my_TypeArray; // 删除数组
```

### 队列

**queue**

**定义**

```C++
queue<type> q; // 定义
```

**初始化**

```c++
queue<tuple<int, int, int>> q;
q.emplace(x, x, x); // 容器内直接构造元素
auto [x, y, time] = q.front(); // 接收元素
```

**基础操作**

```c++
q.empty() // 判空
q.size() // 元素个数
q.front() // 队列头
q.back() // 队列尾
q.pop() // 删除
q.push() // 添加
```

**deque双端队列**

```c++
deq.push_front(2); // 前插入
deq.push_back(3); // 后插入
```

**priority_queue优先队列**

```c++
priority_queue<type> pq; // 大根堆
priority_queue<type, vector<type>, greater<type>> name; // 小根堆
/* struct cmp{
		bool operator() (ListNode* a, ListNode* b){
			return a->val > b->val;
		}
	}
*/
```

**访问**

```c++
heap.push(x) // 增加
heap.empty() // 判空
heap.top() // 头元素
heap.pop() // 弹出头元素
```



### 链表

**list双向链表**

**初始化**

```c++
using listnode = std::pair<int, int>;
using listptr = typename std::list<listnode>::iterator;

std::list<listnode> linklist;

list<int> li = {1, 2, 3};
```

**插入**

```c++
list<int>::iterator itr = find(l.begin(), l.end(), 2); // itr->2
list.insert(itr, 8); // 向itr指向值前方插入8
```

**增删**

```c++
// push_front push_back
l.erase(itr); // 删除itr指向值
linklist.pop_back();
linklist.push_front({key, value});
```

**遍历**

```c++
linklist.begin();
for (auto it = mylist.begin(); it != mylist.end(); ++it){
	cout << *it << " ";
}
cout << endl;
```

**移动**

```c++
linklist.splice(linklist.begin(), linklist, listptr->second);
// arg1: 目标位置; arg2: 源链表，可为自己, arg3: 要移动的元素，迭代器指向的元素
```



### 集合

- **set**：红黑树实现，自动排序，<>接收2参数：元素类型，比较器类型，每个值唯一，值不可修改
- **multiset**：允许重复值，值不可修改
- **unordered_set**：无序集合

**定义**

```c++
set<int> myset;
set<int, less<int>> s;
```

**插入**

```c++
pair<set<int>::iterator, bool> ret;
ret = myset.insert(2); // 若已有2，返回（it->2, false)
// ret.first, ret.second 迭代器可通过此获取值
```

**查找**

```c++
set<int>::iterator it;
it = myset.find(2);
```

**删除**

```c++
myset.erase(it);
myset.erase(value);
```

**无序集合**

```c++
unordered_set<int> aset;
aset.insert(xx);

// 检查
unordered_set<string>::const_iterator it = myset.find("hello");
if(it != myset.end())
    cout << *it << endl;
```

**接口**

```c++
myset.load_factor(); // 装载因子
myset.bucket(x); // x的索引
myset.bucket_count(); // 索引总数
```

**数组转集合**

```c++
unordered_set<int> us(nums.begin(), nums.end());
us.contains(xxx) // 包含
```



### 哈希表

- 键值对存储 pair类型，map
- multimap：允许重复值，multimap和map的键不允许修改

**定义**

```c++
map<type t1, type t2> mp;
unordered_map<type1, type2> hp; // 无序哈希表
hp = {
	{x1, x2}, {y1, y2}
}; // 初始化
```

**状态**

```c++
mp.empty(); // 判空
mp.size(); // 元素个数
mp.begin(); // 返回迭代器
mp.end(); // 最后一个元素的下一位
mp.reserve(100); // 预留100大小

// 取值
(*it).first;// 键
(*it).second;// 值
// *it的类型: pair<const type1, type2>
```

**增删**

```c++
map.insert(pair<type, type>(x1, x2)); // 添加，不可修改
map.insert(make_pair(x1, x2));

mp['a'] = "aa"; // 修改或插入

map.erase(); // 删除
map.erase(key);
map.clear(); // 清空
```

**查找**

```c++
mp.find(first, last, val); // [first, last)
if(mp.find(val) != mp.end()){找到val}
```

```c++
// 检查unordered_map中是否存在给定键的元素value
unordered_map<int, string> umap;
if(umap.count(1)){...}
```



**遍历**

```c++
for(const auto& pair : mp){
	cout << pair.first << ": " << pair.second << endl;
}

for(const auto &[x, indices] : xmap)
```



### 栈

```c++
#include<stack>
stack<int> sk
```

**状态**

```c++
sk.empty(); //是否为空
sk.size();  //元素个数
```

**增删**

```c++
sk.push(); //添加
sk.pop();  //删除
```

**访问**

```c++
sk.top(); //栈顶元素
```

### 二叉树

```c++
struct TreeNode{
	type value;
	TreeNode *leftChild;
	TreeNode *rightChild;
};
```

### 大根堆

```c++
make_heap(vec.begin(), vec.end());

pop_heap(vec.begin(), vec.end()); // 移除最大元素
vec.pop_back(); // 移除最大元素

push_heap(vec.begin(), vec.end()); // 加入新值
vec.push_back();

// 堆排序
sort_heap(vec.begin(), vec.end());
```

### 并查集

```c++
class UnionSet{
private:
	vector<int> parent; // 父结点
    vector<int> deep; // 树深度
public:
    UnionSet(int n){
        parent.resize(n);
        deep.resize(n, 0);
        for(int i = 0; i < n; ++i){
            parent[i] = i;
        }
    }
    int find(int x){
        if(parent[x] != x){
            parent[x] = find(parent[x]); // 递归找根
        }
        return parent[x];
    }
    void union(int x, int y){
        int rootX = find(x);
        int rootY = find(y);
        if(rootX != rootY){
            if(rank[rootX] < rank[rootY]){
                rank[rootX] = rootY;
            }else if(rank[rootX] > rank[rootY]){
                rank[rootY] = rootX;
            }else{
                rank[rootX] = rootY;
                rank[rootY]++;
            }
        }
    }
}
```



## 基本操作

**运算符**

```c++
(a < b) ? (func1, func2) : (func3, func4)
// 逗号运算符(表达式1, 表达式2) 将会执行表达式1和表达式2，整个表达式的值为表达式2的值
```

**取模**

```c++
((x%p)+p)%p // 将任意值转移到0~p之间
```

**数字字符char转为数字**

```c++
str - '0'
```

**字母字符转为数字**

```c++
str - 'A'
```

**初始化数组**

```c++
memset(str, 0, sizeof(str));
```

**检查字符是否为十进制数字字符**

```c++
isdigit()
```

**最值**

```c++
max(a,b)
min(a,b)
```

**查询最大(小)值所在的第一个位置**

```c++
max_element(begin, end)
min_element(begin, end)
  
int ans = *max_element(dist.begin(), dist.end());
// 获取到指向某个元素的迭代器，解引用*获取该元素
```

**整型十六进制**

```c++
printf("%#x", n)
```

**整数求对应ASCII码的符号**

```c++
(char)n
```

**字符求对应ASCII码值**

```c++
int(string[i])
```

**整型转换为二进制字符串**

```c++
bitset<8> binary(int_number); // 8表示二进制串的位数
binary.to_string();
```

**二进制字符串转换为整型**

```c++
bitset<5> tempbit(string_value); // 先转换为bitset
int tempdec = (int)tempbit.to_ulong(); // 再转换为整型
```

**输入格式**

```c++
#include<bits/stdc++.h>

while(scanf("%d", &h) != EOF){
	xxx;
}
```

**合并有序序列**

```c++
// 都需要有序
merge(vec.begin(), vec.end(), // 范围1
     vec2.begin(), vec2.end(),// 范围2
     vec_out.begin());		  // 输出数组


// 原序列上合并两个有序的子序列
vector<int> vec = {1,2,3,4,1,2,3,4};
inplace_merge(vec.begin(), vec.begin()+4, vec.end()); // 1,1,2,2,3,3,4,4
```

**类型转换**

```c++
// void * 指针转换为具体类型指针
auto *xxx = static_cast<some_type *>(voidPtr);
// xxx 强制转换为 type 类型
reinterpret_cast<type>(xxx);
```

**异常处理**

```c++
throw "xxx"

try{
	xx
}catch( ExceptionName e){
	xx
}catch(const char * msg){
	cerr << msg << endl;
}cache(std::exception &e) {
  WARN("xxx", e.what());
}
```

**计时**

```c++
auto start = std::chrono::high_resolution_clock::now();
auto end = std::chrono::high_resolution_clock::now();
auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
std::cout << duration.count() << std::endl;
```

**断言**

```c++
ASSERT(
        xxx,
        "'{0}', {1}",
       	arg1,
        arg2;) // arg1 替换{0}, arg2替换{1}
```



## 库

### 标准库

**std::move**

```c++
// 显式移动某个对象资源，避免不必要复制
std::string a = "hello";
std::string b = std::move(a); // 移动构造
// 此时 a 被“清空”，b 拥有原来 a 的资源
```

**判断**

```c++
std::isprint(ch) // 是否为可打印字符
std::isspace(ch) // 是否为空格
```

**std::type_index**

```C++
// 运行时类型识别（RTTI）
std::type_index int_idx = std::type_index(typeid(int));
int_idx.name(); // 获取类型名
// 获取表达式或类型的类型信息
typeid(type)
```

**std::is_base_of**

````c++
std::is_base_of<A, B>::value // 查看B是否继承自A，即B是A的派生类
````

**输入输出**

```c++
setw(2)
setfill('0')
```



### gflags

用于解析输入命令行变量

```C++
DEFINE_int32(var_name, 默认值, 描述);
// 使用
gflags::ParseCommandLineFlags(&argc, &argv, true);

// 访问时
FLAGS_var_name

// 在其他文件，跨文件访问调用
DECLARE_string(var); // 类似于 extern
```

### libconfig

```C++
libconfig::Config &cfg // 加载配置文件
cfg.readFile("xxx.cfg");// 读取文件
cfg.lookup("xxx.xxx") //

libconfig::Setting root = cfg.getRoot(); // 获取根Setting

// 修改配置
root["xxxx"] = xxx;
root[i] // 获取子元素

// 写入文件
cfg.writeFile("xxx.cfg");

root.isGroup() // 类似结构体 {}
root.isArray() // 同类型元素有序集合 []
root.isList() // 不同类型元素有序集合 ()
root.isScalar() // 标量
```

### chrono

```C++
std::chrono::nanoseconds var; // 纳秒
std::chrono::steady_clock::now(); // 当前时间
std::chrono::steady_clock::time_point()::min(); // 时间点类型可表示的最小值："从未发生"初始状态
```

## 高级操作

### 指针

`std::unique_ptr`：智能指针，实现独占所有权资源管理模式，动态分配内存资源只被一个指针所拥有

### 排序

适用于vector，deque，array等可随机访问结构

```c++
sort(vec.begin(), vec.end(), compare_function); // 通过compare_function排序
partial_sort(vec.begin(), vec.begin()+5, vec.end(), greater<int>()); // 获取最大前5个值

sort(arr.begin(), arr.end(), greater<int>()); // 升序
sort(arr.begin(), arr.end(), less<int>()); // 降序

// compare函数
bool compare_function(data a, data b) {
    if(xxx) {
        return a.val < b.val;
    }
    return a.val > b.val;
}
```

**将满足某条件值移到最前**

```c++
bool lessThanten(int i){
	return (i < 10);
}
partition(vec.begin(), vec.end(), lessThanten);
stable_partition(vec.begin(), vec.end(), lessThanten); // 保持原有顺序
```

**逆序**

```c++
reverse(str.begin(), str.end());
```

### 查找

**二叉查找**

```c++
bool found = binary_search(vec.begin(), vec.end(), 9); //查找9是否在

bool found = includes(vec.begin(), vec.end(), // s和vec均有序
                     s.begin(), s.end());// 若s所有元素被包含在vec中返回true

itr = lower_bound(vec.begin(), vec.end(), 9); // 找到9可以被插入保持有序的第一个位置
itr = upper_bound(vec.begin(), vec.end(), 9); // 找到9可以被插入保持有序的最后一个位置

pair_of_itr = equal_range(vec.begin(), vec.end(), 9); // 返回第一和最后的位置对
```

### 迭代器操作

- 范围半开放：[begin, end)

**计数**

```c++
int n = count(vec.begin(), vec.end(), val); // 返回val个数
int n = count_if(vec.begin(), vec.end(), [](int x){return x<10;}); //返回满足条件的个数
```

**比较**

```c++
itr = max_element(vec.begin(), vec.end()); // 返回第一个最大值*itr
itr = max_element(vec.begin(), vec.end(), [](int x, int y){return (x%10)<(y%10);});
// 返回满足比较方法条件的第一个最大值

pair_of_itr = minmax_element(vec.begin(), vec.end(), [](int x, int y){return (x%10)<(y%10);}); // 返回一对迭代器
```

**线性搜索**

```c++
itr = find(vec.begin(), vec.end(), val); // 查找val,返回找到值的下一位的索引
itr = find_if(vec.begin(), vec.end(), [](int x){return x>80;});
itr = find_if_not(vec.begin(), vec.end(), [](int x){return x>80;});
```

```c++
itr = search_n(vec.begin(), vec.end(), count, val); // 查找连续count的val
distance(vec.begin(), itr); // itr的索引, 获取两者间距离

// 强行转换为 int 型: static_cast<int>(distance(nums.begin(), itr))

// 查找子集
itr = search(vec.begin(), vec.end(), sub.begin(), sub.end());
itr = find_end(vec.begin(), vec.end(), sub.begin(), sub.end()); // 查找最后一个子范围
```

```c++
// 查找到items中任何一个均可
itr = find_first_of(vec.begin(), vec.end(), items.begin(), items.end());

// 联结搜索, 默认搜索连着的相同的
itr = adjacent_find(vec.begin(), vec.end(), [](int x, int y){return x==y*4});
```

**比较**

```c++
if(equal(vec.begin(), vec.end(), vec2.begin())){} // 相同
if(is_permutation(vec.begin(), vec.end(), vec2.begin())){}   // 相同元素不同顺序
pair_of_itr = mismatch(vec.begin(), vec.end(), vec2.begin()) // 找到第一个不同
lexicographical_compare(vec.begin(), vec.end(), vec2.begin(), vec2.end()); // 一比一比较小于
```

**检查**

```c++
is_sorted(vec.begin(), vec.end())		 // 检查是否有序
is_sorted_until(vec.begin(), vec.end()); // 直到...均有序
is_partitioned(vec.begin(), vec.end(), [](int x){return x>80;}); // 检查是否以该条件区分开
is_heap(vec.begin(), vec.end())			 // 检查是否为堆
is_heap_until(vec.begin(), vec.end())    // 直到...前为堆
```

```c++
// 检查是否 所有/任何一个/无 元素满足条件
all_of(vec.begin(), vec.end(), [](int x){return x>80;});
any_of(vec.begin(), vec.end(), [](int x){return x>80;});
none_of(vec.begin(), vec.end(), [](int x){return x>80;});
```

**拷贝**

```c++
copy(vec.begin(), vec.end(), vec2.begin());
copy_if(vec.begin(), vec.end(), vec2.begin(), [](int x){return x>80;});

copy_n(vec.begin(), count, vec2.begin()); // 拷贝count个
copy_backward(vec.begin(), vec.end(), vec2.end());// 从后拷贝进入
```

**移动**

```c++
// 若为string可能原vec被移动的就消失了，若是int则直接类似于拷贝
move(vec.begin(), vec.end(), vec2.begin()); 
move_backward(vec.begin(), vec.end(), vec2.begin());
```

**转移**

```c++
transform(vec.begin(), vec.end(), // vec3[0] = vec[0] - 1
         vec3.begin(),
         [](int x){ return x-1;});

transform(vec.begin(), vec.end(),
          vec2.begin(),
          vec3.begin(),
          [](int x, int y) {return x+y;}); // vec3[0] = vec[0] + vec2[0]
```

**交换**

```c++
swap_ranges(vec.begin(), vec.end(), vec2.begin()); // 双向拷贝
```

**填充**

```c++
fill(vec.begin(), vec.end(), val); // 填充val
fill_n(vec.begin(), count, val);   // 填充count个val

generate(vec.begin(), vec.end(), rand); // 生成
generate_n(vec.begin(), count , rand);
```

**替代**

```c++
replace(vec.begin(), vec.end(),	// 数据范围
       6,						// 原始值
       9); 						// 新的值

replace_if(vec.begin(), vec.end(),
          [](int x){return x>80;},
          9);

replace_copy(vec.begin(), vec.end(), // 源
            vec2.begin(),		 	 // 目的
            6,						 // 原始值
            9);					     // 新值
```

**移除**

```c++
remove(vec.begin(), vec.end(), 3); // 移除所有的3
remove_if(vec.begin(), vec.end(), [](int x){return x>80;}); // 条件删除
remove_copy(vec.begin(), vec.end(), 
           vec2.begin(),
           6);// 移除所有的6，剩余值拷贝到vec2中
```

```c++
unique(vec.begin(), vec.end()); // 移除连续的相同的元素
unique(vec.begin(), vec.end(), less<int>()); // 移除比前一个元素大的元素
unique_copy(vec.begin(), vec.end(), vec2.begin());
```

**倒置**

```c++
reverse(vec.begin(), vec.end());
reverse_copy(vec.begin(), vec.end(), vec2.begin());
```

**旋转**

```c++
rotate(vec.begin(), vec.begin()+3, vec.end());
// 1 2 3 4 5 6 7
// 4 5 6 7 1 2 3
```

**打乱**

```c++
random_shuffle(vec.begin(), vec.end());

shuffle(vec.begin(), vec.end(), default_random_engine());
```

**更改**

```c++
// vector, deque, array等随机访问迭代器可对迭代器直接加减,比较
vector<int>::iterator itr; // 可以直接用 auto 代替
++itr;
if(itr2>itr2) ...;
itr = itr + 2;

// list, set/multiset, map/multimap等双向迭代器只可自加减
++itr;
--itr;

// forward_list等单向迭代器只可自增，不可自减
++itr;

int x = *itr;
*itr = 100; // 更改值

advance(itr, 5); // 等价于 itr+=5
std::advance(iterator, 2); // 迭代器前移2个位置
std::distance(vec.begin(), iterator); // 获取索引
```

**流迭代器**

```c++
vector<string> vec4;

// 从标准输入读取字符串到vec4
copy(istream_iterator<string>(cin), // 起始位置
     istream_iterator<string>(),    // 结束位置
     back_inserter(vec4));
// 使用 back_inserter 适配器将读取的字符串插入到 vec4 的末尾

// 将 vec4 中的字符串输出到标准输出，以空格分隔
copy(vec4.begin(), vec4.end(),
     ostream_iterator<string>(cout, " "));
```

```c++
// 不经过中间容器
copy(istream_iterator<string>(cin),
     istream_iterator<string>(),
     ostream_iterator<string>(cout, " ")); 
```

**插入迭代器**

```c++
vector<int> vec1 = {4, 5};
vector<int> vec2 = {12, 14, 16, 18};
vector<int>::iterator it = find(vec2.begin(), vec2.end(), 16);

insert_iterator<vector<int>> iitr(vec2, it);
copy(vec1.begin(), vec1.end(), // source
     iitr);                    // destination
                               // vec2 = {12, 14, 4, 5, 16, 18}
```

**逆向迭代器**

```c++
vector<int> vec = {4,5,6};
reverse_iterator<vector<int>::iterator> ritr;
for(ritr = vec.rbegin(); ritr != vec.rend(); ritr++){
	cout << *ritr << endl;// 6,5,4
}
```

**常量迭代器**

```c++
set<int>::const_iterator citr; // 只读不可改
for_each(myset.cbegin(), myset.cend(), MyFunction); // c++11 对每个元素执行MyFunction
```

### 函数

**函数对象**：重载了operator()类的实例

**内置函数对象**

```c++
int x = multiplies<int>()(3, 4); // x = 3 * 4
if(not_equal_to<int>()(x, 10))   // if(x!=10)
```

**自定义函数对象**

```c++
// 构造函数对象，用于将元素乘以10
class MultiplyBy10 {
public:
    int operator()(int x) const {
        return x * 10;
    }
};

std::vector<int> nums = {1, 2, 3, 4, 5};
std::vector<int> result;
// 使用 std::transform 和自定义函数对象 MultiplyBy10 将 nums 中的每个元素乘以10
std::transform(nums.begin(), nums.end(),   // 源
               std::back_inserter(result), // 目的
               MultiplyBy10());
```

**绑定器**：将函数或函数对象的某些参数绑定为固定值

```c++
transform(myset.begin(), myset.end(),		// 源
         back_inserter(vec),				// 目的
         bind(multiplies<int>(), placeholders::_1, 10));// 绑定器
		 // placeholders::_1 占位符，表示 transform 传入的每个元素
		 // 绑定了multiplies的第2个参数为10
```

**函数转化为函数对象**

```c++
double Pow(double x, double y){
    return pow(x, y);
}

auto f = function<double (double, double)>(Pow);
```

**lambda函数**

```c++
[] (int x){return (x>20)||(x<5)};
```

**构造函数**

```c++
NonCopyable() = default;  // 允许默认构造
NonCopyable(const NonCopyable&) = delete;  // 禁止拷贝构造
NonCopyable& operator=(const NonCopyable&) = delete;  // 禁止复制赋值
```



### 输入输出流

**创建支持流的类**

```c++
 struct Dog {
 	 int age_;
     string name_;
 };

ostream& operator<<(ostream& sm, const Dog& d){
    sm << "name is " << d.name_ << " and age is " << d.age_ << endl;
    return sm;
}

istream& operator>>(istream& sm, Dog& d){
    sm >> d.name_;
    sm >> d.age_;
    return sm;
}

int main(){
    Dog d{2, "Bob"};
    cout << d; // name is Bob and age is 2
    cin >> d;
}
```

**格式化数据**

```c++
cout.setf(ios::oct, ios::basefield); // 输出八进制
cout.setf(ios::hex, ios::basefield); // 输出十六进制
cout.setf(ios::dec, ios::basefield); // 输出十进制
cout.setf(ios::showbase); // 会输出几进制前的标识符: 0x, 0等
cout.unsetf(ios::showbase);

cout.width(10); // 宽度为10个字符
cout.setf(ios::left, ios::adjustfield); // 靠左
```

#### 文件流

**打开文件写**

```c++
ofstream of1("h.txt"); // 创建文件写 或 打开文件并清空原内容
ofstream of2("a.txt", ofstream::app); // append加入到原内容后

ofstream of3("b.txt", ofstream::in | ofstream::out); // 从中间加入内容
of3.seekp(10, ios::beg); // 将输出指针移动到begin的后10个字符处，覆写
of3.seekp(-5, ios::end); // 离end的前5个字符处
```

**文件位置指针**

```c++
std::ifstream fileobj("data.txt", std::ios::binary);
fileobj.seekg(n); // 定位到第 n 个字节
fileobj.seekg(n, ios::cur); // 读指针从 fileobj 当前位置后移 n 个字节
fileobj.seekg(n, ios::end); // 末尾前移 n 个字节
fileobj.seekg(0, ios::end); // 定位到结尾
```

**写入文件**

```c++
of <<  "hello" << endl; // hello
of << 233 << endl; // 233
of << bitset<8>(14) << endl; // 00001110
of << complex<int>(2,3) << endl; // (2,3)
```

```c++
ofstream of("x.txt");
of.put('c'); // 放一个字符到流
of.write(buf, 6); // buf中6个字符输出到流
```

```c++
cout << ends; // '\0'
cout << flush; // 清空流
cout << setw(8) << left << setfill('_') << 99 << endl; // 99______ 宽度为8，输出不足用_填充
cout << hex << showbase << 14; // 0xe 流格式为十六进制
```

**取整**

```c++
ceil()// 向上取整
floor()// 向下取整
```

**打开文件读**

```c++
ifstream inf("h.txt");
int i;
inf >> i; // 读一个字

std::string line;
while(std::getline(inf, line)) // 读一行
    xxx
```

**一行读取**

```c++
std::ifstream file;
file.open("xx", ios::out | ios::in); // 读写
cin.getline(data, 100);
file << data << endl;
file >> data;

```



```c++
ifstream inf("x.txt");
char buf[80];

inf.get(buf, 80); // 读80字符到buf
inf.getline(buf, 80); // 读80直到'\n'
inf.read(buf, 20); // 读20字符
inf.ignore(3); // 忽略3字符
inf.peek(); // 返回流顶部的字符
inf.unget(); // 返回一个字符给流
inf.putback('z'); // 返回一个字符'z'给流
inf.gcount(); // 返回字符流读出的字符数
```

**错误状态**

```c++
inf.good(); // 一切正常 goodbit=1
inf.bad();  // 不可恢复错误 badbit=1
inf.fail(); // 错误流操作 failbit=1 badbit=1
inf.eof();  // 文件结束 eofbit=1

inf.clear(); // 清除所有状态
inf.clear(ios::badbit); // 为错误flag设置新值 置1
inf.rdstate(); // 读状态flag
inf.clear(inf.rdstate() & ~ios::failbit); // 只清除failbit
```

**判断错误格式**

```c++
if(inf){} // 成功读
if(inf >> i){} // 成功读

inf.exceptions(ios::badbit | iOS::failbit); // 两者中任何一个置1，抛出异常
```

#### 字符串流

```c++
std::istringstream istr("12,");
int i;
char comma;

istr >> i >> comma; // i=12, comma=','

stringstream ss;

ss << 89 << "  Hex: " << hex << 89 << "  Oct: " << oct << 89;
cout << ss.str() << endl;  // 89  Hex: 59  Oct: 131

int a, b, c;
string s1;

ss >> hex >> a; // a = 137 = 0x89
ss >> s1;		// s1:"Hex:"
ss >> dec >> b; // b=59 读一个十进制的59

ss.ignore(6);
ss >> oct >> c; // c= 89 = 八进制的131
```

#### 缓冲区

```c++
cout << 34;
streambuf* pbuf = cout.rdbuf();
ostream myCout(pbuf);
myCout << 34; // 34输出到标准输出

myCout.setf(ios::showpos); // 显示正负数
myCout.width(20);
myCout << 12 << endl; //                  +12
```

```c++
ofstream of("hello.txt");
streambuf* origBuf = cout.rdbuf();
cout.rdbuf(of.rdbuf());
cout << "hello" << endl;  // hello.txt has "hello"

cout.rdbuf(origBuf);
cout << "bye" << endl; // stdout: bye
```

**流缓冲区迭代器**

```c++
istreambuf_iterator<char> i(cin);
ostreambuf_iterator<char> o(cout);

while(*i != 'x'){
    *o = *i;
    ++o;
    ++i;
}// stdin输入啥，stdout输出啥，遇x退出

copy(istreambuf_iterator<char>(cin), istreambuf_iterator<char>(), ostreambuf_iterator<char>(cout));// 和上面基本一样，除了遇x不退出
```

### 信号处理

```c++
signal(registered signal, signal handler); // signal: SIGINT
void signalHandler(int signum) { xxx }

// raise() 生成信号
int raise(signal sig);
rasise(SIGINT);
```

### 多线程

**基础值**

```c++
unsigned int n = std::thread::hardware_concurrency(); // 支持的并发线程数
```

**基础操作**

```c++
std::thread t = std::thread(&Class_name::Func, this);
std::thread t1(callable_func, args...);
t1.join(); // 等待线程完成
detach(); // 将线程与主线程分离，线程后台独立运行，主线程不再等待他

// Lambda 表达式内联定义线程执行代码
std::thread t2([](int args)) {
	func_content
}, arg);
```

**互斥量**

```c++
std::mutex mtx;
mtx.lock(); // 锁定互斥锁

// 访问共享资源
mtx.unlock(); // 释放互斥锁

std::lock_guard<std::mutex> lock(mtx); // 作用域锁，构造时锁定析构时解锁，自动锁定和释放
// 访问共享资源

std::unique_lock<std::mutex> ul(mtx);
// 访问或修改共享资源
// ul.unlock(); // 可选：手动解锁
```

**TLS**

- 线程局部存储：每个线程有自己数据副本，关键字，被其修饰的变量在每个线程中都有独立实例

```c++
thread_local int threadData = 0;
```

**传递方法**

```c++
// 值传递：参数传递
// 引用传递
func(int&xx){..}
std::thread t(func, std::ref(xx)); // 显式告诉std::thread为引用传递
```

**条件变量**

```c++
// 线程间协调，允许多个线程等待某条件发生，确保workerThread工作只能在mainThread中数据准备完毕才进行

#include <mutex>
#include <condition_variable>

std::mutex mtx;
std::condition_variable cv;
bool ready = false;

void workerThread() {
    std::unique_lock<std::mutex> lk(mtx);
    cv.wait(lk, []{ return ready; }); // 等待ready变为true条件
    // 当条件满足时执行工作
}

void mainThread() {
    {
        std::lock_guard<std::mutex> lk(mtx);
        // 准备数据
        ready = true;
    } // 离开作用域时解锁
    cv.notify_one(); // 通知一个等待的线程
}
```

**原子操作**

```c++
// 多线程下，要么完全执行，要么完全不执行
std::atomic<int> count(0);
count.fetch_add(1, std::memory_order_relaxed);
// fetch-and-add 操作，给count+1, arg2: 指定该操作的内存序列模型为"放松"内存序列
```

**线程间通信**

```c++
std::promise<int> p; // 可把一个值存储到共享状态中，承诺会在某个时刻写入一个 int 类型值
std::future<int> f = p.get_future(); // 可从共享状态中读取值

std::thread t([&p] {
    p.set_value(10); // 设置值，触发 future
});

int result = f.get(); // 获取值，阻塞当前线程，直到共享状态变为就绪，直到 p 调用 set_value 为止，取出值赋值给 result
```

### CMake

```cmake
cmake_minimum_required(VERSION xxxx) # 设置最低 CMake 版本要求
add_executable(xx dir/file) # 添加源代码文件
target_link_libraries(xx xx xx) # 添加依赖库到构建系统
set(CMAKE_C_FLAGS "-xx -xx") # 设置编译选项
include_directories(xxx/xxx) # 指定头文件搜索路径
```

## 语法

### 继承

```c++
class class2: public class {}
```

派生类可以访问基类中的public和protected成员；外部类只能访问类的public成员

### 多态

调用成员函数时，会根据调用函数的对象的类型来执行不同的函数

**虚函数**：关键字为virtual，派生类重写基类中定义的虚函数时，会告诉编译器不要静态链接到该函数，而是使用动态链接根据所调用的对象类型来选择调用的函数

```c++
// 重写
void func() const override { xxxx }
```

包含**纯虚函数**的类为抽象类，不能实例化，强制派生类提供具体实现

```c++
virtual int vfunc() = 0;
```

```c++
Base_class *ptr; // 基类指针
ptr = new Drive_class(); // 实例化派生类
delete ptr;
```



### 重载

在同一个作用域内，可以声明几个功能类似的同名函数，但是这些同名函数的形式参数（指参数的个数、类型或者顺序）必须不同

**重载运算符**

```c++
class_name operator + (const class_name &, const class_name &)
```

```c++
class Box
{
   public:
      // 重载 + 运算符
      Box operator+(const Box& b)
      {
         return xxx; // 调用为 B+A
      }
      void operator()(const Box& b) // 可以重载括号
      {
         cout << "x" << endl;// 调用为 B()
      }
}
```

