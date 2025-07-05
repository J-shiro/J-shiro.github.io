# CS106L


**CS106L 2019 FALL**

## Stream

[C++ core guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)

`istringstream`, `ostringstream`

```cpp
if (!getline(cin, line)) // 标准输入 cin 中读取一整行字符串，存入 line
	throw domain_error("Unable to get line from cin."); // 标准库异常，
istringstream iss(line); // 输入字符串流
iss >> result; // istringstream 中提取一个值，赋给 result

if(!(iss >> name >> year >> average)) throw "Invalid file format.";

fpos pos = oss.tellp() + streamoff(3);
oss.seekp(pos);
```

状态位，当流的状态位不是good时，流操作将无效

```cpp
iss.fail()
iss.good()
iss.eof()
iss.bad()
```

标准输入输出

```
cin
cout buffered
cerr unbuffered
clog buffered
```

`cin` 只会读到下一个空格处前

`cin.ignore()` 忽略一个字符

```cpp
getline(cin, name, '\n') # 读取直到\n 获取字符串，包含\n
```

文件读取

```cpp
string filename, line;
ifstream file(filename);
getline(file, line);
```

## Sequence Containers

**Lambda 函数**

```cpp
auto func = [](auto i) {return i*2}; // 编译器将识别出类型
```

**pair 对**

```cpp
pair<int, int> func() {
	return make_pair(a, b);
}
```

**结构体**

```cpp
struct Course {
	string code;
	vector<string> instructors;
}

// 遍历
void func(vector<Course>& courses) {
	for(auto& course : courses) {
		...
	}
}

// 初始化
Course test {"CS106L", {"A", "B"} };
```

容器 vector

```cpp
vector<int> a;
a.at(2); // 会进行越界检查，抛出异常
a[2]; // 不进行越界检查，不会抛出异常
```

容器 deque，双端队列

- 取数操作比 vector 慢
- 前端插入速度快

## Associative Containers

- map/set：键是按顺序排序的，遍历更快
- unordered map/set：根据键访问单个元素更快

```cpp
map<string, int> mp;
mp[word]; // 不存在时自动创建入口并默认初始化
mp.at(word); // 不存在时抛出异常

mp.count(word);
```

## Iterators

- 迭代器本身是一个内存地址

```cpp
vector<int>::iterator iter = myset.begin();

cout << *iter << endl; // 解引用读取值
++iter； // 移动迭代器

if(iter == myset.end()) return; // 判断结束
```

## Advanced Containers

**Multimap**

- 可以存储相同的键指向不同的值，基于红黑树实现
- 插入元素按照 key 排序，默认使用`std::less<Key` ，升序
- 无 `[] operator`
- `begin()` ：正向迭代器起始位置，最小key元素
- `rbegin()` ：反向迭代器起始位置，最大key元素

```cpp
// 添加
multimap<int, int> mm;
mm.insert(make_pair(3, 3));
mm.insert({3, 12});
mm.count(3); // 2
```

**pair 对**

```cpp
std::pair<string, int> p; // {"a", 1}
p.first = "a";
p.second = 1;
 
std::pair<string, int> p{"a", 1};
std::make_pair("a", 1);

// 结构化绑定
auto [x1, x2] = func(); // func 返回 std::pair<>
```

map 迭代器，指向 `std::pair`

```cpp
map<int, int>::iterator i = mp.begin();
cout << (*i).first << (*i).second << endl;
```

**查找**

```cpp
// std::find 比 std::cound 速度更快
auto it = std::find(vec.begin(), vec.end(), target);

// std::lower_bound(x) 返回 > x 的值
set<int>::iterator iter = mySet.lower_bound(2);
// std::upper_bound(x) 返回 >= x 的值
set<int>::iterator iter = mySet.upper_bound(3);
```

|  | [a, b] | [a, b) | (a, b] | (a, b) |
| --- | --- | --- | --- | --- |
| begin | `lower_bound(a)` | `lower_bound(a)` | `upper_bound(a)` | `upper_bound(a)` |
| end | `upper_bound(b)` | `lower_bound(b)` | `upper_bound(b)` | `lower_bound(b)` |

**迭代器类型**

- `Input`，`Output`，`Forward`，`Bidirectional`，`Random access`
- 共同特征
    1. 可从已存在迭代器创建
    2. 可使用`++`自增
    3. 可以使用`==`和`!=` 进行比较

**Input：**顺序单向数据结构，解引用只读【`find`，`count`，`input stream`】

**Output：**解引用只写【`copy` ，`output stream`】

**Forward：**多次遍历，解引用可读可写【`replace` ，`std::forward_list`】

**Bidirectional：**可**`--`** 后退【`reverse` ，`std::map`，`std::set` ，`std::list`】

**Random access：**可随意 + 或 - 任意数值【`std::vector`，`std::deque`，`std::string`，`pointer`】

## Templates

泛型编程

- 若类型不同，浮点型转换为整型，该隐式转换是编译时完成
- `auto`无法用于参数

```cpp
// 声明**模板函数**
template <typename T>  // T 是**模板参数**，告知编译器 T 是一个类型，尽量将 T 命名为更具信息的名称
pair<T, T> cmp(T a, T b) { // T 在调用函数时被替代
		// 引用 cmp(const T& a, const T& b) {
	xxx;
}

auto [s1, s2] = cmp<std::string>("a", "b"); // "a" 与 "b" 会从 c-string 转换为 std::string
```

## Templates and Functions

模板函数 - **课堂举例**

```cpp
// 迭代器只用于访问数据
template <typename InputIterator, typename DataType>
int countOccurences(InputIterator begin, InputIterator end,
										DataType val) {
	int count = 0;
	for (auto iter = begin; iter != end; ++iter) {
		if (*iter == val) ++count;
	}
	return count;
}
```

C++ 模板实例化过程中类型替换带来的编译错误

```cpp
vector<int> v1{1, 2, 3, 1, 2, 3};
vector<int> v2{1, 2, 3};
countOccurences(v1.begin(), v1.end(), v2.begin());
// DataType 替换为 vector<int>::iterator
// InputIterator 替换为 vector<int>::iterator
// 比较 *iter == val 时：int == vector<int>::iterator 导致报错
```

**说明：**模板函数实际上定义了每个模板参数必须满足的**隐式接口**，传入的模版参数必须支持函数所假设其具有的操作，否则，编译器就会出现很复杂的报错。

**C++20**引入**概念：对模板参数的`requirements` ，显示接口**

```cpp
template <typename It, typename Type>
	requires std::input_iterator<It> &&
             equality_comparable_with<iter_value_t<It>, Type>
int countOccurences(It begin, It end, Type val) {
	int count = 0;
	for(auto iter = begin; iter != end; ++iter) {
		if(*iter == val) ++count;
	}
	return count;
}
```

`input_iterator<It>` ：`It`必须满足**输入迭代器**要求，可读，可递增，多个拷贝共享同一位置

`equality_comparable_with<iter_value_t<It>, Type>` ：满足`*iter == val` 合法

**谓词 predicate**

- 接受一些参数并返回布尔值的函数

上述代码可以将描述更新为：**在元素范围内该元素满足了多少次[predicate]**

```cpp
template <typename InputIterator, typename UnaryPredicate>
int countOccurences(InputIterator begin, InputIterator end, UnaryPredicate predicate)
{
    int count = 0;
    for (auto iter = begin; iter != end; ++iter)
    {
        if (predicate(*iter))
            ++count;
    }
    return count;
}

template <typename DataType>
inline bool isLessThan5(DataType val)
{
    return val < 5;
}

vector<int> vec{1, 3, 5, 7, 9};
cout << countOccurences(vec.begin(), vec.end(), isLessThan5); // returns 2
```

**lambda 函数**

```cpp
// 格式 参数中可使用 auto，将会创建一个类
auto func = [capture-clause](parameters) -> return-value { // -> return-value 可忽略
	// body
	// 捕获子句作用：lambda 函数体内可以访问哪些外部变量以及如何访问它们
};
```

捕获方式

- `[x]` ：按值拷贝捕获
- `[&x]`：按引用捕获，修改原始值
- `[=]`：按值捕获所有在函数体中使用的外部变量
- `[&]`：按引用捕获所有在函数体中使用的外部变量
- `[this]`：捕获当前类的`this`指针
- `[=, &x]`：默认按值捕获，`x`特别按引用捕获

使用 lambda 函数来代替 谓词函数，由于函数内可能包含不存在于函数体内的变量，而 lambda 函数可以通过捕获组引入

## Algorithms

前一节实现的内容中，STL 库实际帮忙生成了对应优化的函数

```cpp
// count and count_if
template<class InputIt, class T>
constexpr typename iterator_traits<InputIt>::difference_type 
count(InputIt first, InputIt last, const T &value);

// 返回值，常量表达式：返回迭代器类型的“差值类型”
// std::iterator_traits<> 模版结构体，提取迭代器类型信息

template<class InputIt, class UnaryPredicate>
constexpr typename iterator_traits<InputIt>::difference_type 
count_if(InputIt first, InputIt last, UnaryPredicate p);
```

枚举

```cpp
enum class Year { FRESHMAN, SOPHOMORE, JUNIOR, SENIOR, GRAD};

var = Year::GRAD;
```

**查找：**google 输入`stl xxx` 进入 [https://en.cppreference.com/](https://en.cppreference.com/) 寻找可使用的函数

实现比较

<img src="/img/cs106l.zh-cn.assets/image.png" alt="图片无法加载" />

```cpp
auto [min, max] = minmax_element(A.begin(), A.end()); // 适用于vector<int>
// A 为结构体
auto cmpA = [](const A& a1, const A& a2){
	// 实现具体比较逻辑返回布尔
}
auto [Amin, Amax] = minmax_element(A.begin(), A.end(), cmpA);

```

实现平均值

```cpp
accumulate(A.begin(), A.end(), 0) / A.size(); // vector<int>中init起始值为0

auto addA = [](int sum, const A& a1){
	return sum + a1.average;
};
accumulate(A.begin(), A.end(), 0, addA) / A.size();
```

实现中位数

排序后取中间值的时间复杂度：O(nlogn)，尝试使用部分排序O(n)

```cpp
nth_element(begin(numvec), begin(numvec) + numvec.size()/2, end(numvec));
int median = numvec[numvec.size()/2];
```

`begin(x)`与`x.begin()`

- `begin(x)` 更泛用：可以处理数组、自定义类型、非标准容器

**判断**

```cpp
// 给定区间是否有任意一个元素满足
bool has_even = std::any_of(v.begin(), v.end(), [](int x) {
	return x % 2 == 0;
});

// 查找第一个满足条件的元素, 返回迭代器
auto it = std::find_if(v.begin(), v.end(), [](int x) {
	return x % 2 == 0;
});

// 满足条件元素复制到另一个容器
std::vector<int> even; // 目标容器
std::copy_if(v.begin(), v.end(), std::**back_inserter**(even); [](int x) {
// **迭代器适配器，返回输出迭代器，调用 push_back
// 使得拷贝时候不会将元素放入未初始化的内存中，而是会不断增加内存**
	return x % 2 == 0;
});
```

**流适配器创建迭代器**

```cpp
copy(begin(s), end(s), ostream_iterator<S>(cout, "\n")); 
// 将 s 所有元素输出到标准输出，每个输出后有 \n 
```

## STL Summary

**适配器**

1. 容器适配器：底层容器封装提供不同接口行为
    1. `stack, queue, priority_queue`
2. 迭代器适配器：将普通迭代器作为特定用途如输入插入等
    1. `back_inserter, front_inserter, ostream_iterator, istream_iterator`
3. 函数适配器：将普通函数或函数对象包装成与算法搭配的新形式
    1. `bind, function, lambda`

工程量大时，使用 `using std::cout` 代替使用`using namespace std;` 

- 实现小项目：对文本频率相似度进行分析
    
    涉及知识点记录
    
    `std::search`
    
    ```cpp
    auto find = std::search(text.begin(), text.end(), word.begin(), word.end());
    // 返回找到对应位置的迭代器
    ```
    
    `std::inner_product`
    
    ```cpp
    // 来源于 numeric 库，计算点积
    int res = std::inner_product(vec1.begin(), vec1.end(), vec2.begin(), 0);
    ```
    

## Classes and Constant

**const**

- 从右向左看
- `const` 对象只允许调用`const` 函数，且将所有公共成员视为`const` 来保证对象不会改变

```cpp
int * const p; // 常量指针，指向 int 类型值，指针不可变，指向的值可变
// YES: (*p)++; 
// NO: p++;

const int *p; // 指向常量整型数的非常量指针，指针可变，指向的值不可变
int const *p;

const int* const p; // 指向常量整型数的常量指针
int const* const p;
```

**常量迭代器**

- 迭代器实际更像指针，是指针的超集

```cpp
const vector<int>::iterator itr = v.begin(); // 类似于 int * const itr
++itr; // doesn't compile
*itr = 15; // compile
```

`const_iterator` 设置**迭代器只读，则指向的值为常量不可更改，但迭代器可移动**

```cpp
vector<int>::const_iterator itr = v.begin();
*itr = 5; // NO
++itr; // OK
int value = *itr; // OK
```

常量函数

- 保证函数不会调用任何非常量函数，不会修改任何非静态、不可变的成员

```cpp
size_t Vector<ElemType>::size() const;
```

## Operators

如何应用 `operators` 到用户自定义类中

```cpp
vector<string> v{"hello", "world"};
cout << v[0]; // cout.operator<<(v.operator[](0)); 左边部分调用的隐式函数
							// operator<<(cout, v.operator[](0));
v[1] += "!"; // v.operator[](1).operator+=("!");
						 // operator+=(operator[](v, 1), "!");
```

**实现格式**

- 成员函数实现：`[], (), =, ++, +=`
- 非成员函数实现：`<<, +, <` ，`ostream` 流是STL标准库，不能修改或覆盖，必须使用成员函数

`+=` 返回引用，表示在原数据基础上更改

```cpp
// v += "!";
vector<string>& vector<string>::operator+=(const string& element) {
	push_back(element);
	return *this;
}

// v += vec;
vector<string>& vector<string>::operator+=(const vector<int>& other) {
	for ( int val : other) push_back(val);
	return *this;
}
```

`+` 返回新拷贝

```cpp
// 成员函数
StringVector StringVector::operator+(const StringVector& other) const {
	StringVector result = *this; // 创建新拷贝
	for(const std::string& s : other) {
		result += s;
	}
	return result;
}

// 非成员函数
StringVector operator+(const StringVector& first, const StringVector& second) {
	StringVector result = first;
	for (const std::string& s : second) result += s;
	return result;
}
```

`<< and >>`实现，使用引用

```cpp
// cout << f1 << f2;
// cout.operator<<(f1).operator<<(f2);
ostream& operator<<(std::ostream& os, const Fraction& f) {
	os << f.num << "/" << f.denom; // num 和 denom 可能为私有变量无法访问
	// 一：使用访问器，f.getnum(), f.getdenom()
	// 二：友元
}
```

**友元函数：**在类外可访问私有变量，在原 Fraction 类 private 中加入

```cpp
friend operator<<(ostream& os, const Fraction& f);
```

**POLA**

Principle of Least Astonishment，最小惊讶原则：当正在实现他人需要使用的代码时，最好通过别人不会感到惊讶的方式去实现他

- 对称运算符（`+, -` 等），使用非成员函数实现
    - 防止出现`a+1`可行而`1+a`不可行情况
- 始终提供一组相关运算符中所有运算符

## Special Member Functions

- 默认构造：无参创建对象
- 拷贝构造：根据对已存在对象的拷贝，创建新对象；创建现有对象的副本
- 拷贝赋值：根据对另一个已存在对象的拷贝，替换已存在对象；先清空所有内容并替换为另一个内容
- 析构：超过范围销毁对象

构造函数初始化队列

```cpp
Func::Func(int a, int b): a(a), b(b) {
}
```

**复制操作**

默认拷贝构造函数无法满足条件的情况

```cpp
vector<int> operator+(const vector<int>& vec, int elem) {
	vector<int> copy = vec; // vec 和 copy 对象均指向同一内存数组
	copy += element; // 向 copy 加入元素，实际加到了同一内存数组中
	return copy; // 调用返回值时，会创建新的另一个副本，此时有3个对象指向同一内存数组
}

// 当 vec 析构函数尝试释放内存，底层数组被释放一次
// 问题**：copy 的析构函数被调用时，会导致2次释放数组**
```

所以必须**自己实现拷贝构造函数**

✅ 若指针指向一个数组，不能简单复制指针本身，需要深度拷贝，将数组同样复制

✅ 构造函数不能抛出异常：`noexcept`

✅ `this`是一个指针

✅ 声明了三者任意其一，则需实现三个（拷贝构造器、拷贝赋值、析构），后续还需实现移动构造器和移动赋值

```cpp
private:
	std::string *elems;

Func::iterator Func::begin() {
	return elems;
}

// 拷贝构造函数
Func::Func(const Func& other) noexcept :
	var1(other.var1), var2(other.var2)
{
	elems = new std::string[20]; // 成员变量
	std::copy(other.begin(), other.end(), begin()); // 数组本身可当作迭代器使用
}

// 拷贝赋值函数
Func& Func::operator=(const Func& other) {
	// 检查指针是否相等
	if(this ！= &other) { // 解决自我赋值：a = a;
		
		delete[] elems;
		
		var1 = other.var1;
		var2 = other.var2;
		
		elems = new std::string[20];
		std::copy(other.begin(), other.end(), begin());
	}
	return *this;
}

```

禁止使用该拷贝构造函数

```cpp
Func(const Func& other) = delete; // 告诉编译器禁止复制对象
```

## Move Semantics

`emplace_back`

- `push_back`需要创建临时对象，将对象拷贝到容器末尾
- `emplace_back`无需构造临时对象，而是就地在容器末尾直接构造，直接在容器内部调用构造函数

```cpp
struct Person {
    std::string name;
    int age;
    Person(std::string n, int a) : name(std::move(n)), age(a) {}
};

std::vector<Person> people;

people.push_back(Person("Tom", 25));
people.emplace_back("Jerry", 20); // 参数完美转发给构造函数
```

**编译器：返回值优化（RVO），拷贝省略（copy elision）**

```cpp
#define LOG_FUNC(msg) \
    printf("%s\n", msg);

class StrVec {
public:
    char* data;
    size_t size;

    // ✅ 默认构造函数
    StrVec() : data(nullptr), size(0) {
        LOG_FUNC("Default Constructor");
    }

    // ✅ 构造函数（分配 size 个 'a'）
    StrVec(size_t sz, const char* c) : size(sz) {
        LOG_FUNC("Parameterized Constructor");
        data = new char[size + 1];
        memset(data, c[0], size);
        data[size] = '\0';
    }

    // ✅ 拷贝构造函数
    StrVec(const StrVec& other) : size(other.size) {
        LOG_FUNC("Copy Constructor");
        data = new char[size + 1];
        strcpy(data, other.data);
    }

    // ✅ 拷贝赋值运算符
    StrVec& operator=(const StrVec& other) {
        LOG_FUNC("Copy Assignment");
        if (this != &other) {
            delete[] data;
            size = other.size;
            data = new char[size + 1];
            strcpy(data, other.data);
        }
        return *this;
    }

    // ✅ 析构函数
    ~StrVec() {
        LOG_FUNC("Destructor");
        delete[] data;
    }
};
```

➡️ 编译时加入`-fno-elide-constructors` ，会强制禁用拷贝省略

- 则`return xxx` 返回对象时，会调用拷贝构造函数，因为局部变量只在该局部函数内有作用，返回给`main`函数需要重新构造对象；
- 接着调用析构函数删除对象`xxx`

```cpp
// main.cpp
// g++ -std=c++11 -fno-elide-constructors
StrVec readName(size_t size) {
	StrVec name(size, "a"); // 1. 构造函数  7. 构造函数
	return name; // 2. 拷贝构造函数 + 3 析构函数  8. 拷贝构造函数 + 9 析构函数
}

int main() {
	StrVec name1 = readName(123); // 4. 拷贝构造函数 + 5. 析构函数
	StrVec name2; // 6. 默认构造函数
	name2 = readName(123); // 10. 拷贝赋值函数 + 11. 析构函数
} // 12.13. 析构函数
```

➡️ 若不加入该参数编译，则会优化`return`不进行临时构造，而是在`main`函数处直接构造

```cpp
// g++ -std=c++17
StrVec readName(size_t size) {
	StrVec name(size, "a"); // 1. 构造函数  3. 构造函数
	return name; 
}

int main() {
	StrVec name1 = readName(123);
	StrVec name2; // 2. 默认构造函数
	name2 = readName(123); // 4. 拷贝赋值函数 + 5. 析构函数
} // 6.7. 析构函数
```

**此处 `name2 = readName(123)` 其对右侧临时值进行了拷贝和析构，有多余步骤，是否能优化为直接移动到`name2`**

**左值与右值** l-value and r-value

- 左值：拥有名称/身份，可使用取地址符找到地址（`&var`），可左边可右边
- 右值：无名称/身份，临时值，不能使用取地址符找到地址，只在右边

左右值引用

`auto&`是左值引用，`auto&&`是右值引用

```cpp
int val = 2; // val: 左值
int *ptr = 0x123; // ptr: 左值
vector<int> v1{1, 2, 3}; // v1: 左值

auto& ptr2 = ptr; // ptr2 是左值引用，可以绑定左值 ptr，类似于 ptr2 为 ptr 别名
auto&& v4 = v1 + v2; // v4 是右值引用，可以绑定右值 v1 + v2，延长了生命周期
auto& ptr3 = &val; // NO：ptr3 是左值引用，不能绑定到右值 &val

auto&& val2 = val; // NO：val2 是右值引用，不能绑定到左值 val

const auto& ptr3 = ptr + 5; // ptr3 是常量左值引用，可以绑定到右值 ptr + 5
```

右值对于移动语义非常关键：左值不是一次性的，不可从其移动，右值是一次性的，可以从其复制或移动

**新特殊成员函数**

1. 移动构造函数：从已存在的右值创建一个新对象

```cpp
StrVec(StrVec&& other) noexcept :
	ptr(other.ptr), // 直接将 other 的指针移动到此借用
	var1(other.var1) {
	other.ptr = nullptr; // other 的指针不再需要
}
```

1. 移动赋值：从已存在右值覆写已存在的对象

```cpp
StrVec& operator=(StrVec&& rhs) noexcept {
	if(this != &rhs) {
		delete [] ptr;
		var1 = rhs.var1;
		ptr = rhs.ptr; // 直接将指针指向对应底层指针指向值（数组），未复制而是直接移动
		rhs.ptr = nullptr; // 该临时指针可直接置空
	}
	return *this;
}
```

- 上述实现仍不是最完美的
- 尽管`rhs`在参数中是属于右值引用，但在函数中，`rhs`本身是一个左值，有`=`说明会生成副本
- 希望`rhs`成为一个右值

```cpp
// 使用 std::move
xxx = std::move(rhs.xxx);
xxx(std::move(other.xxx)) // 初始化队列
```

**`move` 作用**：接收传入的参数无条件返回其右值，将其视为临时值

## Inheritance

常量成员函数：不能改变任何该实例中类的私有变量

**namespace**

```cpp
using std::xxx // 命名空间

namespace hh {

}
hh::abc();
```

**继承**

若不同流需要实现打印功能

尝试一：模板，隐式接口

```cpp
template <typename StreamType>
void print(StreamType& stream, int i) {
	stream << i;
}
```

尝试二：继承，显示式接口

```cpp
// 接口
class Drink {
public:
	// 纯虚函数
	virtual void make() = 0; // 强制任何集成了 Drink 类的类必须实现 make 函数，否则不能被视为真正的类
};

class Tea : public Drink {
public
	void make() {
		// 实现
	}
};

// 只要 istream 实现 print（非虚函数），且所有类型的流继承自 istream，则只需要写一个函数
void print(istream &stream, int i) {
	stream << i;
}
```

类中，一切默认 private

- 基类：超类、父类
- 派生类：子类

总是调用超类的构造函数，若没指定，调用基类的默认构造函数

```cpp
class Derived : public Base {
	Derived() : Base(args) {
	}
};
```

**抽象类**

- 类中至少有一个纯虚函数
- 接口是抽象类的子集
- 抽象类无法被实例化

```cpp
class Base {
public:
	virtual void foo() = 0; // 纯虚函数
	virtual void foo2(); // 非纯虚函数
	void bar() = { return 1; }; // 常规函数
};
```

若 `B` 继承自 `A`，且有同名变量 `z`，则会隐藏 `A::z`

规范化：将析构函数设为`= default`，编译器**自动生成默认实现**

```cpp
class B {
public:
    ~B() { // 更改为 virtual ~B 才会先调用 D destructor 再调用 B destructor
        std::cout << "B destructor\n";
    }
};

class D : public B {
public:
    ~D() {
        std::cout << "D destructor\n";
    }
};

int main() {
    B* b = new D();  // 指针类型是 B*，对象实际是 D
    delete b;        // ❓ 会调用 B destructor:  由于基类析构函数不是 virtual
								     // 所以只会调用编译器知道的类型的析构函数
}

```

**访问标识符**

- private：只可被该类访问
- protected：只可被该类及其派生类访问
- public：可被任何类访问

在基类实现`make()`函数，且有同名的纯虚函数`make()`，派生类调用方式

```cpp
t.Base::make(); // 调用基类的 make 函数
t.make(); // 派生类实现了 make 方法
```

## Template Classes and Concepts

静态多态性 vs 动态多态性

- 模板为静态多态性，在编译时会基于给定的数据类型生成所有不同的代码片段，创建模板
- 继承为动态多态性，派生类在运行时才确定所有的数据类型，类中只存在一份

**类型转换 casting**

```cpp
int a = (int) b;
int a = int (b);
int a = static_cast<int>(b); // 现代C++最佳实践：静态转换
```

**模板类**

**从类到模板类**

原类：只可传入整型

```cpp
class Q {
public:
	Q() = default;
	~Q() = default;
	
	int top() const {}
	void pop() {}
	void push(int val) {}
	friend std::ostream& operator<<(std::ostream& os, const Q q) {}
private:
	vector<int> _heap;
	size_t _count{0};
};

int main() {
	Q q;
	q.push(3);
	q.push(5);
	q.push(7);
	cout << q << endl;
}
```

模板类：可以传入任何数据类型

- 实际`template<class` 与 `template<typename` 效果一样

```cpp
template <class T, class Container = std::vector<T>>
class Q {
public:
	Q() = default;
	~Q() = default;
	
	T top() const {}
	void pop() {}
	void push(T val) {}
	friend std::ostream& operator<<(std::ostream& os, const Q q) {}
private:
	vector<T> _heap; // 也可以使用 Container _heap
	size_t _count{0};
};

int main() {
	Q<vector<string>, vector<vector<string>>> q;
	q.push({"about"});
	q.push({"bed"});
	q.push({"cute"});
	cout << q << endl;
}
```

**concepts(C++20)**

自定义约束

```cpp
template<class Derived, class Base>
concept DerivedFrom =
    is_base_of_v<Base, Derived> && // Base 是否是 Derived 的基类
    is_convertible_v<const volatile Derived*, const volatile Base*>; // Derived* 是否能隐式转换成 Base*
```

使用其限制模板参数

```cpp
template<class D, class B>
void f(T) requires DerivedFrom<D, B> {
    // 只有当 D 是 B 的派生类时，这个函数模板才会参与重载
		// 否则编译器会直接忽略（不会报错）
}

```

## RAII and Smart Pointers

代码路径：

- 判断1正确，进入并返回
- 判断1错误判断2正确，进入并返回
- 判断1和2均错误，不进入，返回
- **更多：在多个地方抛出异常【参数为函数，重载了各个操作符，调用函数返回错误】**

```cpp
string EvaluateSalaryAndReturnName (Employee e) {
    if (e.Title() == "CEO" || e.Salary() > 100000) {
		cout << e.First() << " "
			<< e.Last() << " is overpaid" << endl;
    }
    return e.First() + " " + e.Last();
}
```

后续示例：是否会出现内存泄漏

```cpp
string EvaluateSalaryAndReturnName (int idNumber) {
    Employee* e = new Employee(idNumber); // 分配堆上数据
    if (e->Title() == "CEO" || e->Salary() > 100000) {
			cout << e->First() << " "
				<< e->Last() << " is overpaid" << endl;
    }
		auto result = e->First() + " " + e->Last();
	    
		delete e;		// 释放堆上内存，若异常导致跳过这行，导致内存泄漏
    return result;
}
```

需要释放的资源：锁、堆空间、套接字、流

4️⃣种级别——异常安全

1. 无抛出异常保证：绝对不能抛出异常，析构函数，swap，移动构造函数
2. 强异常保证：回滚到函数调用前的状态
3. **基本异常保证**：异常后程序处于合理状态
4. 无异常保证：资源泄漏、内存崩溃

**RAII：Resource Acquisition Is Initialization，资源获取即初始化**

- SBRM：Scope Based Memory Management，基于作用域的内存管理
- CADRE：Constructor Acquires, Destructor Releases，构造函数获取，析构函数释放
- PIMPL：Pointer to Implementation

✅ 获取资源在构造函数中进行，释放资源在析构函数中进行

```cpp
// no-RAII
ifstream input();
input.open("hello.txt");

// RAII
ifstream input("hello.txt");
```

**智能指针**

```cpp
void test() {
	Node* n = new Node();
	...
	delete n; // 删除指针，不符合RAII，遵循相同思路，将其包裹在一个对象中，使用智能指针
}
```

内置智能指针：`std::unique_ptr, std::shared_ptr, std::weak_ptr`

**独占指针**

独占资源，对象销毁自动删除，且不可复制，否则可能会导致double-free

```cpp
// 之前代码更改为
void test() {
	std::unique_ptr<Node> n(new Node);
	...
} // freed
```

**共享指针**

资源可被多个共享指针存储，所有指针都不指向他时才删除

```cpp
std::shared_ptr<int> p1(new int);
// use p1
{
	std::shared_ptr<int> p2 = p1;
	// use p1, p2
}
// use p1
```

```cpp
// 之前代码更改为
void test() {
	std::shared_ptr<Node> n(new Node);
	...
} // freed
```

**内置智能指针构造器**

```cpp
// 主要使用这种方式构造
std::unique_ptr<Node> n = std::make_unique<Node>();
std::shared_ptr<Node> n = std::make_shared<Node>():
```

## Multithreading

- 使用原子类型
- 条件变量允许跨线程通信

1️⃣ 初始示例

```cpp
void greet(int id) {
	// nstd::this_thread::sleep_for(std::chrono::seconds(5));
	// 主线程超出作用域后，子线程将无法执行
	cout << "hello " << id << endl; // hello 1 和 hello 2 可能重叠
}

int main() {
	cout << "begin..." << endl;
	
	std::thread thread1(greet, 1);
	std::thread thread2(greet, 2);
	
	cout << "end;" << endl;
	
	return 0;
}
```

2️⃣ 加入锁使得不同线程输出不重叠完整输出`hello x`

```cpp
std::mutex mtx;

void greet(int id) {
	std::lock_guard<std::mutex> lg(mtx);
	cout << "hello " << id << endl;
}

int main() {
	cout << "begin..." << endl;
	
	std::thread thread1(greet, 1);
	std::thread thread2(greet, 2);
	
	cout << "end;" << endl;
	
	return 0;
}
```

3️⃣ 主线程等待两个子线程完成后，合并

```cpp
std::mutex mtx;

void greet(int id) {
	std::lock_guard<std::mutex> lg(mtx);
	cout << "hello " << id << endl;
}

int main() {
	cout << "begin..." << endl;
	
	std::thread thread1(greet, 1);
	std::thread thread2(greet, 2);
	
	thread1.join();
	thread2.join(); // 等待 hello 均输出完，再往下执行
	
	cout << "end;" << endl;
	
	return 0;
}
```

4️⃣ 更多线程

```cpp
std::mutex mtx;
const size_t num_thread = 10;
void greet(int id) {
	std::lock_guard<std::mutex> lg(mtx);
	cout << "hello " << id << endl;
}

int main() {
	cout << "begin..." << endl;
	
	vector<std::thread> threads;
	
	for(size_t i = 0; i < num_thread; i++){
		threads.push_back(std::thread(greet, i));
		// threads[i].join();
	} 
	
	for(std::thread& t : threads) { // 使用引用
		t.join();
	}
	
	cout << "end;" << endl;
	
	return 0;
}
```

## 参考

博客记录

- [https://crownz-sec.github.io/2022/07/31/Stanford CS106L 2019 Note-Top half/](https://crownz-sec.github.io/2022/07/31/Stanford%20CS106L%202019%20Note-Top%20half/)
- [https://crownz-sec.github.io/2022/07/31/Stanford CS106L 2019 Note-Second half](https://crownz-sec.github.io/2022/07/31/Stanford%20CS106L%202019%20Note-Second%20half/)/

课程网站

- [https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1202/index.html](https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1202/index.html)
- [https://learncs.me/stanford/cs106l](https://learncs.me/stanford/cs106l)

作业pdf

- [https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1202/handouts/003_assignment_2_wikiracerA.pdf](https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1202/handouts/003_assignment_2_wikiracerA.pdf)
- [https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1202/handouts/004_assignment_2_wikiracerB.pdf](https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1202/handouts/004_assignment_2_wikiracerB.pdf)
- [https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1202/handouts/005_assignment_3_kdtree.pdf](https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1202/handouts/005_assignment_3_kdtree.pdf)

github

- [https://github.com/jackwang0108/CS106L-2019Fall](https://github.com/jackwang0108/CS106L-2019Fall)
- [https://github.com/yucdong/cs106l-projects](https://github.com/yucdong/cs106l-projects)
- [https://github.com/PKUFlyingPig/CS106L](https://github.com/PKUFlyingPig/CS106L)

实现

- [https://www.jianshu.com/p/8cee186bbdaa](https://www.jianshu.com/p/8cee186bbdaa)
