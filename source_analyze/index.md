# glibc源码分析


## Heap

### 结构

#### malloc_par

`malloc.c`中，记录堆管理器的相关参数

```c
struct malloc_par
{
  unsigned long trim_threshold; // 收缩阈值 默认128KB
  /*
  	用于控制main_arena中保留的内存量
  	当释放的chunk为mmap获得的，同时大小大于mmap_threshold，更新mmap_threshold同时将trim_threshold乘2;
  	当释放的chunk大小在 fast bin 范围内，合并完 size 大于 FASTBIN_CONSOLIDATION_THRESHOLD:0x10000，根据该字段缩小 top chunk
  */
  INTERNAL_SIZE_T top_pad;			// 初始化或扩展堆时申请内存是否添加额外pad，默认为0
    								// 调用sbrk函数时在原有请求大小上添加的一个值，是一个填充
  INTERNAL_SIZE_T mmap_threshold;	// mmap分配阈值
  /* 
  	决定sysmalloc用mmap还是sbrk分配内存界限, >则mmap, <则sbrk,
  	若释放的内存通过mmap得到的, 则mmap_threshold与该内存大小取max, 且该值最大不超过DEFAULT_MMAP_THRESHOLD_MAX:0x2000000
  */
  INTERNAL_SIZE_T arena_test; // 最小分配区
  INTERNAL_SIZE_T arena_max;  // 最大分配区
 
  int n_mmaps;			// mmap分配的内存数量, mmap一次+1, munmap一次-1
  int n_mmaps_max;		// 最多能mmap的内存数量
  int max_n_mmaps;		// n_mmaps达到过的最大值

  int no_dyn_threshold;	// 是否开启mmap分配阈值动态调整，默认为0开启
 
  INTERNAL_SIZE_T mmapped_mem;		// 当前 mmap 分配的内存大小总和
  /*INTERNAL_SIZE_T  sbrked_mem;*/
  /*INTERNAL_SIZE_T  max_sbrked_mem;*/
  INTERNAL_SIZE_T max_mmapped_mem;	// mmap 的内存大小总和达到过的最大值
  INTERNAL_SIZE_T max_total_mem;  // 单线程情况下统计进程分配的内存总数
 
  char *sbrk_base; // brk系统调用申请的heap区域的起始地址
};
```

该结构体类型实例`mp_`来记录ptmalloc参数

```c
#define DEFAULT_TOP_PAD 131072 // 0x20000
#define DEFAULT_MMAP_MAX       (65536) // 0x10000
#define DEFAULT_MMAP_THRESHOLD_MIN (128 * 1024)
#define DEFAULT_MMAP_THRESHOLD DEFAULT_MMAP_THRESHOLD_MIN // 0x20000
#define DEFAULT_TRIM_THRESHOLD (128 * 1024) // 0x20000

static struct malloc_par mp_ =
{
  .top_pad = DEFAULT_TOP_PAD,
  .n_mmaps_max = DEFAULT_MMAP_MAX,
  .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
  .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
  .arena_test = NARENAS_FROM_NCORES (1)
};
```

#### heap_info

- **位于堆块的开头**，记录通过mmap从Memory Mapping Segment处申请到的内存块信息，`arena.c`中
- 为**非主线程**分配内存使用，因为主分配区可以直接使用sbrk扩展，只有一个堆，非主线程的堆是提前分配好的，当该资源用完时需要重新申请内存空间，不连续所以需要记录不同的堆的链接结构

```c
typedef struct _heap_info
{
  mstate ar_ptr; /* 指向管理该堆块的arena分配区 */
  struct _heap_info *prev; /* 上一个heap_info，单链表形式记录一个线程所有堆结构 */
  size_t size;   /* 该堆块大小 */
  size_t mprotect_size; /* 记录该堆块被mprotected保护的大小*/

  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK]; // 在SIZE_SZ不正常时填充来对其, 正常pad占用0字节
} heap_info;
```

### malloc

#### 2.23

##### 宏

```c
SIZE_SZ				// sizeof( size_t ) 1字节大小
MALLOC_ALIGN_MASK	// ( 2 * SIZE_SZ ) - 1 = 2 * 8 - 1 = 0x10 - 1
MINSIZE 			// ( MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK ) & ~MALLOC_ALIGN_MASK 向下取整
MIN_CHUNK_SIZE 		// offsetof( struct malloc_chunk, fd_nextsize ) 0x20字节
```

##### __libc_malloc

```c
void *__libc_malloc (size_t bytes)
{
  mstate ar_ptr; // 保存指向分配区main_arena的指针
  void *victim; // 保存获得的堆块内存指针: chunk_addr + 0x10

  // 获取 __malloc_hook
  void *(*hook) (size_t, const void *) = atomic_forced_read (__malloc_hook); 
  if (__builtin_expect (hook != NULL, 0)) // 检查__malloc_hook值是否被设置
      return (*hook)(bytes, RETURN_ADDRESS (0)); // 若被设置则调用其指向的函数, 参数为申请的内存大小
  
  arena_get (ar_ptr, bytes); // 若未被设置则获取本线程一个可用分配区thread_arena
  victim = _int_malloc (ar_ptr, bytes); // 申请内存并返回

  if (!victim && ar_ptr != NULL) // 堆块未申请成功且arena的指针不为空
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes); // 获取下一个分配区
      victim = _int_malloc (ar_ptr, bytes); // 再次申请分配
    }

  if (ar_ptr != NULL) 
      (void) mutex_unlock (&ar_ptr->mutex); // 操作完成, 解锁分配区使其他线程能够访问
	
    // 只有3种情况
  assert (!victim || // 未申请到内存
          chunk_is_mmapped (mem2chunk (victim)) || // mmap获取的内存
          ar_ptr == arena_for_chunk (mem2chunk (victim))); // 内存从当前线程对应的thread_arena管理的内存中获取
  return victim;
}
```

##### _int_malloc

**CAS**：从内存位置读取值与期望值比较，相等则更新，不相等则失败重新尝试

**ABA**：一个值在经过多次修改后又回到原始值

```c
static void *_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* 请求的chunk_size */
  unsigned int idx;                 /* 对应bin数组中的index索引 */
  mbinptr bin;                      /* 指向对应bin的指针 */

  mchunkptr victim;                 /* 指向分配的chunk */
  INTERNAL_SIZE_T size;             /* 分配的chunk的size */
  int victim_index;                 /* 分配的chunk的bin的index */

  mchunkptr remainder;              /* 指向分割后剩下的那块chunk */
  unsigned long remainder_size;     /* 分割后剩下那块chunk的size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* 链表操作 */
  mchunkptr bck;                    /* 链表操作 */

  const char *errstr = NULL;

  checked_request2size (bytes, nb); // 检查并将申请内存转换为适合内存分配的块大小

  if (__glibc_unlikely (av == NULL)) // 没有可用arena即arena未初始化
  {
    void *p = sysmalloc (nb, av); // 通过sysmalloc系统调用从mmap获取堆块
    if (p != NULL)
      alloc_perturb (p, bytes); // 用memset清理空间数据
    return p;
  }

  // 在fastbin大小内
  if ((unsigned long)(nb) <= (unsigned long)(get_max_fast())) // global_max_fast:0x80
  {
    idx = fastbin_index(nb); // 获取fastbin中的索引，无任何检查，改global_max_fast可使idx极大
    mfastbinptr *fb = &fastbin(av, idx);
    // #define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx]) 即fb指向fastbin中对应的bin的地址
    mchunkptr pp = *fb; // pp指向该对应fastbin中第一个chunk
    do
    {
      victim = pp; // 取出第一个空闲chunk来分配 【victim】
      if (victim == NULL) // fastbin中无chunk，跳出，去申请相应大小的smallbin
        break;
        	// 等价于*fb = victim->fd, 链表头指向该空闲chunk的下一个chunk
    } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd, victim)) != victim);
      // # define catomic_compare_and_exchange_val_acq(mem, newval, oldval) 
      // CAS(Compareand-Swap)原子操作, 避免多线程的ABA问题
      
    // 存在可使用的chunk
    if (victim != 0)
    {
      if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0))
          // 检测该chunk的size是否符合该bin的index
      {
        errstr = "malloc(): memory corruption (fast)";
      errout:
        malloc_printerr(check_action, errstr, chunk2mem(victim), av);
        return NULL;
      }
      check_remalloced_chunk(av, victim, nb); // 对chunk标志位检查、是否是malloc_state所表示的分配区中的
        									  // 检查是否已分配，是否重复分配和大小检查
      void *p = chunk2mem(victim); // p 指向 chunk 的 fd 字段地址即data区域
      alloc_perturb(p, bytes);
      return p;
    }
  }

  // 在 small bin 大小范围内
  if (in_smallbin_range(nb)) 
  {
    idx = smallbin_index(nb); // 获取smallbin的下标索引
    bin = bin_at(av, idx);	// 取出对应的bin

    if ((victim = last(bin)) != bin)
        // #define last(b) ((b)->bk) 即 bin->bk != bin说明small bin非空
        // 【victim为取出的表尾第一个chunk】
    {
      if (victim == 0) /* main_arena未初始化时victim为0，表示smallbin还未初始化为双向循环链表 */
        malloc_consolidate(av); // 初始化
      else
      {
        bck = victim->bk; // 取出victim之后的一个chunk检查
        if (__glibc_unlikely(bck->fd != victim)) // 安全检查: 该chunk的fd应指回victim
        {
          errstr = "malloc(): smallbin double linked list corrupted";
          goto errout;
        }
        set_inuse_bit_at_offset(victim, nb); // 设置物理相邻的下一个chunk inuse位, 表示victim被使用
        // 使链表头 bin 与 bck 的bk与fd相互连接, 将 victim 脱离双向循环链表
        bin->bk = bck;
        bck->fd = bin;

        if (av != &main_arena) // 若是非住分配区将标志位清零
          victim->size |= NON_MAIN_ARENA; // 只有申请出的chunk才会置该位, bin中chunk不置位 0x4
          
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim); // p 指向 chunk 的 fd 字段地址
        alloc_perturb(p, bytes);
        return p;
      }
    }
  }
  // 否则在 large bin 范围中，先不查找而是对fastbin进行处理
  else
  {
    idx = largebin_index(nb); // 获取largebin中索引
    if (have_fastchunks(av)) // ((M)->flags & FASTCHUNKS_BIT) == 0 即是否已初始化main_arena
      malloc_consolidate(av); // 对fastbin中所有chunk进行遍历、合并，将空闲chunk放入unsorted bin
  }
  // 在 unsorted bin中找，并将相应的bin按照大小放入small bin和large bin中
  for (;;)
  {
    int iters = 0;
    // 取unsorted bin中最后一个chunk victim, 反向遍历unsorted bin直到unsorted bin为空
    while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av))
    {
      bck = victim->bk; // victim的前一个chunk
      if (__builtin_expect(victim->size <= 2 * SIZE_SZ, 0) || 
          __builtin_expect(victim->size > av->system_mem, 0))
          // 若小于0x10或大于arena管理的最大内存，报错
        malloc_printerr(check_action, "malloc(): memory corruption",
                        chunk2mem(victim), av);
      size = chunksize(victim); // 获取chunk大小
	  
      // 需要切割情况
      if (in_smallbin_range(nb) &&	// 申请大小在small bin范围
          bck == unsorted_chunks(av) && // unsorted bin中只有一个chunk victim
          victim == av->last_remainder && // victim刚好是last_remainder
          (unsigned long)(size) > (unsigned long)(nb + MINSIZE)) // victim大小 > 申请大小 + 0x20
      {
        remainder_size = size - nb; 
        remainder = chunk_at_offset(victim, nb); // 切出一个remainder_size的chunk
          
        unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder; // 切出的chunk放入unsorted bin
        av->last_remainder = remainder; // 设置新的remainder
        remainder->bk = remainder->fd = unsorted_chunks(av); // 维护双向链表
          
        if (!in_smallbin_range(remainder_size))
        { // 若是large bin则设置两个nextsize
          remainder->fd_nextsize = NULL;
          remainder->bk_nextsize = NULL;
        }

        set_head(victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
        set_head(remainder, remainder_size | PREV_INUSE);
        set_foot(remainder, remainder_size);

        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim); // 转换为内存指针返回
        alloc_perturb(p, bytes);
        return p;
      }

      /* 不满足切割的条件，将 victim 从 unsorted bin 中取出 */
      unsorted_chunks(av)->bk = bck;
      bck->fd = unsorted_chunks(av);

      if (size == nb) // 若victim大小刚好为用户申请的大小, 直接取出
      {
        set_inuse_bit_at_offset(victim, size);
        if (av != &main_arena)
          victim->size |= NON_MAIN_ARENA;
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p;
      }
      // 到这说明该victim会被放入对应大小的bin链表中，分别获得bck和fwd用于插入
	  // 若 victim 大小属于 small bin
      if (in_smallbin_range(size))
      {
        victim_index = smallbin_index(size);
        bck = bin_at(av, victim_index); // bck赋值为smallbin的链表表头
        fwd = bck->fd;	// fwd指向small bin第一个chunk，victim将插入到bck和fwd中作为第一个chunk
      }
      // 若 victim 大小属于 large bin
      else
      {
        victim_index = largebin_index(size);
        bck = bin_at(av, victim_index); // bck赋值为largebin的链表表头
        fwd = bck->fd;	// fwd指向large bin第一个chunk

        if (fwd != bck) // large bin中非空，即其中有空闲chunk存在
        {
          size |= PREV_INUSE; // 当前chunk的size的inuse置位，便于加快chunk大小比较
          assert((bck->bk->size & NON_MAIN_ARENA) == 0); // 多次判断确保NON_MAIN_ARENA为0，主线程
          if ((unsigned long)(size) < (unsigned long)(bck->bk->size))
              // fd一般指向比自己小的，bck的bk指向的是最小的size，此时victim为最小size
          {
            // 交换
            fwd = bck; // fwd 指向 largebin 链表表头
            bck = bck->bk; // bck 指向largebin中最小size的chunk
			
            // 更新victim的2个nextsize，使得victim插入largebin的末尾
            // fd_nextsize指向最大的chunk
            victim->fd_nextsize = fwd->fd; 
            // bk_nextsize指向最大chunk的bk_nextsize, 即最小size的第一个chunk(因为最小chunk可能多个)
            victim->bk_nextsize = fwd->fd->bk_nextsize; 
            fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; // 对应反向指
          }
          else // victim不为最小size
          {
            assert((fwd->size & NON_MAIN_ARENA) == 0);
            // 遍历找到第一个小于等于victim size的chunk
            while ((unsigned long)size < fwd->size)
            {
              fwd = fwd->fd_nextsize; // 不断遍历使得fwd->size非严格递减
              assert((fwd->size & NON_MAIN_ARENA) == 0);
            }

            if ((unsigned long)size == (unsigned long)fwd->size)
              fwd = fwd->fd; // 插入第二个位置，则不需要更新fd_nextsize和bk_nextsize
            else
            { // 此时victim > fwd(同样大小第一个)，更新将victim插入fwd前
              victim->fd_nextsize = fwd;
              victim->bk_nextsize = fwd->bk_nextsize;
              fwd->bk_nextsize = victim;
              victim->bk_nextsize->fd_nextsize = victim;
            }
            bck = fwd->bk; // bck 更新为找到的fwd的上一个chunk
          }
        }
        else // largebin 为空直接插入更新nextsize
          victim->fd_nextsize = victim->bk_nextsize = victim;
      }
	  // 统一维护fd和bk指针将victim插入bck和fwd中间
      mark_bin(av, victim_index); 
        /* 
       		#define mark_bin(m, i) ((m)->binmap[idx2block(i)] |= idx2bit(i))
        	将对应map里该index对应的标志位置1 
      	*/
      victim->bk = bck;
      victim->fd = fwd;
      fwd->bk = victim;
      bck->fd = victim; // 将当前chunk插入到对应bin中

#define MAX_ITERS 10000
      if (++iters >= MAX_ITERS) // 循环10000次处理unsorted bin中的chunk
        break;
    }

    // 此时unsorted bin 链表已经处理完成，在 large bin 中查找
    if (!in_smallbin_range(nb))
    {
      bin = bin_at(av, idx); // 对应large bin

      if ((victim = first(bin)) != bin && // large bin不为空，victim设为largebin最大cunk
          (unsigned long)(victim->size) >= (unsigned long)(nb)) // 申请大小小于最大chunk
      {
        victim = victim->bk_nextsize; // 最大chunk的bk_nextsize指向最小chunk, 此时victim最小
        // 遍历找到比申请的nb大小小的最近的
        while (((unsigned long)(size = chunksize(victim)) < (unsigned long)(nb)))
          victim = victim->bk_nextsize; // 最小chunk的bk_nextsize的chunk size 不断变大
		// victim有效 且 有至少两个size相同的chunk
        if (victim != last(bin) && victim->size == victim->fd->size)
          victim = victim->fd; // 再往下跳一步避免维护两个nextsize指针
          
		// 分割
        remainder_size = size - nb; // 不一定完全合适，计算remainder_size
        unlink(av, victim, bck, fwd); // 将找到的victim 脱链

        // 比MINSIZE还小则不能切割，将整个victim返回，实际分配的chunk比所需chunk大一些
        if (remainder_size < MINSIZE)
        {
          set_inuse_bit_at_offset(victim, size); // 设置下一个chunk的prev_inuse
          if (av != &main_arena)
            victim->size |= NON_MAIN_ARENA; // 非主线程设置non_main_arena位
        }
		// 否则需要切割
        else
        { // 从victim中切分出所需的chunk，剩余部分作为新chunk加入unsorted bin中
          remainder = chunk_at_offset(victim, nb); // 剩余chunk
          bck = unsorted_chunks(av); // 获取unsorted bin
          fwd = bck->fd; // 指向 unsorted bin 第一个 chunk
          if (__glibc_unlikely(fwd->bk != bck)) // 检测是否指针相互指向
          {
            errstr = "malloc(): corrupted unsorted chunks";
            goto errout;
          }
          // 将remainder其放入unsorted bin中
          remainder->bk = bck;
          remainder->fd = fwd;
          bck->fd = remainder;
          fwd->bk = remainder;
          if (!in_smallbin_range(remainder_size))
          {
            remainder->fd_nextsize = NULL;
            remainder->bk_nextsize = NULL;
          }
          // 设置victim标志
          set_head(victim, nb | PREV_INUSE |
                               (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head(remainder, remainder_size | PREV_INUSE);
          set_foot(remainder, remainder_size);
        }
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p; // 从largebin中取出victim返回
      }
    }

    ++idx; // 正确的idx找不到chunk，加一看下一个索引:比当前binindex大的small/large bin 是否能找到chunk
    bin = bin_at(av, idx);
    block = idx2block(idx); // 将idx/32转移到binmap中的block, 32位一组block
    // #define idx2block(i) ((i) >> BINMAPSHIFT)
    // #define BINMAPSHIFT 5
    map = av->binmap[block]; // binmap用于加速查找bin是否包含空闲chunk
    bit = idx2bit(idx); // 将idx指定的位置1，其他位清零
    // #define idx2bit(i) ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))

    for (;;)
    {
      // 大于等于该bit位的位都未置1，表示该block没有可用的空闲chunk，需要搜索下一个block
      if (bit > map || bit == 0)
      {
        do
        {     // 加一换到下一组block
          if (++block >= BINMAPSIZE) // 检查是否超过范围
            goto use_top;
        } while ((map = av->binmap[block]) == 0); // 直到找到一个不为0的block

        bin = bin_at(av, (block << BINMAPSHIFT)); // block*32转换为bin的位置
        bit = 1;
      } // 可以确定有可用的chunk

      while ((bit & map) == 0) // 与后为0则表明没有可用chunk
      { // 在一个block中遍历对应的bin直到找到一个bit不为0，退出遍历
        bin = next_bin(bin); // 找下一个bin
        bit <<= 1;
        assert(bit != 0);
      }
	  // 获取bin中的最后一个chunk victim
      victim = last(bin);
      if (victim == bin) // victim与bin链表头相同则说明bin中无空闲chunk，binmap设置有误
      {
        av->binmap[block] = map &= ~bit; // 将binmap的相应bit位清零
        bin = next_bin(bin); // 获取下一个bin
        bit <<= 1; // 将bit移到下一个bit位，即乘以2
      }
      else // bin中有空闲chunk，不为空，基本操作同之前
      {
        size = chunksize(victim); // 获取大小

        /*  We know the first chunk in this bin is big enough to use. */
        assert((unsigned long)(size) >= (unsigned long)(nb));

        remainder_size = size - nb; // 计算切分出所需chunk后剩余部分大小
        unlink(av, victim, bck, fwd); // 从链表取出victim

        // 无法切割
        if (remainder_size < MINSIZE)
        {
          set_inuse_bit_at_offset(victim, size);
          if (av != &main_arena)
            victim->size |= NON_MAIN_ARENA;
        }
        else // 可以切割，将切割出的remainder放入unsored bin
        {
          remainder = chunk_at_offset(victim, nb);
          bck = unsorted_chunks(av);
          fwd = bck->fd;
          if (__glibc_unlikely(fwd->bk != bck))
          {
            errstr = "malloc(): corrupted unsorted chunks 2";
            goto errout;
          }
          remainder->bk = bck;
          remainder->fd = fwd;
          bck->fd = remainder;
          fwd->bk = remainder;
          // 若剩余部分chunk属于smallbin，将分配区的last_remainder chunk设置为remainder
          if (in_smallbin_range(nb))
            av->last_remainder = remainder;
          if (!in_smallbin_range(remainder_size))
          {
            remainder->fd_nextsize = NULL;
            remainder->bk_nextsize = NULL;
          }
          set_head(victim, nb | PREV_INUSE |
                               (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head(remainder, remainder_size | PREV_INUSE);
          set_foot(remainder, remainder_size);
        }
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p;
      }
    }

  // 均找不到可用chunk, 则切top chunk
  use_top:
    victim = av->top;
    size = chunksize(victim);

    if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE))
    {
      remainder_size = size - nb; // 切割出remainder
      remainder = chunk_at_offset(victim, nb);
      av->top = remainder; // remainder成为新的top chunk
      // 设置标志位
      set_head(victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head(remainder, remainder_size | PREV_INUSE);

      check_malloced_chunk(av, victim, nb);
      void *p = chunk2mem(victim);
      alloc_perturb(p, bytes);
      return p; // 返回top chunk切割出的victim
    }
    else if (have_fastchunks(av)) // 看是否有fastchunk
    {
      malloc_consolidate(av); // 进一步处理fastchunk放入unsorted bin
      if (in_smallbin_range(nb)) // 再重新赋值idx找
        idx = smallbin_index(nb);
      else
        idx = largebin_index(nb);
    }
    else
    {
      void *p = sysmalloc(nb, av); // 系统调用sysmalloc向操作系统申请内存返回堆块
      if (p != NULL)
        alloc_perturb(p, bytes);
      return p;
    }
  } // 分配不到则死循环，在其他线程中找，要么报错要么找到并返回
} 
```

##### checked_request2size

```c
// 可用于prev_size复用
#define checked_request2size(req, sz)
if (REQUEST_OUT_OF_RANGE (req)) { // 看是否超过范围
  __set_errno (ENOMEM);
  return 0;
}
(sz) = request2size (req); // 将申请内存转换为适合内存分配的块大小

#define request2size(req) (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?
MINSIZE : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
      // = bytes + sizeof(size_t)*2 + sizeof(size_t) - 1 关于 0x10 向下取整
```

- `bytes`变化堆块大小使得与下一个堆块的`prev_size`重合，则8+7向下取整0，最终只申请`prev_size+size+bytes`
- 若超过下一个堆块的`prev_size`，则9+7向下取整0x10，最终申请`prev_size+size+bytes+prev_size+size`

<img src="/img/source_analyze.zh-cn.assets/image-20241119131202911.png" alt="图片无法加载" />

##### get_max_fast

```c
#define get_max_fast() global_max_fast

#define set_max_fast(s) 
	global_max_fast = (((s) == 0) ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))

set_max_fast(DEFAULT_MXFAST); // malloc_init_state函数中

#define DEFAULT_MXFAST (64 * SIZE_SZ / 4) // 64*8/4=128=0x80
```

##### fastbin_index

```c
#define fastbin_index(sz) ((((unsigned int)(sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
// 64位下 申请size右移4位再减2，最小的size为0x20，则0x20/16-2=0索引
```

##### chunk_size

```c
#define chunksize(p) ((p)->size & ~(SIZE_BITS)) // 去除3个标志位后得到chunk的size
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

##### chunk2mem

```c
#define chunk2mem(p) ((void *)((char *)(p) + 2 * SIZE_SZ))
// 将指向 prev_size 的指针偏移2个机器字长后指向 fd
```

##### in_smallbin_range

```c
#define in_smallbin_range(sz) ((unsigned long)(sz) < (unsigned long)MIN_LARGE_SIZE)
// 小于 largebin 最小的 size 
#define MIN_LARGE_SIZE ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
// (64 - 0)*(2 * 8) = 0x400 = 1024
#define NSMALLBINS 64
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define SMALLBIN_WIDTH MALLOC_ALIGNMENT
#define MALLOC_ALIGNMENT (2 * SIZE_SZ)
```

##### malloc_consolidate

遍历fastbin，合并并放入unsorted bin中

```c
static void malloc_consolidate(mstate av)
{
  mfastbinptr *fb;
  mfastbinptr *maxfb;
  mchunkptr p;
  mchunkptr nextp;
  mchunkptr unsorted_bin;
  mchunkptr first_unsorted;
    
  mchunkptr nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int nextinuse;
  mchunkptr bck;
  mchunkptr fwd;

  if (get_max_fast() != 0) // 已初始化
  {
    clear_fastchunks(av); // 清除fastchunk的标志位

    unsorted_bin = unsorted_chunks(av);
    // #define unsorted_chunks(M) (bin_at(M, 1)) 获取unsorted_bin

    maxfb = &fastbin(av, NFASTBINS - 1); // 指向最大size的fastbin地址
      // #define NFASTBINS (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)
    fb = &fastbin(av, 0); // 指向最小size的fastbin地址
    do
    {
      p = atomic_exchange_acq(fb, 0); // 将fastbin置为0，而p指向fastbin第一个chunk
      if (p != 0)
      {
        do
        {
          check_inuse_chunk(av, p); // 具体是检查下一个相邻chunk的prev_size位
          nextp = p->fd; // p的下一个chunk

          size = p->size & ~(PREV_INUSE | NON_MAIN_ARENA); // p指向chunk的size
          nextchunk = chunk_at_offset(p, size); // 下一个chunk
            // #define chunk_at_offset(p, s) ((mchunkptr)(((char *)(p)) + (s)))
          nextsize = chunksize(nextchunk); // 下一个chunk的size

          if (!prev_inuse(p)) // 即p相邻上一个chunk空闲: 在small/large/unsorted bin中
          {
            // 前向合并
            prevsize = p->prev_size;
            size += prevsize;	// size变为前一个chunk大小加上当前size大小
            p = chunk_at_offset(p, -((long)prevsize)); // p此时指向相邻上一个chunk
            unlink(av, p, bck, fwd); // 将p从双向链表中取出
          }
		  // 下一个 chunk 不是 top chunk
          if (nextchunk != av->top) 
          {
            nextinuse = inuse_bit_at_offset(nextchunk, nextsize); 
            if (!nextinuse)// 下一个chunk+nextsize偏移的prev_inuse为0，表示下一个chunk空闲
            {
              // 后向合并
              size += nextsize;
              unlink(av, nextchunk, bck, fwd); // 将下一个chunk也脱链
            }
            else
              clear_inuse_bit_at_offset(nextchunk, 0); // 下一个chunk的prev_inuse设为0，即当前chunk此时空闲

            first_unsorted = unsorted_bin->fd; // 第一个unsorted bin
            unsorted_bin->fd = p;
            first_unsorted->bk = p; // 在unsorted bin链表头加入p，此处改unsorted bin原先chunk的指针
			
            // 在 large bin 中将两个nextsize指针置空
            if (!in_smallbin_range(size))
            {
              p->fd_nextsize = NULL;
              p->bk_nextsize = NULL;
            }

            set_head(p, size | PREV_INUSE); // 设置p的size
            p->bk = unsorted_bin;
            p->fd = first_unsorted; // 此处将p的bk和fd指针更改
            set_foot(p, size); // 设置下一个chunk的prev_size为size
          }
          else
          { // 下一个chunk是top chunk，则将当前chunk合并入top chunk
            size += nextsize;
            set_head(p, size | PREV_INUSE);
            av->top = p;
          }

        } while ((p = nextp) != 0); // 内部循环某个fastbin的链表中的chunk，合并+放入unsorted bin中
      }
    } while (fb++ != maxfb); // 循环整个fastbin 
  }
  else // global_max_fast为0则初始化
  {
    malloc_init_state(av);
    check_malloc_state(av);
  }
}
```

##### malloc_init_state

```c
static void malloc_init_state(mstate av)
{
  int i;
  mbinptr bin;
    
  for (i = 1; i < NBINS; ++i)
  {
    bin = bin_at(av, i);
    bin->fd = bin->bk = bin; // 初始化创建循环链表
  }

#if MORECORE_CONTIGUOUS
  if (av != &main_arena)
#endif
    set_noncontiguous(av);
  if (av == &main_arena) // 若为主线程
    set_max_fast(DEFAULT_MXFAST); // 设置global_max_fast为0x80，即fastbin最大size
  av->flags |= FASTCHUNKS_BIT; // FASTCHUNKS_BIT = 1U 设置标志位

  av->top = initial_top(av); // 初始化分配区的top chunk
}
```

##### unlink

```c
#define unlink(AV, P, BK, FD)
  {                                                                                                     
    FD = P->fd; // p在bin中下一个chunk
    BK = P->bk; // p在bin中上一个chunk
    if (__builtin_expect(FD->bk != P || BK->fd != P, 0))
        // 检查fd和bk应该对应相互指向对方
      malloc_printerr(check_action, "corrupted double-linked list", P, AV);
    else
    {
      FD->bk = BK;
      BK->fd = FD; // 将中间的p chunk脱离
      if (!in_smallbin_range(P->size) && __builtin_expect(P->fd_nextsize != NULL, 0))
      { // 若 P 属于 large bin 且 fd->nextsize 不为空
        if (__builtin_expect(P->fd_nextsize->bk_nextsize != P, 0) || 
            __builtin_expect(P->bk_nextsize->fd_nextsize != P, 0))
          // 判断 fd_nextsize 和 bk_nextsize 是否合法: 相互对应指向对方
          malloc_printerr(check_action,"corrupted double-linked list (not small)", P, AV);
          
        // 下一个chunk的fd_nextsize为空
        if (FD->fd_nextsize == NULL)
        {
          if (P->fd_nextsize == P) // p的fd_nextsize指向自己: p和FD size相等
            FD->fd_nextsize = FD->bk_nextsize = FD; // 此时FD替代p将两个nextsize指针指向自己
          else // p的fd_nextsize不指向自己: p和FD size相等
          { // 此时FD替代p将两个nextsize指针指向p原本指向的chunk
            FD->fd_nextsize = P->fd_nextsize;
            FD->bk_nextsize = P->bk_nextsize;
            P->fd_nextsize->bk_nextsize = FD;
            P->bk_nextsize->fd_nextsize = FD; // 相互指
          }
        }
        // 下一个chunk的fd_nextsize不为空: p和FD size不相等
        else
        {
          P->fd_nextsize->bk_nextsize = P->bk_nextsize;
          P->bk_nextsize->fd_nextsize = P->fd_nextsize; 
          // FD的两个nextsize替换为p的两个nextsize
        }
      }
    }
  }
```

##### alloc_perturb

```c
static void alloc_perturb(char *p, size_t n)
{
  if (__glibc_unlikely(perturb_byte)) // 若perturb_byte不为0
    memset(p, perturb_byte ^ 0xff, n); // 设置内存为该值的最低1字节，可能导致程序崩溃
}
```



#### 2.27

##### __libc_malloc

主要讲解变化

```c
void *__libc_malloc(size_t bytes)
{
  // 增加
#if USE_TCACHE
  size_t tbytes;
  checked_request2size(bytes, tbytes);
  size_t tc_idx = csize2tidx(tbytes); // 获取tcache的索引

  MAYBE_INIT_TCACHE(); // tcache初始化
  /*
  	#define MAYBE_INIT_TCACHE()
  		if (__glibc_unlikely(tcache == NULL))
    		tcache_init();
  */

  DIAG_PUSH_NEEDS_COMMENT;
  // mp_.tcache_bins = TCACHE_MAX_BINS = 64
  if (tc_idx < mp_.tcache_bins && tcache && tcache->entries[tc_idx] != NULL)
  { // 在tcache范围内，且entries指向不为空
    return tcache_get(tc_idx); // 获取tcache并返回
  }
  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)
  {
    victim = _int_malloc(&main_arena, bytes);
    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           &main_arena == arena_for_chunk(mem2chunk(victim)));
    return victim;
  }

// 变化
/*
  if (ar_ptr != NULL) 
    (void) mutex_unlock (&ar_ptr->mutex)
*/
  if (ar_ptr != NULL)
    __libc_lock_unlock(ar_ptr->mutex); 
}
```

##### _int_malloc

```c
// 增加 fastbin中
#if USE_TCACHE
        size_t tc_idx = csize2tidx(nb);
        if (tcache && tc_idx < mp_.tcache_bins) // 若在tcache范围内
        {
          mchunkptr tc_victim;

          while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = *fb) != NULL)
          { // 小于mp_.tcache_count=7即tcache没装满：遍历将fastbin中chunk加到tcache中直到满7个或fastbin为空
            if (SINGLE_THREAD_P) // 单线程
              *fb = tc_victim->fd; // 取出一个空闲chunk
            else
            {
              REMOVE_FB(fb, pp, tc_victim); // 取出一个空闲chunk
              if (__glibc_unlikely(tc_victim == NULL))
                break;
            }
            tcache_put(tc_victim, tc_idx); // 把fastbin中拿出的chunk加入到tcache链表中
          }
        }
#endif

// 增加 small bin中
#if USE_TCACHE
      size_t tc_idx = csize2tidx(nb);
      if (tcache && tc_idx < mp_.tcache_bins)
      {
        mchunkptr tc_victim;
        while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = last(bin)) != bin)
        {
          if (tc_victim != 0)
          {
            bck = tc_victim->bk;
            set_inuse_bit_at_offset(tc_victim, nb); // 设置tc_victim物理相邻的下一个chunk的prev_inuse位
            if (av != &main_arena)
              set_non_main_arena(tc_victim);
            bin->bk = bck;
            bck->fd = bin;

            tcache_put(tc_victim, tc_idx);// 把small bin中拿出的chunk加入到tcache中
          }
        }
      }
#endif
```

##### REMOVE_FB

```c
#define REMOVE_FB(fb, victim, pp) // 封装成一个宏,CAS操作
// 从刚刚得到的空闲chunk链表指针中取出第一个空闲的chunk(victim)
// 并将链表头设置为该空闲chunk的下一个chunk(victim->fd)
  do                              
  {                               
    victim = pp;                  
    if (victim == NULL)           
      break;                      
  } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd, victim)) != victim);
```



##### tcache_init

```c
static void tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof(tcache_perthread_struct);

  if (tcache_shutting_down)
    return;

  arena_get(ar_ptr, bytes);
  victim = _int_malloc(ar_ptr, bytes); // 通过_int_malloc获取内存chunk
  if (!victim && ar_ptr != NULL) 
  {
    ar_ptr = arena_get_retry(ar_ptr, bytes); // 获取下一个分配区
    victim = _int_malloc(ar_ptr, bytes); // 再次malloc
  }

  if (ar_ptr != NULL)
    __libc_lock_unlock(ar_ptr->mutex);
  // 申请成功
  if (victim)
  {
    tcache = (tcache_perthread_struct *)victim; // 将victim给tcache，每个线程都有一个tcache缓解竞争
    memset(tcache, 0, sizeof(tcache_perthread_struct)); // 清空数据
  }
}
```

##### tcache_get

```c
static __always_inline void *tcache_get(size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx]; // 从entries中取出入口指针
  assert(tc_idx < TCACHE_MAX_BINS);
  assert(tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next; // 更新entries，指向其下一个chunk
  --(tcache->counts[tc_idx]); // counts减少一个
  return (void *)e;
}
```

##### tcache_put

```c
static __always_inline void tcache_put(mchunkptr chunk, size_t tc_idx)
{ // 将其放入tcache中
  tcache_entry *e = (tcache_entry *)chunk2mem(chunk);
  assert(tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

##### unlink

```c
#define unlink(AV, P, BK, FD) {
// 增加 开头加了一个判断：P的 chunk 大小需要等于下一个 chunk 的 prev_size
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))
      malloc_printerr ("corrupted size vs. prev_size");			      
```



### sysmalloc

#### 2.23

##### sysmalloc

```c
static void *sysmalloc(INTERNAL_SIZE_T nb, mstate av) // 需要申请的大小need_bytes + mainarena
{
  mchunkptr old_top;        /* av->top的原始值 */
  INTERNAL_SIZE_T old_size; /* av->top大小 */
  char *old_end;            /* av->top结束地址 */

  long size; /* 给MORECORE或mmap调用的参数 */
  char *brk; /* MORECORE返回值 */

  long correction; /* 给第二个MORECORE调用的参数 */
  char *snd_brk;   /* MORECORE第二个返回值 */

  INTERNAL_SIZE_T front_misalign; /* 新空间前的不可用字节 */
  INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
  char *aligned_brk;              /* aligned offset into brk */

  mchunkptr p;                  /* the allocated/returned chunk */
  mchunkptr remainder;          /* remainder from allocation */
  unsigned long remainder_size; /* its size */

  size_t pagesize = GLRO(dl_pagesize);
  bool tried_mmap = false; // 标记是否尝试过mmap
  
  if (av == NULL || // 无arena，则也没有top chunk
     ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && // 大于mmap阈值则使用mmap
     (mp_.n_mmaps < mp_.n_mmaps_max))) // 且mmap的次数小于最大的nmap的次数
  {
    char *mm; /* mmap调用的返回值 */
  // 走mmap调用
  try_mmap:
/* 
	mmap直接分配内存，不需要添加到管理free bin的链表中，所以不存在chunk前后关系
	当chunk被使用时无法借用后一个chunk的prev_size字段，需要将prev_size的SIZE_SZ加上进行内存向上取整对齐
	nb 向上对齐为 size
*/
    if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
      size = ALIGN_UP(nb + SIZE_SZ, pagesize);
    else
      size = ALIGN_UP(nb + SIZE_SZ + MALLOC_ALIGN_MASK, pagesize);
    tried_mmap = true;

    if ((unsigned long)(size) > (unsigned long)(nb))
    { 
      // 若size>nb 调用MMAP
      mm = (char *)(MMAP(0, size, PROT_READ | PROT_WRITE, 0));

      if (mm != MAP_FAILED) // MMAP成功
      {
        if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
        { // 若对齐，进行检查，不可用字节设为0
          assert(((INTERNAL_SIZE_T)chunk2mem(mm) & MALLOC_ALIGN_MASK) == 0);
          front_misalign = 0;
        }
        else // 未对齐获取不可用字节大小
          front_misalign = (INTERNAL_SIZE_T)chunk2mem(mm) & MALLOC_ALIGN_MASK;
        if (front_misalign > 0)
        {
          correction = MALLOC_ALIGNMENT - front_misalign; // 进行纠正
          p = (mchunkptr)(mm + correction);
          p->prev_size = correction;
          set_head(p, (size - correction) | IS_MMAPPED);
        }
        else
        {
          p = (mchunkptr)mm;
          set_head(p, size | IS_MMAPPED); // 设置size中标志
        }

        int new = atomic_exchange_and_add(&mp_.n_mmaps, 1) + 1; // mmap的数量加1
        atomic_max(&mp_.max_n_mmaps, new); // 取最大更新max_n_mmaps

        unsigned long sum;
        sum = atomic_exchange_and_add(&mp_.mmapped_mem, size) + size; // mmap的内存大小加上size
        atomic_max(&mp_.max_mmapped_mem, sum); // 取最大值更新max_mmapped_mem

        check_chunk(av, p);
        return chunk2mem(p); // 返回内存
      }
    }
  }

  if (av == NULL)
    return 0; // mmap失败且无arena，系统调用失败

  // 有arena则有top chunk，需要扩展top chunk，切割内存返回
  old_top = av->top; // 获取原top chunk
  old_size = chunksize(old_top); // 获取原top chunk 大小
  old_end = (char *)(chunk_at_offset(old_top, old_size)); // 获取原top chunk结束地址

  brk = snd_brk = (char *)(MORECORE_FAILURE); // 初始化brk和snd_brk为0，#define MORECORE_FAILURE 0

  assert((old_top == initial_top(av) && old_size == 0) ||
         // 1. arena第一次结构体初始化时，top chunk未被分配，此时top chunk指向自己, size为0
         ((unsigned long)(old_size) >= MINSIZE &&
         prev_inuse(old_top) &&
         ((unsigned long)old_end & (pagesize - 1)) == 0));
    	 // 2. 非第一次，top chunk已有，检查size大于等于0x20，prev_inuse置位，且与页面对齐

  assert((unsigned long)(old_size) < (unsigned long)(nb + MINSIZE));
  // top chunk 不够用：原top chunk 大小 < 申请大小+0x20 

  // 非主线程
  if (av != &main_arena)
  {
    heap_info *old_heap, *heap;
    size_t old_heap_size;

    old_heap = heap_for_ptr(old_top); // 获取原始heap堆段的起始地址，heap_info在堆块开头
    old_heap_size = old_heap->size;	// 获取原始堆大小
    // 尝试扩展堆块
    if ((long)(MINSIZE + nb - old_size) > 0 && grow_heap(old_heap, MINSIZE + nb - old_size) == 0)
    {// 堆块扩展成功
      // 更新
      av->system_mem += old_heap->size - old_heap_size;
      arena_mem += old_heap->size - old_heap_size;
      // 新堆顶块大小: old_heap + old_heap->size - old_top
      set_head(old_top, (((char *)old_heap + old_heap->size) - (char *)old_top) | PREV_INUSE);
    } // 或创建新堆
    else if ((heap = new_heap(nb + (MINSIZE + sizeof(*heap)), mp_.top_pad)))
    {
      // 创建新堆后更新数据
      heap->ar_ptr = av; // 更新 arena 管理分配区
      heap->prev = old_heap; 
      av->system_mem += heap->size;
      arena_mem += heap->size;
        
	  // 更新新的top chunk位置，之前的top chunk作废
      top(av) = chunk_at_offset(heap, sizeof(*heap));
      // top chunk大小: heap大小减去开头heap结构体大小
      set_head(top(av), (heap->size - sizeof(*heap)) | PREV_INUSE);

      /* 释放旧的top chunk,  */
      old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK; // 预留两个chunk和align来作为标记，防止错误
      set_head(chunk_at_offset(old_top, old_size + 2 * SIZE_SZ), 0 | PREV_INUSE);
      if (old_size >= MINSIZE)
      {
        set_head(chunk_at_offset(old_top, old_size), (2 * SIZE_SZ) | PREV_INUSE);
        set_foot(chunk_at_offset(old_top, old_size), (2 * SIZE_SZ));
        set_head(old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
        _int_free(av, old_top, 1);
      }
      else
      { // 不够大小直接设置标记，不释放了
        set_head(old_top, (old_size + 2 * SIZE_SZ) | PREV_INUSE);
        set_foot(old_top, (old_size + 2 * SIZE_SZ));
      }
    }
    else if (!tried_mmap)
      goto try_mmap; // 还是不行，只能调mmap
  }
  else// 主线程：main_arena
  {
    size = nb + mp_.top_pad + MINSIZE; // 请求足够的空间来扩展top chunk，nb需要申请走
      
    if (contiguous(av)) // 若top chunk 连续
      size -= old_size; // 实际涨一点大小即可，不需要再申请nb那么大的size，nb比top chunk还大
    size = ALIGN_UP(size, pagesize);

    if (size > 0)
    {
      brk = (char *)(MORECORE(size)); // 通过brk来扩展
        // 系统调用的__brk是将最高地址指针向高地址推，参数为最终地址，返回最终地址
        // glibc的sbrk参数是大小，将扩展多少大小向高地址，返回原来未扩展时的顶
      LIBC_PROBE(memory_sbrk_more, 2, brk, size);
    }

    if (brk != (char *)(MORECORE_FAILURE))
    { // brk调用成功，将top chunk 扩展了size大小
      void (*hook)(void) = atomic_forced_read(__after_morecore_hook);
      if (__builtin_expect(hook != NULL, 0))
        (*hook)(); // after_morecore_hook不为空则执行
    }
    else
    { // 若brk调用失败，说明不能再维护连续内存
      if (contiguous(av)) // 由于之前连续减去过old_size，此处要加回来
        size = ALIGN_UP(size + old_size, pagesize);

      if ((unsigned long)(size) < (unsigned long)(MMAP_AS_MORECORE_SIZE))
        // #define MMAP_AS_MORECORE_SIZE (1024 * 1024) 小于则使用mmap最小的size
        size = MMAP_AS_MORECORE_SIZE;

      if ((unsigned long)(size) > (unsigned long)(nb))
      { // 若size可以包含申请的大小
        char *mbrk = (char *)(MMAP(0, size, PROT_READ | PROT_WRITE, 0)); // mmap系统调用

        if (mbrk != MAP_FAILED)
        { // mmap未失败
          brk = mbrk; // 新mmap的内存起始位置
          snd_brk = brk + size; // 新的mmap的内存结束位置
          set_noncontiguous(av); // 设置arena为不连续
        }
      }
    }
      
	// 若brk不再是0，已经获取了内存地址
    if (brk != (char *)(MORECORE_FAILURE))
    {
      if (mp_.sbrk_base == 0)
        mp_.sbrk_base = brk; // 更新 sbrk_base
      av->system_mem += size;

      // 【1】: topchunk通过brk向下扩展了一小段，nb申请后也够用
      if (brk == old_end && snd_brk == (char *)(MORECORE_FAILURE))
        set_head(old_top, (size + old_size) | PREV_INUSE);
      // 【2】: arena连续则不是mmap出来的，old_size排除了未初始化情况，越brk却越小的情况
      else if (contiguous(av) && old_size && brk < old_end)
      { // 崩溃
        malloc_printerr(3, "break adjusted to free malloc space", brk, av);
      }
      else
      {
        front_misalign = 0;
        end_misalign = 0;
        correction = 0;
        aligned_brk = brk;
		// 【3】: 新分配的内存地址大于原来top chunk结束地址，不连续但分配区连续标志位置位 
        if (contiguous(av)) // 说明是其他线程调用了brk在堆上分配了内存
        {
          if (old_size)
            av->system_mem += brk - old_end; // 其他线程分配的内存一并计入
	      // 对齐操作
          front_misalign = (INTERNAL_SIZE_T)chunk2mem(brk) & MALLOC_ALIGN_MASK;
          // 假设两个top chunk 1,2, 计算1和2中间不对齐的部分
          if (front_misalign > 0)
          {
            // 获取校正，即2开头需要加上该校正，得到地址才和MALLOC_ALIGN_MASK对齐
            correction = MALLOC_ALIGNMENT - front_misalign; 
            aligned_brk += correction; // 不向上对齐，向下对齐，此时aligned_brk指向top chunk
          }

          correction += old_size; // top chunk的大小
		  // 2结尾也同样对齐，correction为 top chunk结束位置到新分配内存空间的大小
          end_misalign = (INTERNAL_SIZE_T)(brk + size + correction);
          correction += (ALIGN_UP(end_misalign, pagesize)) - end_misalign;

          assert(correction >= 0);
          snd_brk = (char *)(MORECORE(correction)); // 再次调用brk补充correction的内存
            
          if (snd_brk == (char *)(MORECORE_FAILURE)) // 失败
          {
            correction = 0;
            snd_brk = (char *)(MORECORE(0)); // 重置为原来分配内存的brk结束地址
          }
          else
          {
            void (*hook)(void) = atomic_forced_read(__after_morecore_hook);
            if (__builtin_expect(hook != NULL, 0))
              (*hook)(); // 提供hook点
          }
        }
        // 【4】: 新分配的内存地址大于原来top chunk结束地址，均不连续
        else
        {
          if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
            assert(((unsigned long)chunk2mem(brk) & MALLOC_ALIGN_MASK) == 0);
          else
          {
            front_misalign = (INTERNAL_SIZE_T)chunk2mem(brk) & MALLOC_ALIGN_MASK;
            if (front_misalign > 0)
            {
              aligned_brk += MALLOC_ALIGNMENT - front_misalign;
            }
          }
          if (snd_brk == (char *)(MORECORE_FAILURE))
          {
            snd_brk = (char *)(MORECORE(0)); // 同样为了对齐进行brk调用申请来补充新top chunk
          }
        }

        if (snd_brk != (char *)(MORECORE_FAILURE)) // 表示申请成功
        { // 需要对不连续的原先top chunk进行处理
          av->top = (mchunkptr)aligned_brk; // 上一个不连续的top chunk
          set_head(av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
          av->system_mem += correction;
            
          if (old_size != 0)
          {
            old_size = (old_size - 4 * SIZE_SZ) & ~MALLOC_ALIGN_MASK;
            set_head(old_top, old_size | PREV_INUSE);
			// 设置标记防止后续需要后续堆块prev_size情况的错误
            chunk_at_offset(old_top, old_size)->size = (2 * SIZE_SZ) | PREV_INUSE;
            chunk_at_offset(old_top, old_size + 2 * SIZE_SZ)->size = (2 * SIZE_SZ) | PREV_INUSE;

            if (old_size >= MINSIZE)
            {
              _int_free(av, old_top, 1); // 释放掉之前的 top chunk
            }
          }
        }
      }
    }
  }
  // 更新
  if ((unsigned long)av->system_mem > (unsigned long)(av->max_system_mem))
    av->max_system_mem = av->system_mem;
  check_malloc_state(av);

  p = av->top;
  size = chunksize(p);
  // 进行 top chunk 的分配，切一块分配给nb，剩余为top chunk
  if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE))
  {
    remainder_size = size - nb;
    remainder = chunk_at_offset(p, nb);
    av->top = remainder;
    set_head(p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);
    check_malloced_chunk(av, p, nb);
    return chunk2mem(p);
  }

  __set_errno(ENOMEM); // 抓取所有未申请到内存情况
  return 0;
}
```

##### MMAP

```c
#define MMAP(addr, size, prot, flags)
	__mmap((addr), (size), (prot), (flags) | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
```

##### initial_top

```c
// 为方便，unsorted bin在第一次调用时可作为虚假的top chunk
#define initial_top(M) (unsorted_chunks(M))
#define unsorted_chunks(M) (bin_at(M, 1))
```

##### heap_for_ptr

```c
#define heap_for_ptr(ptr) 
	((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))
/* 
	非主线程的堆都按照 HEAP_MAX_SIZE对齐分配，
	ptr & ~0xfffff 即将ptr的后5位置0，可以获取 heap_info 结构体的起始地址
*/
#  define HEAP_MAX_SIZE (1024 * 1024) /* 0x100000，必须是2的幂 */
```

##### grow_heap

```c
static int grow_heap (heap_info *h, long diff) // diff为差的size
{
  size_t pagesize = GLRO (dl_pagesize);
  long new_size;

  diff = ALIGN_UP (diff, pagesize);
  new_size = (long) h->size + diff; // 扩展堆后 新的size
  if ((unsigned long) new_size > (unsigned long) HEAP_MAX_SIZE)
    return -1; // 若大于HEAP_MAX_SIZE则失败

  if ((unsigned long) new_size > h->mprotect_size) // 若新堆块大小超出mprotect保护的大小
  {
    if (__mprotect ( // 调用mprotect将超过的部分设置为可读可写
      (char *) h + h->mprotect_size,
      (unsigned long) new_size - h->mprotect_size,
      PROT_READ | PROT_WRITE)
  != 0)
      return -2;// 设置失败

    h->mprotect_size = new_size; // 设置成功后将mprotect_size更新
  }

  h->size = new_size; // 更新堆大小
  LIBC_PROBE (memory_heap_more, 2, h, h->size);
  return 0;
}
```

##### new_heap

```c
static heap_info *internal_function new_heap (size_t size, size_t top_pad)
{
  size_t pagesize = GLRO (dl_pagesize);
  char *p1, *p2;
  unsigned long ul;
  heap_info *h;

  if (size + top_pad < HEAP_MIN_SIZE)
    size = HEAP_MIN_SIZE; // 大小加填充后小于最小size则用HEAP_MIN_SIZE
  else if (size + top_pad <= HEAP_MAX_SIZE)
    size += top_pad; // 小于最大size则用【大小+填充】
  else if (size > HEAP_MAX_SIZE)
    return 0; // 大于最大size则创建失败
  else
    size = HEAP_MAX_SIZE; 
  size = ALIGN_UP (size, pagesize); // 确定创建的对齐堆大小

  p2 = MAP_FAILED;
  if (aligned_heap_area) // aligned_heap_area记录了上一次分配的堆
    { // mmap申请，其与HEAP_MAX_SIZE对齐
      p2 = (char *) MMAP (aligned_heap_area, HEAP_MAX_SIZE, PROT_NONE,MAP_NORESERVE);
      aligned_heap_area = NULL;
      // mmap成功但未对齐
      if (p2 != MAP_FAILED && ((unsigned long) p2 & (HEAP_MAX_SIZE - 1)))
        {
          __munmap (p2, HEAP_MAX_SIZE); // 取消分配，删除地址区域的对象映射
          p2 = MAP_FAILED;
        }
    }
  if (p2 == MAP_FAILED)
    { // mmap申请只保证页面对齐，于是申请两倍HEAP_MAX_SIZE，<<1即乘以2，总有关于HEAP_MAX_SIZE对齐的地方
      p1 = (char *) MMAP (0, HEAP_MAX_SIZE << 1, PROT_NONE, MAP_NORESERVE);
      if (p1 != MAP_FAILED)
        {
          // 从p1出发截取对齐HEAP_MAX_SIZE的位置p2
          p2 = (char *) (((unsigned long) p1 + (HEAP_MAX_SIZE - 1)) & ~(HEAP_MAX_SIZE - 1));
          ul = p2 - p1; 
          if (ul)
            __munmap (p1, ul); // 将多出来那段映射删除
          else
            aligned_heap_area = p2 + HEAP_MAX_SIZE; // 否则刚好可以申请，更新aligned_heap_area留后续使用
          __munmap (p2 + HEAP_MAX_SIZE, HEAP_MAX_SIZE - ul); // 记录后再将后面这块映射删除
          // 此时获得p2与HEAP_MAX_SIZE对齐，大小为HEAP_MAX_SIZE的堆块
        }
      else
        { // 尝试只申请一倍，刚好已经与HEAP_MAX_SIZE对齐得堆块
          p2 = (char *) MMAP (0, HEAP_MAX_SIZE, PROT_NONE, MAP_NORESERVE);
          if (p2 == MAP_FAILED) // 分配失败返回0
            return 0;

          if ((unsigned long) p2 & (HEAP_MAX_SIZE - 1)) // 未对齐返回0
            {
              __munmap (p2, HEAP_MAX_SIZE); // 取消分配
              return 0;
            }
        }
    }
  if (__mprotect (p2, size, PROT_READ | PROT_WRITE) != 0)
      // mprotect只将HEAP_MAX_SIZE前面的size大小设置可读可写
    {
      __munmap (p2, HEAP_MAX_SIZE);
      return 0;
    }
  h = (heap_info *) p2; // 最终返回p2指向的内存
  h->size = size;
  h->mprotect_size = size;
  LIBC_PROBE (memory_heap_new, 2, h, h->size);
  return h;
}
```

##### MORECORE

```c
#define MORECORE (*__morecore)

void *(*__morecore)(ptrdiff_t) = __default_morecore;

void * __default_morecore (ptrdiff_t increment)
{
  // 调用 __sbrk 增加或减少堆内存
  void *result = (void *) __sbrk (increment);
  if (result == (void *) -1)
    return NULL;

  return result;
}

void * __sbrk (intptr_t increment)
{
  void *oldbrk;

  if (__curbrk == NULL || __libc_multiple_libcs)
  // 若__curbrk为空：即尚未设置堆起始地址
    if (__brk (0) < 0) // 调用__brk(0)获取当前堆顶__curbrk
      return (void *) -1;

  if (increment == 0)
    return __curbrk; // 返回当前堆顶地址

  oldbrk = __curbrk;
  if (increment > 0 // 检测溢出
      ? ((uintptr_t) oldbrk + (uintptr_t) increment < (uintptr_t) oldbrk) // 扩展正值后反而大小变小
      : ((uintptr_t) oldbrk < (uintptr_t) -increment)) // 扩展后变为负值
    {
      __set_errno (ENOMEM);
      return (void *) -1;
    }

  if (__brk (oldbrk + increment) < 0) // 最终调用__brk扩展地址
    return (void *) -1;

  return oldbrk;
}

int __brk (void *addr) // 目标堆顶地址
{
  void *newbrk;

  __curbrk = newbrk = (void *) INLINE_SYSCALL (brk, 1, addr); 
  // 内核brk系统调用调整堆顶地址，此时__curbrk为当前堆顶地址

  if (newbrk < addr)
    {
      __set_errno (ENOMEM); // 操作失败返回-1
      return -1;
    }

  return 0; // 成功返回0
}
```



### free

#### 2.23

##### __libc_free

```c
void __libc_free(void *mem)
{
  mstate ar_ptr;
  mchunkptr p;

  void (*hook)(void *, const void *) = atomic_forced_read(__free_hook); // 原子读free_hook
  if (__builtin_expect(hook != NULL, 0)) // 查看free_hook是否被设置
  {
    (*hook)(mem, RETURN_ADDRESS(0)); // 非空则调用该hook
    return;
 
  if (mem == 0) /* 需要释放的内存为0，free(0)无效 */
    return;

  p = mem2chunk(mem); // 用户内存指针转换为chunk指针

  if (chunk_is_mmapped(p)) /* 若是mmap申请的内存 */
  {
    /* 
    	no_dyn_threshold初始默认为0, free的堆大小大于mmap阈值且小于默认最大的mmap阈值
    	说明mmap需求量大，但耗时大，于是调节阈值mmap_threshold来使得倾向于用brk而非mmap
    	#define DEFAULT_MMAP_THRESHOLD_MAX (4 * 1024 * 1024 * sizeof(long))
    	trim_threshold 为是否 systrim 减少 ptmalloc 保留内存的参考值
    */
    if (!mp_.no_dyn_threshold && p->size > mp_.mmap_threshold && p->size <= DEFAULT_MMAP_THRESHOLD_MAX)
    {
      mp_.mmap_threshold = chunksize(p);
      mp_.trim_threshold = 2 * mp_.mmap_threshold; // 收缩阈值也提高
      LIBC_PROBE(memory_mallopt_free_dyn_thresholds, 2, mp_.mmap_threshold, mp_.trim_threshold);
    }
    munmap_chunk(p); // 调用了__munmap释放映射
    return;
  }
      
  // 内存由ptmalloc申请的而非mmap申请
  ar_ptr = arena_for_chunk(p); // 获取arena
  _int_free(ar_ptr, p, 0); // 调用_int_free进行堆块释放
}
```

##### _int_free

```c
static void _int_free(mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;     /* 释放的chunk的大小 */
  mfastbinptr *fb;          /* 对应的fastbin */
  mchunkptr nextchunk;      /* 内存空间中下一个连续的chunk */
  INTERNAL_SIZE_T nextsize; /* 下一个chunk大小 */
  int nextinuse;            /* 下一个chunk是否在使用 */
  INTERNAL_SIZE_T prevsize; /* 内存空间中上一个连续的chunk */
  mchunkptr bck;            /* 存储bin链表指针 */
  mchunkptr fwd;            /* 存储bin链表指针 */

  const char *errstr = NULL;
  int locked = 0;

  size = chunksize(p); // 获取chunk大小
  // 检查1：-size强制转换为无符号整型会发生模运算转换为接近地址空间的最大值，通过判断p和-size防止指针越界溢出
  if (__builtin_expect((uintptr_t)p > (uintptr_t)-size, 0) || __builtin_expect(misaligned_chunk(p), 0))
  {
      // 检查2：是否与MALLOC_ALIGN_MASK对齐
    errstr = "free(): invalid pointer";
  errout:
    if (!have_lock && locked)
      (void)mutex_unlock(&av->mutex);
    malloc_printerr(check_action, errstr, chunk2mem(p), av);
    return;
  }
  // 若大小比 MINSIZE小或size不对齐，则不能free
  if (__glibc_unlikely(size < MINSIZE || !aligned_OK(size)))
  {
    errstr = "free(): invalid size";
    goto errout;
  }

  check_inuse_chunk(av, p);
    
  // 在 fastbin 范围内
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast())
#if TRIM_FASTBINS
      && (chunk_at_offset(p, size) != av->top) // 且下一个chunk不是top chunk
#endif
  )
  {		// 若下一个chunk大小小于2*0x8=0x10或大于系统可用的内存，进入报错部分
    if (__builtin_expect(chunk_at_offset(p, size)->size <= 2 * SIZE_SZ, 0) || 
        __builtin_expect(chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0))
    {
      if (have_lock || // 有互斥锁则直接进入报错
         	({assert(locked == 0);mutex_lock(&av->mutex);locked = 1; // 无锁则显式上锁之后再检查判断
            		chunk_at_offset(p, size)->size <= 2 * SIZE_SZ || 
            		chunksize(chunk_at_offset(p, size)) >= av->system_mem;
             })
         )
      {
        errstr = "free(): invalid next size (fast)";
        goto errout;
      }
      if (!have_lock)
      { // 读取分配区所分配的内存总量需要对分配区加锁,检查完以后,释放分配区的锁
        (void)mutex_unlock(&av->mutex); // 解锁
        locked = 0;
      }
    }

    free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);

    set_fastchunks(av); // 设置arena fastchunk标志位表明有使用fastbin
    unsigned int idx = fastbin_index(size); // 获取fastbin索引
    fb = &fastbin(av, idx); // fb指向fastbin的地址

    mchunkptr old = *fb, old2; // old为fastbin中第一个chunk
    unsigned int old_idx = ~0u;
    do
    {
      if (__builtin_expect(old == p, 0))
      { // 释放的chunk p和fastbin中第一个chunk是同一个chunk，报错double free
        errstr = "double free or corruption (fasttop)";
        goto errout;
      }
      if (have_lock && old != NULL)
        old_idx = fastbin_index(chunksize(old));
      p->fd = old2 = old; // p的fd指向old，即将p插到第一个chunk位置
      // *fb = p，即将fastbin的fd指向p
    } while ((old = catomic_compare_and_exchange_val_rel(fb, p, old2)) != old2);

    if (have_lock && old != NULL && __builtin_expect(old_idx != idx, 0))
    { // 判断：old的索引是否也是该fastbin对应索引
      errstr = "invalid fastbin entry (free)";
      goto errout;
    }
  }
  // 再次判断，若不是mmap的，则是ptmalloc，前向后向合并放入unsorted bin
  else if (!chunk_is_mmapped(p))
  {
    if (!have_lock)
    {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }

    nextchunk = chunk_at_offset(p, size); // 找到其下一个chunk

    if (__glibc_unlikely(p == av->top)) // 检查是不是释放top chunk
    {
      errstr = "double free or corruption (top)";
      goto errout;
    }
    if (__builtin_expect(contiguous(av) && (char *)nextchunk >= ((char *)av->top + chunksize(av->top)), 0))// 若arena连续且下一个chunk地址大于top chunk的结束地址，即已经到top chunk外
    {
      errstr = "double free or corruption (out)";
      goto errout;
    } // 下一个chunk的prev_inuse未置位表示p是已经释放了的
    if (__glibc_unlikely(!prev_inuse(nextchunk)))
    {
      errstr = "double free or corruption (!prev)";
      goto errout;
    }
	// 获取下一个chunk的大小
    nextsize = chunksize(nextchunk);
    if (__builtin_expect(nextchunk->size <= 2 * SIZE_SZ, 0) || __builtin_expect(nextsize >= av->system_mem, 0))
    { // 大小小于0x10或大于系统内存大小，报错
      errstr = "free(): invalid next size (normal)";
      goto errout;
    }
    free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);

    // 若p的前一个chunk是空闲的，向前合并
    if (!prev_inuse(p))
    {
      prevsize = p->prev_size;
      size += prevsize; // 合并后chunk大小
      p = chunk_at_offset(p, -((long)prevsize)); // p指向前一个chunk
      unlink(av, p, bck, fwd); // 将两个chunk合并脱链
    }
    if (nextchunk != av->top)
    { // 若下一个chunk不是 top chunk
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize); // 下一个chunk的下一个chunk的prev_inuse
      if (!nextinuse) // 表示下一个chunk未使用，空闲，则后向合并
      {
        unlink(av, nextchunk, bck, fwd); // 将下一个chunk脱链
        size += nextsize;
      }
      else // 下一个chunk不空闲
        clear_inuse_bit_at_offset(nextchunk, 0); // 则清除下一个chunk的prev_inuse
	  
      // 准备插入合并的chunk到unsorted bin
      bck = unsorted_chunks(av); // 获取unsorted bin地址
      fwd = bck->fd; // 获取unsorted bin的fd指向的第一个chunk
      if (__glibc_unlikely(fwd->bk != bck)) // 判断：fwd的bk是否反向指回bck
      {
        errstr = "free(): corrupted unsorted chunks";
        goto errout;
      }
      // 将 p 插入到unsorted bin中
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
      {
        p->fd_nextsize = NULL;
        p->bk_nextsize = NULL; // large bin要设置两个nextsize
      }
      bck->fd = p;
      fwd->bk = p; // 此时 p 插入到bin 的 fd 指向的第一个 chunk 位置

      set_head(p, size | PREV_INUSE); // 更新
      set_foot(p, size);

      check_free_chunk(av, p);
    }
    else
    { // 若下一个chunk是 top chunk
      size += nextsize;
      set_head(p, size | PREV_INUSE); // 更新标志
      av->top = p; // 与p后的top chunk合并，更新p为 top chunk地址
      check_chunk(av, p);
    }
    
    // 大小大于 65536，进行堆收缩操作
    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD)
    {
      if (have_fastchunks(av))
        malloc_consolidate(av); // 有fast chunk则将fastbin中chunk合并放入unsorted bin中

      if (av == &main_arena)
      { // 主线程中，brk申请的
#ifndef MORECORE_CANNOT_TRIM // top chunk 大小大于 收缩阈值
        if ((unsigned long)(chunksize(av->top)) >= (unsigned long)(mp_.trim_threshold))
          systrim(mp_.top_pad, av); // 进行top chunk收缩操作
#endif
      }
      else // 非主线程中，mmap申请的
      {
        heap_info *heap = heap_for_ptr(top(av)); // 先找到heap结构体
        assert(heap->ar_ptr == av);
        heap_trim(heap, mp_.top_pad);// 进行堆收缩操作
      }
    }

    if (!have_lock)
    {
      assert(locked);
      (void)mutex_unlock(&av->mutex); // 解锁
    }
  }
  else // 若是mmap的chunk，则释放映射，类似__libc_free中的检查
  {
    munmap_chunk(p);
  }
}
```

##### munmap_chunk

```c
static void internal_function munmap_chunk(mchunkptr p)
{
  INTERNAL_SIZE_T size = chunksize(p); // 获取chunk大小
  assert(chunk_is_mmapped(p)); // 检查是mmap分配
    
  // mmap分配的chunk一般为独立的即p->prev_size为0，因此还是释放一个chunk
  uintptr_t block = (uintptr_t)p - p->prev_size;  // 获取前一个chunk的指针block
  size_t total_size = p->prev_size + size; // 计算两个chunk的总大小

  if (__builtin_expect(((block | total_size) & (GLRO(dl_pagesize) - 1)) != 0, 0))
  { // 检查是否页对齐
    malloc_printerr(check_action, "munmap_chunk(): invalid pointer", chunk2mem(p), NULL);
    return;
  }
  atomic_decrement(&mp_.n_mmaps); // 减少mmap内存快的计数
  atomic_add(&mp_.mmapped_mem, -total_size); // 更新mmap分配的总内存量

  __munmap((char *)block, total_size);
}
```

##### arena_for_chunk

```c
#define arena_for_chunk(ptr)
  (chunk_non_main_arena (ptr) ? heap_for_ptr (ptr)->ar_ptr : &main_arena) 
// 是main_arena直接返回，否则用heap_for_ptr宏

#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)

#define heap_for_ptr(ptr)
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1))) // 对ptr对齐找arena
```

##### systrim

```c
static int
systrim(size_t pad, mstate av)
{
  long top_size;     /* Amount of top-most memory */
  long extra;        /* Amount to release */
  long released;     /* Amount actually released */
  char *current_brk; /* address returned by pre-check sbrk call */
  char *new_brk;     /* address returned by post-check sbrk call */
  size_t pagesize;
  long top_area;

  pagesize = GLRO(dl_pagesize);
  top_size = chunksize(av->top);

  top_area = top_size - MINSIZE - 1; // top chunk 大小 - 0x20 - 1
  if (top_area <= pad) // 若小于则说明 top chunk 本来就没啥空间，直接返回
    return 0;

  extra = ALIGN_DOWN(top_area - pad, pagesize); // 将主分配区中可以缩小的大小对页面对齐后保存在extra中

  if (extra == 0) // 无可收缩则退出
    return 0;

  current_brk = (char *)(MORECORE(0)); // 0 即返回当前的堆顶地址
  if (current_brk == (char *)(av->top) + top_size) // 判断当前堆顶地址就是top chunk地址加上大小后的结束地址(堆顶)
  {
    MORECORE(-extra); // 将堆顶往回收缩extra大小
    void (*hook)(void) = atomic_forced_read(__after_morecore_hook);
    if (__builtin_expect(hook != NULL, 0))
      (*hook)();
    // 新堆顶地址
    new_brk = (char *)(MORECORE(0));
    LIBC_PROBE(memory_sbrk_less, 2, new_brk, extra);

    if (new_brk != (char *)MORECORE_FAILURE) // 若brk成功
    { 
      released = (long)(current_brk - new_brk); // 获取收缩了的部分，即释放归还给操作系统的内存
      if (released != 0)
      {
        av->system_mem -= released; // 更新系统内存大小
        set_head(av->top, (top_size - released) | PREV_INUSE); // 更新top chunk的头
        check_malloc_state(av);
        return 1;
      }
    }
  }
  return 0;
}
```

##### heap_trim

```c
static int internal_function heap_trim (heap_info *heap, size_t pad)
{
  mstate ar_ptr = heap->ar_ptr;
  unsigned long pagesz = GLRO (dl_pagesize);
  mchunkptr top_chunk = top (ar_ptr), p, bck, fwd;
  heap_info *prev_heap;
  long new_size, top_size, top_area, extra, prev_size, misalign;

  while (top_chunk == chunk_at_offset (heap, sizeof (*heap)))
    { // heap结构体地址加上结构体大小若是 top chunk 地址则说明：后续的 top chunk 均为空闲，考虑释放整个 heap
      // 但需要检查该heap的前一个heap是否有足够空间，否则删除后剩余空间太小
      /*	结合sysmalloc中非主线程 top chunk 添加的两个chunk+align
      		【1】[prev_size]
      		【2】[size]		> (2*SIZE_SZ) | PREV_INUSE
      		【3】[prev_size]	> (2*SIZE_SZ)
      		【4】[size]		> 0 | PREV_INUSE
      		【5】[align]
      */
      prev_heap = heap->prev; // 上一个heap堆块
      prev_size = prev_heap->size - (MINSIZE - 2 * SIZE_SZ); // 上一个堆块大小 - 0x10
      p = chunk_at_offset (prev_heap, prev_size); 
      misalign = ((long) p) & MALLOC_ALIGN_MASK;
      p = chunk_at_offset (prev_heap, prev_size - misalign); // 通过对齐操作使得p指向【3,4】chunk
      assert (p->size == (0 | PREV_INUSE)); // 判断一下
      p = prev_chunk (p); // 通过取前一个chunk使得p指向【1,2】chunk
      
      // 计算【1,2,3,4,5】大小
      new_size = chunksize (p) + (MINSIZE - 2 * SIZE_SZ) + misalign;
      assert (new_size > 0 && new_size < (long) (2 * MINSIZE)); // 安全检查 0 < new_size < 0x40
      if (!prev_inuse (p)) // 前一个chunk空闲则加上大小
        new_size += p->prev_size; // 作为新堆块 top chunk大小
      assert (new_size > 0 && new_size < HEAP_MAX_SIZE); // 安全大小检查
      if (new_size + (HEAP_MAX_SIZE - prev_heap->size) < pad + MINSIZE + pagesz)
        break; // 若空间不足够则退出不再释放
      // 更新
      ar_ptr->system_mem -= heap->size;
      arena_mem -= heap->size;
      LIBC_PROBE (memory_heap_free, 2, heap, heap->size);
      
      delete_heap (heap); // 调用宏释放heap
      heap = prev_heap; // 此时heap变为前一个堆heap chunk
      if (!prev_inuse (p))
        {
          p = prev_chunk (p);
          unlink (ar_ptr, p, bck, fwd); // 前向合并 脱链
        }
      assert (((unsigned long) ((char *) p + new_size) & (pagesz - 1)) == 0);
      assert (((char *) p + new_size) == ((char *) heap + heap->size));
      top (ar_ptr) = top_chunk = p; // 更新 top chunk
      set_head (top_chunk, new_size | PREV_INUSE);
    }

  top_size = chunksize (top_chunk); // 获取top chunk大小
  if ((unsigned long)(top_size) < (unsigned long)(mp_.trim_threshold))
    return 0; // 小于阈值无法收缩，退出

  top_area = top_size - MINSIZE - 1;
  if (top_area < 0 || (size_t) top_area <= pad) 
    return 0; // 可收缩值过小，退出

  extra = ALIGN_DOWN(top_area - pad, pagesz);
  if (extra == 0)
    return 0; // 对齐后的区域不足以收缩，退出

  if (shrink_heap (heap, extra) != 0) // 释放刚计算的对齐extra
    return 0;

  ar_ptr->system_mem -= extra;
  arena_mem -= extra; // 更新

  set_head (top_chunk, (top_size - extra) | PREV_INUSE); // 设置标志
  return 1;
}
```

##### shrink_heap

```c
static int shrink_heap (heap_info *h, long diff)
{
  long new_size;

  new_size = (long) h->size - diff; // 减去 diff 后的新堆的大小
  if (new_size < (long) sizeof (*h))
    return -1; // 小于heap结构体大小则退出
    
  if (__glibc_unlikely (check_may_shrink_heap ())) // 检查当前系统环境是否支持通过重新映射的方式释放堆空间
    {
      if ((char *) MMAP ((char *) h + new_size, diff, PROT_NONE, MAP_FIXED) == (char *) MAP_FAILED)
        return -2; // 尝试 mmap 将新释放的内存段重新映射为不可访问的内存区域

      h->mprotect_size = new_size; // 更新mprotect记录的映射大小
    }
  else // 不支持mmap重新映射则调用madvise系统调用，指示OS回收这些内存
    __madvise ((char *) h + new_size, diff, MADV_DONTNEED);

  h->size = new_size; // 更新堆大小
  LIBC_PROBE (memory_heap_less, 2, h, h->size);
  return 0;
}
```

#### 2.27

##### __libc_free

```c
// 增加
MAYBE_INIT_TCACHE(); // tcache初始化
```

##### MAYBE_INIT_TCACHE

```c
# define MAYBE_INIT_TCACHE()
  if (__glibc_unlikely (tcache == NULL)) 
    tcache_init();

static void tcache_init(void)
{
  mstate ar_ptr; // arena指针
  void *victim = 0; // 用于存储分配得到的内存块(tcache_perthread_struct)
  const size_t bytes = sizeof (tcache_perthread_struct); // 分配的字节数
  
  // static __thread bool tcache_shutting_down = false;
  if (tcache_shutting_down) // 若tcache系统关闭则不初始化
    return;

  arena_get (ar_ptr, bytes); // 获取一个arena用于分配内存
  victim = _int_malloc (ar_ptr, bytes); // 从 arena 中分配bytes字节的内存块
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes); // 分配失败重新尝试
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex); // 使用了某个arena，解锁允许其他线程访问

  if (victim) // 内存分配成功
    {
      tcache = (tcache_perthread_struct *) victim; 
      // victim转换为tcache_perthread_struct指针存在全局变量tcache中
      memset (tcache, 0, sizeof (tcache_perthread_struct)); // 初始化内存为0
    }
}
```

##### _int_free

```c
// 增加
#if USE_TCACHE
{
    size_t tc_idx = csize2tidx (size); // 获取tcache的索引
	// 若 tcache已初始化 + tcache索引在范围内 + tcache的数量此时小于7
    if (tcache && tc_idx < mp_.tcache_bins && tcache->counts[tc_idx] < mp_.tcache_count)
    {
        tcache_put (p, tc_idx);// 将chunk放入tcache中
        return;
    }
}
#endif
```

##### tcache_put

```c
static __always_inline void tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx]; // chunk插入tcache中
  tcache->entries[tc_idx] = e; // 设置新入口
  ++(tcache->counts[tc_idx]); // 增加tcache的数量
}
```

#### 2.31

##### _int_free

```c
// 增加
#if USE_TCACHE
 {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins) // tcache已初始化且索引在tcache范围内
    {	// 内存块地址转换为 tcache_entry 结构体指针
		tcache_entry *e = (tcache_entry *) chunk2mem (p);

        if (__glibc_unlikely (e->key == tcache)) // tcache为tcacche_perthread_structure的地址
        {
            tcache_entry *tmp;
            LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
            // 循环检测tcache中是否有与e相等的chunk，可能double free
            for (tmp = tcache->entries[tc_idx]; tmp; tmp = tmp->next)
              if (tmp == e)
                malloc_printerr ("free(): double free detected in tcache 2");
         }
        if (tcache->counts[tc_idx] < mp_.tcache_count)
        { // 将当前内存块放入 tcache 中进行缓存
            tcache_put (p, tc_idx);
            return;
        }
     }
}
#endif
```



### calloc

#### 2.23

##### __libc_calloc

分配一块内存并初始化为零，calloc申请内存不会从tcache中获取，而是直接从堆块中获取

```c
void *__libc_calloc(size_t n, size_t elem_size) // n项，每一项大小为elem_size
{
  mstate av;
  mchunkptr oldtop, p;
  INTERNAL_SIZE_T bytes, sz, csz, oldtopsize;
  void *mem;
  unsigned long clearsize;
  unsigned long nclears;
  INTERNAL_SIZE_T *d;

  bytes = n * elem_size; // 相乘将需要申请的内存大小转换为以字节为单位
  // 判断溢出
#define HALF_INTERNAL_SIZE_T (((INTERNAL_SIZE_T)1) << (8 * sizeof(INTERNAL_SIZE_T) / 2))
  if (__builtin_expect((n | elem_size) >= HALF_INTERNAL_SIZE_T, 0))
  {
    if (elem_size != 0 && bytes / elem_size != n)
    {
      __set_errno(ENOMEM); // 发生整数溢出，退出
      return 0;
    }
  }

  void *(*hook)(size_t, const void *) = atomic_forced_read(__malloc_hook); 
  if (__builtin_expect(hook != NULL, 0)) // 若malloc_hook被定义
  {
    sz = bytes;
    mem = (*hook)(sz, RETURN_ADDRESS(0)); // 调用malloc_hook
    if (mem == 0) // 失败则退出
      return 0;
    return memset(mem, 0, sz); // 并将内存清零
  }
  sz = bytes; // 大小赋值

  arena_get(av, sz); // 获取arena
  if (av)
  {
#if MORECORE_CLEARS
    /* 
    	由于无论是main_arena控制的堆通过sbrk扩展还是非main_arena通过heap_info向后扩展受保护的内存区域
      	新扩展的内存区初始值为0，不需要清空，因此后续需要清理的内存大小只清理与 top chunk 重合区域，提升效率
    */
    oldtop = top(av); // 获取top chunk
    oldtopsize = chunksize(top(av)); // 获取 top chunk 头之后可控制的内存大小
#if MORECORE_CLEARS < 2
    // 主线程 + top chunk需要清空的内存大小为 top chunk 到原先 heap 区域末尾位置
    if (av == &main_arena && oldtopsize <  mp_.sbrk_base + av->max_system_mem - (char *)oldtop)
      oldtopsize = (mp_.sbrk_base + av->max_system_mem - (char *)oldtop);
#endif
    // 非主线程
    if (av != &main_arena)
    { // top chunk 需要清空的内存大小为 top chunk 到原先 heap_info 受保护区域末尾位置
      heap_info *heap = heap_for_ptr(oldtop); // 获取heap_info
      if (oldtopsize < (char *)heap + heap->mprotect_size - (char *)oldtop)
        oldtopsize = (char *)heap + heap->mprotect_size - (char *)oldtop;
    }
#endif
  }
  else 
  { // 无可用的arena，后续_int_malloc会直接mmap获取内存，而mmap获取内存初始值为0，不需要清零
    oldtop = 0;
    oldtopsize = 0;
  }
  mem = _int_malloc(av, sz); // 在 arena 中尝试分配内存

  assert(!mem || chunk_is_mmapped(mem2chunk(mem)) || // 未申请到内存或mmap获取的内存
         av == arena_for_chunk(mem2chunk(mem))); // 内存从当前线程对应的arena管理的内存中获取
  // 未申请到内存且arena不为空
  if (mem == 0 && av != NULL)
  {
    LIBC_PROBE(memory_calloc_retry, 1, sz);
    av = arena_get_retry(av, sz); // 再次获取arena
    mem = _int_malloc(av, sz); // 再次申请分配内存
  }

  if (av != NULL)
    (void)mutex_unlock(&av->mutex);

  if (mem == 0)
    return 0; // 申请为0则退出

  p = mem2chunk(mem); // 将申请到的内存转换为chunk地址

  if (chunk_is_mmapped(p))
  {
    if (__builtin_expect(perturb_byte, 0))
      return memset(mem, 0, sz);

    return mem; // 直接返回，因为mmap的内存默认初始化为0
  }
  csz = chunksize(p); // 需要清空的堆大小

#if MORECORE_CLEARS
  if (perturb_byte == 0 && (p == oldtop && csz > oldtopsize))
  { // 如果是从 top chunk 上切下来的，申请比原先top chunk大小大，则说明原来top chunk扩展
    // 只需要清零 top chunk 范围的内存
    csz = oldtopsize;
  }
#endif

  d = (INTERNAL_SIZE_T *)mem;
  clearsize = csz - SIZE_SZ;
  nclears = clearsize / sizeof(INTERNAL_SIZE_T);
  assert(nclears >= 3);

  if (nclears > 9)
    return memset(d, 0, clearsize);// 清零字节数较多，直接调用 memset
  else // 字节数较少，使用循环展开手动清零，以优化性能
  {
    *(d + 0) = 0;
    *(d + 1) = 0;
    *(d + 2) = 0;
    if (nclears > 4)
    {
      *(d + 3) = 0;
      *(d + 4) = 0;
      if (nclears > 6)
      {
        *(d + 5) = 0;
        *(d + 6) = 0;
        if (nclears > 8)
        {
          *(d + 7) = 0;
          *(d + 8) = 0;
        }
      }
    }
  }

  return mem;
}
```



### realloc

#### 2.23

##### __libc_realloc

```c
void *__libc_realloc(void *oldmem, size_t bytes)
{
  mstate ar_ptr;
  INTERNAL_SIZE_T nb; /* padded request size */

  void *newp; /* 返回的堆块 */

  void *(*hook)(void *, size_t, const void *) = atomic_forced_read(__realloc_hook);
  if (__builtin_expect(hook != NULL, 0))
    return (*hook)(oldmem, bytes, RETURN_ADDRESS(0)); // 若realloc_hook被设置则调用

#if REALLOC_ZERO_BYTES_FREES
  if (bytes == 0 && oldmem != NULL) // 若大小为0即 realloc(0)
  {
    __libc_free(oldmem); // 相当于free，将oldmem指针对应堆块释放
    return 0;
  }
#endif
  if (oldmem == 0) // 若 oldmem 为 NULL，相当于 malloc(bytes)
    return __libc_malloc(bytes);

  const mchunkptr oldp = mem2chunk(oldmem); // 将chunk转换为对应内存大小
  const INTERNAL_SIZE_T oldsize = chunksize(oldp); // 获取chunk大小

  if (chunk_is_mmapped(oldp))
    ar_ptr = NULL; // 若是mmap申请，则arena指针为空
  else
    ar_ptr = arena_for_chunk(oldp); // 否则通过该chunk获取arena地址

  if (__builtin_expect((uintptr_t)oldp > (uintptr_t)-oldsize, 0) || // 不超过内存空间，判断溢出
      __builtin_expect(misaligned_chunk(oldp), 0)) // 该堆块必须关于0x10对齐
  {
    malloc_printerr(check_action, "realloc(): invalid pointer", oldmem, ar_ptr);
    return NULL;
  }
  checked_request2size(bytes, nb); // 将申请内存转换为适合内存分配的块大小, 转换为nb大小

  // 若该chunk是mmap的
  if (chunk_is_mmapped(oldp))
  {
    void *newmem;

#if HAVE_MREMAP
    newp = mremap_chunk(oldp, nb); // 将oldp原来的chunk的大小调整为nb
    if (newp)
      return chunk2mem(newp); // 调整成功返回
#endif
    if (oldsize - SIZE_SZ >= nb) // 减去头的用户数据大小要大于申请的堆块大小
      return oldmem;

    // 若 mremap失败，则通过malloc获取内存
    newmem = __libc_malloc(bytes);
    if (newmem == 0)
      return 0;
	
    // 将原先内存的数据复制到新内存中
    memcpy(newmem, oldmem, oldsize - 2 * SIZE_SZ);
    munmap_chunk(oldp); // 将原先内存释放掉
    return newmem;
  }
    
  // 若不是mmap的则为ptmalloc申请 
  (void)mutex_lock(&ar_ptr->mutex); // 上锁

  newp = _int_realloc(ar_ptr, oldp, oldsize, nb); // 调用 _int_realloc 核心函数

  (void)mutex_unlock(&ar_ptr->mutex); // 解锁
  // 判断三种情况
  assert(!newp || chunk_is_mmapped(mem2chunk(newp)) ||
         ar_ptr == arena_for_chunk(mem2chunk(newp)));
  // realloc 申请没调整成功
  if (newp == NULL)
  {
    LIBC_PROBE(memory_realloc_retry, 2, bytes, oldmem);
    newp = __libc_malloc(bytes); // 尝试malloc
    if (newp != NULL)
    {
      memcpy(newp, oldmem, oldsize - SIZE_SZ); // 复制数据到新内存
      _int_free(ar_ptr, oldp, 0); // 释放旧内存
    }
  }
  return newp;
}
```

##### int_realloc

用于重新分配内存块，尝试更改内存块大小

```c
// av指向内存状态的指针，oldp指向内存状态的指针，oldsize当前块的大小，nb请求的新大小
void * _int_realloc(mstate av, mchunkptr oldp, INTERNAL_SIZE_T oldsize, INTERNAL_SIZE_T nb)
{
  mchunkptr newp;          /* 新分配的内存块指针 */
  INTERNAL_SIZE_T newsize; /* 新内存块大小 */
  void *newmem;            /* 对应用户内存的指针 */

  mchunkptr next; /* 指向oldp后面的连续内存块 */

  mchunkptr remainder;          /* 新分配内存后剩余的内存块 */
  unsigned long remainder_size; /* 剩余内存块大小 */

  mchunkptr bck; /* 链表临时变量 */
  mchunkptr fwd; /* 链表临时变量 */

  unsigned long copysize; /* 需要复制的字节数 */
  unsigned int ncopies;   /* 需要复制的INTERNAL_SIZE_T字数 */
  INTERNAL_SIZE_T *s;     /* 复制源的指针 */
  INTERNAL_SIZE_T *d;     /* 复制目标的指针 */

  const char *errstr = NULL;
  // 若大小小于0x10或大于系统内存
  if (__builtin_expect(oldp->size <= 2 * SIZE_SZ, 0) || __builtin_expect(oldsize >= av->system_mem, 0))
  {
    errstr = "realloc(): invalid old size";
  errout:
    malloc_printerr(check_action, errstr, chunk2mem(oldp), av); // 报错
    return NULL;
  }

  check_inuse_chunk(av, oldp);
  assert(!chunk_is_mmapped(oldp)); // 检查该chunk不是mmap申请的

  next = chunk_at_offset(oldp, oldsize); // 获取下一个chunk
  INTERNAL_SIZE_T nextsize = chunksize(next); // 下一个chunk大小
  if (__builtin_expect(next->size <= 2 * SIZE_SZ, 0) || __builtin_expect(nextsize >= av->system_mem, 0))
  {
    errstr = "realloc(): invalid next size"; // 安全检查下一个chunk大小
    goto errout;
  }

  if ((unsigned long)(oldsize) >= (unsigned long)(nb))
  { // chunk大小足够大
    newp = oldp;
    newsize = oldsize;
  }
  else
  { // chunk大小不足够申请的大小nb，尝试扩展内存
    if (next == av->top && // 下一个chunk是top chunk
        (unsigned long)(newsize = oldsize + nextsize) >= (unsigned long)(nb + MINSIZE))
    { // 且两个chunk大小大于nb+MINSIZE
      set_head_size(oldp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
      av->top = chunk_at_offset(oldp, nb); // 设置top chunk为oldp偏移nb，即切割一片内存与原堆块合并
      set_head(av->top, (newsize - nb) | PREV_INUSE);
      check_inuse_chunk(av, oldp);
      return chunk2mem(oldp); // 返回合并后堆块
    } 
    else if (next != av->top && // 若下一个chunk不是 top chunk
             !inuse(next) && // 下一个chunk空闲
             (unsigned long)(newsize = oldsize + nextsize) >= (unsigned long)(nb)) // 两个chunk大小大于nb
    {
      newp = oldp; // 后向合并 next
      unlink(av, next, bck, fwd); // 把下一个chunk脱链，还未返回，后续还需要切割后面的chunk
    }
    else // 下一个chunk不是空闲的
    {
      newmem = _int_malloc(av, nb - MALLOC_ALIGN_MASK); // 新申请一块内存
      if (newmem == 0)
        return 0;

      newp = mem2chunk(newmem); // 内存转换为chunk指针
      newsize = chunksize(newp); // 获取chunk大小

      if (newp == next) // 之前判断空闲不能判断是否在fastbin，所以此处申请可能为fastbin相连
      {
        newsize += oldsize; // 相邻则直接加在一起
        newp = oldp;
      }
      else // 否则拷贝＋释放操作
      {
        copysize = oldsize - SIZE_SZ; // 复制的大小
        s = (INTERNAL_SIZE_T *)(chunk2mem(oldp));
        d = (INTERNAL_SIZE_T *)(newmem);
        ncopies = copysize / sizeof(INTERNAL_SIZE_T);
        assert(ncopies >= 3);

        if (ncopies > 9)
          memcpy(d, s, copysize); // 大于9直接向d中拷贝copysize大小的s中数据

        else // 否则手动拷贝，一次拷贝8字节优化
        {
          *(d + 0) = *(s + 0);
          *(d + 1) = *(s + 1);
          *(d + 2) = *(s + 2);
          if (ncopies > 4)
          {
            *(d + 3) = *(s + 3);
            *(d + 4) = *(s + 4);
            if (ncopies > 6)
            {
              *(d + 5) = *(s + 5);
              *(d + 6) = *(s + 6);
              if (ncopies > 8)
              {
                *(d + 7) = *(s + 7);
                *(d + 8) = *(s + 8);
              }
            }
          }
        }

        _int_free(av, oldp, 1); // 释放之前的chunk
        check_inuse_chunk(av, newp);
        return chunk2mem(newp); // 直接返回了
      }
    }
  }

  assert((unsigned long)(newsize) >= (unsigned long)(nb));
  // 用于切割
  remainder_size = newsize - nb;

  if (remainder_size < MINSIZE)// 无法切割出一个chunk
  {
    set_head_size(newp, newsize | (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_inuse_bit_at_offset(newp, newsize); // 设置标志位
  }
  else// 剩余部分还可以切割一个chunk
  {
    remainder = chunk_at_offset(newp, nb); // 切割
    set_head_size(newp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_inuse_bit_at_offset(remainder, remainder_size);
    _int_free(av, remainder, 1); // 释放remainder
  }

  check_inuse_chunk(av, newp);
  return chunk2mem(newp);
}
```

##### mremap_chunk

调整mmap分配的内存块大小

```c
static mchunkptr internal_function mremap_chunk(mchunkptr p, size_t new_size)
{ // 调整由mmap分配的内存块 p 的大小到 new_size
  size_t pagesize = GLRO(dl_pagesize); // 当前系统页大小
  INTERNAL_SIZE_T offset = p->prev_size; // 当前块的偏移量，prev_size
  INTERNAL_SIZE_T size = chunksize(p); // 当前块大小
  char *cp;

  assert(chunk_is_mmapped(p)); // 确保是mmap分配
  assert(((size + offset) & (GLRO(dl_pagesize) - 1)) == 0); // 确保块大小加上偏移量是页大小整数倍对齐

  new_size = ALIGN_UP(new_size + offset + SIZE_SZ, pagesize); // 将new_size调整为与系统页对齐

  if (size + offset == new_size) // 若刚好等于调整后则返回
    return p;
  // 否则调用系统调用__mremap重新映射内存块，mremap重新分配一块内存并将之前的数据复制到新的内存上
  cp = (char *)__mremap((char *)p - offset, size + offset, new_size,MREMAP_MAYMOVE);

  if (cp == MAP_FAILED)
    return 0; // 调整失败

  p = (mchunkptr)(cp + offset); // mremap返回地址cp加上偏移得到新的块指针p

  assert(aligned_OK(chunk2mem(p))); // 地址对齐
  assert((p->prev_size == offset)); // 偏移量未变
  set_head(p, (new_size - offset) | IS_MMAPPED); // 更新头信息

  INTERNAL_SIZE_T new; // 更新mmaped_mem信息
  new = atomic_exchange_and_add(&mp_.mmapped_mem, new_size - size - offset) + new_size - size - offset;
  atomic_max(&mp_.max_mmapped_mem, new);
  return p;
}
```

## IO_FILE

### 结构

#### _IO_list_all

```c
// 指向_IO_FILE单链表的链表头
extern struct _IO_FILE_plus *_IO_list_all;
```

#### _IO_FILE_plus

```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  // vtable: 实现文件流操作的虚函数表,包含一组函数指针,指向实现各种IO操作的函数，不同的对象指向函数可能不同
  const struct _IO_jump_t *vtable;
};
```

#### _IO_FILE

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* 指针指向当前读到的位置 */
  char *_IO_read_end;	/* get area的结束，系统读取数据的结尾 */
  char *_IO_read_base;	/* putback+get area的开始，系统读取数据的开头 */
  char *_IO_write_base;	/* IO文件缓冲区开头 */
  char *_IO_write_ptr;	/* 指针指向当前写到的位置 */
  char *_IO_write_end;	/* IO文件缓冲区结尾 */
  char *_IO_buf_base;	/* buf缓冲区的开始 */
  char *_IO_buf_end;	/* buf缓冲区的结束 */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain; // 指向下一个_IO_FILE结构体

  int _fileno;
  int _flags2;
  __off_t _old_offset;
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

**偏移**

```c
0x0:'_flags',
0x8:'_IO_read_ptr',
0x10:'_IO_read_end',
0x18:'_IO_read_base',
0x20:'_IO_write_base',
0x28:'_IO_write_ptr',
0x30:'_IO_write_end',
0x38:'_IO_buf_base',
0x40:'_IO_buf_end',
0x48:'_IO_save_base',
0x50:'_IO_backup_base',
0x58:'_IO_save_end',
0x60:'_markers',
0x68:'_chain',
0x70:'_fileno',
0x74:'_flags2',
0x78:'_old_offset',
0x80:'_cur_column',
0x82:'_vtable_offset',
0x83:'_shortbuf',
0x88:'_lock',
0x90:'_offset',
0x98:'_codecvt',
0xa0:'_wide_data',
0xa8:'_freeres_list',
0xb0:'_freeres_buf',
0xb8:'__pad5',
0xc0:'_mode',
0xc4:'_unused2',
0xd8:'vtable'
```

#### _IO_FILE_complete

```c
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
  __off64_t _offset;
  struct _IO_codecvt *_codecvt; // house of apple 3利用
  struct _IO_wide_data *_wide_data; // house of apple 2劫持这个变量
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

#### _IO_codecvt

```c
struct _IO_codecvt
{
  _IO_iconv_t __cd_in;
  _IO_iconv_t __cd_out;
};
```

#### _IO_iconv_t

```c
typedef struct
{
  struct __gconv_step *step;
  struct __gconv_step_data step_data;
} _IO_iconv_t;
```

#### __gconv_step

```c
struct __gconv_step
{
  struct __gconv_loaded_object *__shlib_handle;
  const char *__modname;
  int __counter;

  char *__from_name;
  char *__to_name;

  __gconv_fct __fct;
  __gconv_btowc_fct __btowc_fct;
  __gconv_init_fct __init_fct;
  __gconv_end_fct __end_fct;
    
  int __min_needed_from;
  int __max_needed_from;
  int __min_needed_to;
  int __max_needed_to;

  int __stateful;
  void *__data;
};
```



#### _IO_wstrnfile

```c
typedef struct{
  _IO_strfile f;
  wchar_t overflow_buf[64]; // overflow_buf
} _IO_wstrnfile;
```

#### _IO_strnfile

```c
typedef struct{
  _IO_strfile f;
  char overflow_buf[64];
} _IO_strnfile;
```

#### _IO_strfile

```c
typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;
```

#### _IO_streambuf

```c
struct _IO_streambuf
{
  FILE _f;
  const struct _IO_jump_t *vtable;
};
```

#### _IO_str_fields

```c
struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer_unused;
  _IO_free_type _free_buffer_unused;
};
```

#### _IO_wide_data

```c
// 结构与_IO_FILE很像
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable; // vtable表
};
```



#### _IO_jump_t

不同的实例对象指向的函数可能不同

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

#### STD

- 初始情况`_IO_list_all`指向`_IO_2_1_stdin_`，`_IO_2_1_stdout_`，`_IO_2_1_stderr_`三个`_IO_FILE`结构体，开在libc的数据段上

```c
// stdfiles.c
DEF_STDFILE(_IO_2_1_stdin_, 0, 0, _IO_NO_WRITES);
DEF_STDFILE(_IO_2_1_stdout_, 1, &_IO_2_1_stdin_, _IO_NO_READS);
DEF_STDFILE(_IO_2_1_stderr_, 2, &_IO_2_1_stdout_, _IO_NO_READS+_IO_UNBUFFERED);

struct _IO_FILE_plus *_IO_list_all = &_IO_2_1_stderr_;
libc_hidden_data_def (_IO_list_all)
```

```c
// stdio.c
// 三个全局指针指向三个结构体
_IO_FILE *stdin = (FILE *) &_IO_2_1_stdin_;
_IO_FILE *stdout = (FILE *) &_IO_2_1_stdout_;
_IO_FILE *stderr = (FILE *) &_IO_2_1_stderr_;
```
<img src="img/source_analyze.zh-cn.assets/image-20241206005717674.png" alt="图片无法加载" />

#### DEF_STDFILE

```c
// stdfiles.c
# define DEF_STDFILE(NAME, FD, CHAIN, FLAGS) // 文件流对象名、文件描述符、文件链、标志[只读只写]
// 锁，保护文件流的并发访问
 static _IO_lock_t _IO_stdfile_##FD##_lock = _IO_lock_initializer; 
// 宽字符数据结构
 static struct _IO_wide_data _IO_wide_data_##FD = { ._wide_vtable = &_IO_wfile_jumps }; 
// 文件流结构体
 struct _IO_FILE_plus NAME = {FILEBUF_LITERAL(CHAIN, FLAGS, FD, &_IO_wide_data_##FD), &_IO_file_jumps};
```



#### _IO_link_in

```c
// 有文件读写操作，为对应文件创建_IO_FILE结构体，头插法链接到_IO_list_all链表上
void _IO_link_in (struct _IO_FILE_plus *fp)
{
  // _IO_LINKED 标志未被设置, 执行插入操作
  if ((fp->file._flags & _IO_LINKED) == 0)
    {
      // 设置标志位
      fp->file._flags |= _IO_LINKED;
#ifdef _IO_MTSAFE_IO
      // 线程安全操作
      _IO_cleanup_region_start_noarg (flush_cleanup);
      _IO_lock_lock (list_all_lock);
      run_fp = (_IO_FILE *) fp;
      _IO_flockfile ((_IO_FILE *) fp);
#endif
      // 链接到开头
      fp->file._chain = (_IO_FILE *) _IO_list_all;
      _IO_list_all = fp;
#ifdef _IO_MTSAFE_IO
      // 线程安全操作
      _IO_funlockfile ((_IO_FILE *) fp);
      run_fp = NULL;
      _IO_lock_unlock (list_all_lock);
      _IO_cleanup_region_end (0);
#endif
    }
}
libc_hidden_def (_IO_link_in)
```

#### _IO_cookie_file

```c
struct _IO_cookie_file
{
  struct _IO_FILE_plus __fp; // 包含一个FILE结构体和一个_IO_jump_t指针vtable
  void *__cookie;
  cookie_io_functions_t __io_functions; // 包含4个函数指针
};
```

#### _IO_cookie_io_functions_t

```c
typedef struct _IO_cookie_io_functions_t
{
  cookie_read_function_t *read;		/* Read bytes.  */
  cookie_write_function_t *write;	/* Write bytes.  */
  cookie_seek_function_t *seek;		/* Seek/tell file position.  */
  cookie_close_function_t *close;	/* Close file.  */
} cookie_io_functions_t;
```



### fopen

#### fopen

```c
# define fopen(fname, mode) _IO_new_fopen (fname, mode)
```

#### _IO_new_fopen

```c
FILE *_IO_new_fopen (const char *filename, const char *mode)
{
  return __fopen_internal (filename, mode, 1);
}
```

#### __fopen_internal

```c
FILE *__fopen_internal (const char *filename, const char *mode, int is32)
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
    // 若定义了 _IO_MTSAFE_IO 宏，结构体将包含 lock 成员，
    // 实现条件性编译，针对是否支持多线程安全生成不同的结构体布局
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));
    // malloc创建locked_FILE结构体

  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  // 初始化多线程锁
  new_f->fp.file._lock = &new_f->lock;
#endif
  // NULL初始化
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
  // 设置vtable
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
  // 将结构体插入链表中
  _IO_new_file_init_internal (&new_f->fp);
  // 执行系统调用打开文件
  if (_IO_file_fopen ((FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}
```

#### _IO_no_init

```c
// 初始化操作
void _IO_no_init (FILE *fp, int flags, int orientation,
	     struct _IO_wide_data *wd, const struct _IO_jump_t *jmp)
{
  _IO_old_init (fp, flags);
  fp->_mode = orientation;
  if (orientation >= 0)
    {
      fp->_wide_data = wd;
      fp->_wide_data->_IO_buf_base = NULL;
      fp->_wide_data->_IO_buf_end = NULL;
      fp->_wide_data->_IO_read_base = NULL;
      fp->_wide_data->_IO_read_ptr = NULL;
      fp->_wide_data->_IO_read_end = NULL;
      fp->_wide_data->_IO_write_base = NULL;
      fp->_wide_data->_IO_write_ptr = NULL;
      fp->_wide_data->_IO_write_end = NULL;
      fp->_wide_data->_IO_save_base = NULL;
      fp->_wide_data->_IO_backup_base = NULL;
      fp->_wide_data->_IO_save_end = NULL;

      fp->_wide_data->_wide_vtable = jmp;
    }
  else
    fp->_wide_data = (struct _IO_wide_data *) -1L;
  fp->_freeres_list = NULL;
}
```

#### _IO_old_init

```c
void _IO_old_init (FILE *fp, int flags)
{
  fp->_flags = _IO_MAGIC|flags; // #define _IO_MAGIC 0xFBAD0000 魔数
  fp->_flags2 = 0;
  if (stdio_needs_locking)
    fp->_flags2 |= _IO_FLAGS2_NEED_LOCK;
  fp->_IO_buf_base = NULL;
  fp->_IO_buf_end = NULL;
  fp->_IO_read_base = NULL;
  fp->_IO_read_ptr = NULL;
  fp->_IO_read_end = NULL;
  fp->_IO_write_base = NULL;
  fp->_IO_write_ptr = NULL;
  fp->_IO_write_end = NULL;
  fp->_chain = NULL;

  fp->_IO_save_base = NULL;
  fp->_IO_backup_base = NULL;
  fp->_IO_save_end = NULL;
  fp->_markers = NULL;
  fp->_cur_column = 0;
#if _IO_JUMPS_OFFSET
  fp->_vtable_offset = 0;
#endif
#ifdef _IO_MTSAFE_IO
  if (fp->_lock != NULL)
    _IO_lock_init (*fp->_lock);
#endif
}
```

#### _IO_new_file_init_internal

```c
void _IO_new_file_init_internal (struct _IO_FILE_plus *fp)
{
  // 设置一些标志
  fp->file._offset = _IO_pos_BAD;
  fp->file._flags |= CLOSED_FILEBUF_FLAGS;

  _IO_link_in (fp); // 头插法加到链表中
  fp->file._fileno = -1;
}
```

#### _IO_new_file_fopen

```c
FILE *_IO_new_file_fopen (FILE *fp, const char *filename, const char *mode, int is32not64)
{
  int oflags = 0, omode;
  int read_write;
  int oprot = 0666;
  int i;
  FILE *result;
  const char *cs;
  const char *last_recognized;

  if (_IO_file_is_open (fp))
    return 0;
  switch (*mode)
    {
    case 'r':
      omode = O_RDONLY;
      read_write = _IO_NO_WRITES;
      break;
    case 'w':
      omode = O_WRONLY;
      oflags = O_CREAT|O_TRUNC;
      read_write = _IO_NO_READS;
      break;
    case 'a':
      omode = O_WRONLY;
      oflags = O_CREAT|O_APPEND;
      read_write = _IO_NO_READS|_IO_IS_APPENDING;
      break;
    default:
      __set_errno (EINVAL);
      return NULL;
    }
  last_recognized = mode;
  for (i = 1; i < 7; ++i)
    {
      switch (*++mode)
	{
	case '\0':
	  break;
	case '+':
	  omode = O_RDWR;
	  read_write &= _IO_IS_APPENDING;
	  last_recognized = mode;
	  continue;
	case 'x':
	  oflags |= O_EXCL;
	  last_recognized = mode;
	  continue;
	case 'b':
	  last_recognized = mode;
	  continue;
	case 'm':
	  fp->_flags2 |= _IO_FLAGS2_MMAP;
	  continue;
	case 'c':
	  fp->_flags2 |= _IO_FLAGS2_NOTCANCEL;
	  continue;
	case 'e':
	  oflags |= O_CLOEXEC;
	  fp->_flags2 |= _IO_FLAGS2_CLOEXEC;
	  continue;
	default:
	  continue;
	}
      break;
    }

  result = _IO_file_open (fp, filename, omode|oflags, oprot, read_write, is32not64);

  if (result != NULL)
    {
      cs = strstr (last_recognized + 1, ",ccs=");
      if (cs != NULL)
	{
	  struct gconv_fcts fcts;
	  struct _IO_codecvt *cc;
	  char *endp = __strchrnul (cs + 5, ',');
	  char *ccs = malloc (endp - (cs + 5) + 3);

	  if (ccs == NULL)
	    {
	      int malloc_err = errno;
	      (void) _IO_file_close_it (fp);
	      __set_errno (malloc_err);
	      return NULL;
	    }

	  *((char *) __mempcpy (ccs, cs + 5, endp - (cs + 5))) = '\0';
	  strip (ccs, ccs);

	  if (__wcsmbs_named_conv (&fcts, ccs[2] == '\0' ? upstr (ccs, cs + 5) : ccs) != 0)
	    {
	      (void) _IO_file_close_it (fp);
	      free (ccs);
	      __set_errno (EINVAL);
	      return NULL;
	    }

	  free (ccs);

	  assert (fcts.towc_nsteps == 1);
	  assert (fcts.tomb_nsteps == 1);

	  fp->_wide_data->_IO_read_ptr = fp->_wide_data->_IO_read_end;
	  fp->_wide_data->_IO_write_ptr = fp->_wide_data->_IO_write_base;

	  memset (&fp->_wide_data->_IO_state, '\0', sizeof (__mbstate_t));
	  memset (&fp->_wide_data->_IO_last_state, '\0', sizeof (__mbstate_t));

	  cc = fp->_codecvt = &fp->_wide_data->_codecvt;

	  cc->__cd_in.step = fcts.towc;

	  cc->__cd_in.step_data.__invocation_counter = 0;
	  cc->__cd_in.step_data.__internal_use = 1;
	  cc->__cd_in.step_data.__flags = __GCONV_IS_LAST;
	  cc->__cd_in.step_data.__statep = &result->_wide_data->_IO_state;

	  cc->__cd_out.step = fcts.tomb;

	  cc->__cd_out.step_data.__invocation_counter = 0;
	  cc->__cd_out.step_data.__internal_use = 1;
	  cc->__cd_out.step_data.__flags = __GCONV_IS_LAST | __GCONV_TRANSLIT;
	  cc->__cd_out.step_data.__statep = &result->_wide_data->_IO_state;

	  _IO_JUMPS_FILE_plus (fp) = fp->_wide_data->_wide_vtable;
	  result->_mode = 1;
	}
    }

  return result;
}
libc_hidden_ver (_IO_new_file_fopen, _IO_file_fopen)
```

#### _IO_file_open

```c
FILE *_IO_file_open (FILE *fp, const char *filename, int posix_mode, int prot,
	       int read_write, int is32not64)
{
  int fdesc;
  if (__glibc_unlikely (fp->_flags2 & _IO_FLAGS2_NOTCANCEL))
    fdesc = __open_nocancel (filename, posix_mode | (is32not64 ? 0 : O_LARGEFILE), prot);
  else
    fdesc = __open (filename, posix_mode | (is32not64 ? 0 : O_LARGEFILE), prot);
  if (fdesc < 0)
    return NULL;
  fp->_fileno = fdesc;
  _IO_mask_flags (fp, read_write,_IO_NO_READS+_IO_NO_WRITES+_IO_IS_APPENDING);
  if ((read_write & (_IO_IS_APPENDING | _IO_NO_READS)) == (_IO_IS_APPENDING | _IO_NO_READS))
    {
      off64_t new_pos = _IO_SYSSEEK (fp, 0, _IO_seek_end);
      if (new_pos == _IO_pos_BAD && errno != ESPIPE)
        {
          __close_nocancel (fdesc);
          return NULL;
        }
    }
  _IO_link_in ((struct _IO_FILE_plus *) fp);
  return fp;
}
libc_hidden_def (_IO_file_open)
```

### fread

<img src="/img/source_analyze.zh-cn.assets/image-20241206210233580.png" alt="图片无法加载" />

#### fread

```c
#define fread(p, m, n, s) _IO_fread (p, m, n, s)
```

#### _IO_fread

```c
size_t _IO_fread (void *buf, size_t size, size_t count, FILE *fp)
{
  size_t bytes_requested = size * count;
  size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)
    return 0;
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}
libc_hidden_def (_IO_fread)
```

#### _IO_sgetn

```c
#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))

size_t _IO_sgetn (FILE *fp, void *data, size_t n)
{ // 会通过vtable调用不同结构体的函数 _IO_file_xsgetn
  return _IO_XSGETN (fp, data, n);
}
libc_hidden_def (_IO_sgetn)
```

#### _IO_file_xsgetn

```c
// 通过文件流fp从文件系统读取最多n字节数据到用户缓冲区data中
size_t _IO_file_xsgetn(FILE *fp, void *data, size_t n)
{
  size_t want, have;
  ssize_t count;
  char *s = data; // 指向用户缓冲区data
  want = n; // 剩余需要读取的字节数，初始为n

  if (fp->_IO_buf_base == NULL)
  // 文件流缓冲区未初始化
  {
    if (fp->_IO_save_base != NULL)
    {
      free(fp->_IO_save_base); // 释放备份缓冲区
      fp->_flags &= ~_IO_IN_BACKUP; // 清除备份模式标志
    }
    // 初始化文件流缓冲区
    _IO_doallocbuf(fp);
  }
  
  // 仍有数据需要读取
  while (want > 0)
  {
    have = fp->_IO_read_end - fp->_IO_read_ptr; // 文件流缓冲区剩余数据大小
    // 文件流缓冲区大小足够满足需要读取的字节数want
    if (want <= have)
    {
      memcpy(s, fp->_IO_read_ptr, want); // 从文件流缓冲区复制到用户缓冲区
      fp->_IO_read_ptr += want; // 更新指针
      want = 0; // 标记读取完成
    }
    // 若文件流缓冲区数据不足
    else
    {
      if (have > 0) // 文件流缓冲区中还有部分数据可用
      {
        // 先尽可能多的从文件流缓冲区复制到用户缓冲区
        s = __mempcpy(s, fp->_IO_read_ptr, have);
        want -= have; // 更新剩余需求
        fp->_IO_read_ptr += have; // 更新文件流缓冲区读取指针
      }
	  // 处于备份模式
      if (_IO_in_backup(fp))
      {
        _IO_switch_to_main_get_area(fp);
        continue; // 切换备份缓冲区重新尝试读取
      }
      // 若文件流缓冲区未满 且 需要读取的数据小于文件流缓冲区总容量
      if (fp->_IO_buf_base && want < (size_t)(fp->_IO_buf_end - fp->_IO_buf_base))
      {
        // underflow 调用系统函数将数据读入文件流缓冲区, 实际调用 _IO_UNDERFLOW
        // 最终调用 _IO_new_file_underflow 函数
        if (__underflow(fp) == EOF)
          break;
        continue; // 填充完文件流缓冲区，继续尝试读取
      }
      // 所需读取的数据大于文件流缓冲区总容量
      // 重置文件流缓冲区指针
      _IO_setg(fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
      _IO_setp(fp, fp->_IO_buf_base, fp->_IO_buf_base);
	  
      // 对齐，若文件流缓冲区大小不小于128字节，则读入长度为文件流缓冲区长度整数倍
      count = want;
      if (fp->_IO_buf_base)
      {
        size_t block_size = fp->_IO_buf_end - fp->_IO_buf_base;
        if (block_size >= 128)
          count -= want % block_size;
      }
	  // 直接系统调用读取文件中数据到用户缓冲区中
      count = _IO_SYSREAD(fp, s, count);
      if (count <= 0)
      {
        if (count == 0)
          fp->_flags |= _IO_EOF_SEEN;
        else
          fp->_flags |= _IO_ERR_SEEN;

        break;
      }
	  // 更新
      s += count;
      want -= count;
      if (fp->_offset != _IO_pos_BAD)
        _IO_pos_adjust(fp->_offset, count);
    }
  }

  return n - want;
}
libc_hidden_def(_IO_file_xsgetn)
```

#### _IO_doallocbuf

```c
void _IO_doallocbuf (FILE *fp)
{
  if (fp->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED) || fp->_mode > 0)
    if (_IO_DOALLOCATE (fp) != EOF)
      return;
  _IO_setb (fp, fp->_shortbuf, fp->_shortbuf+1, 0);
}
libc_hidden_def (_IO_doallocbuf)
```

#### _IO_new_file_underflow

```c
int _IO_new_file_underflow(_IO_FILE *fp)
{
  _IO_ssize_t count; // 存储从文件中读取的字节数
#if 0
  if (fp->_flags & _IO_EOF_SEEN)
    return (EOF);
#endif

  if (fp->_flags & _IO_NO_READS) // 文件末尾已经被读取, 表示不允许读取数据
  {
    fp->_flags |= _IO_ERR_SEEN;
    __set_errno(EBADF); // 文件描述符无效
    return EOF;
  }
  // 文件流缓冲区已有数据，直接返回_IO_read_ptr指向的数据
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *)fp->_IO_read_ptr;

  // 若文件流没有为读取分配缓冲区
  if (fp->_IO_buf_base == NULL)
  {
    if (fp->_IO_save_base != NULL) // 之前有分配过备份的缓冲区
    {
      free(fp->_IO_save_base); // 释放这些缓冲区
      fp->_flags &= ~_IO_IN_BACKUP;
    }
    _IO_doallocbuf(fp); // 分配新文件流缓冲区
  }
  // 是否设置 行缓冲 或 无缓冲
  if (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
  {
#if 0
      _IO_flush_all_linebuffered ();
#else
    _IO_acquire_lock(_IO_stdout);

    if ((_IO_stdout->_flags & 
        (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF)) == (_IO_LINKED | _IO_LINE_BUF))
      _IO_OVERFLOW(_IO_stdout, EOF);// 调用_IO_OVERFLOW函数处理标准输出的溢出情况

    _IO_release_lock(_IO_stdout);
#endif
  }

  _IO_switch_to_get_mode(fp); // 切换为读取模式
  
  // 设置读写指针均为缓冲区基地址
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end = fp->_IO_buf_base;
  // 调用系统SYSREAD调用从文件读取数据存储到缓冲区中，返回实际读取的字节数
  count = _IO_SYSREAD(fp, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base);
  if (count <= 0)
  {
    if (count == 0)
      fp->_flags |= _IO_EOF_SEEN;
    else
      fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  // 读取结束指针移动count字节
  fp->_IO_read_end += count;
  if (count == 0) // 未成功读取任何数据
  {
    fp->_offset = _IO_pos_BAD;
    return EOF;
  }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust(fp->_offset, count); // 调整文件流的偏移量
  return *(unsigned char *)fp->_IO_read_ptr; // 返回当前读取指针指向字节
}
libc_hidden_ver(_IO_new_file_underflow, _IO_file_underflow)
```



### fwrite

<img src="/img/source_analyze.zh-cn.assets/image-20241206205821979.png" alt="图片无法加载" />

#### fwrite

```c
#define fwrite(buf, size, count, fp) _IO_fwrite (buf, size, count, fp)
```

#### _IO_fwrite

```c
size_t _IO_fwrite (const void *buf, size_t size, size_t count, FILE *fp)
{
  size_t request = size * count;
  size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);
  _IO_release_lock (fp);
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
libc_hidden_def (_IO_fwrite)
```

#### _IO_new_file_xsputn

```c
// 从用户缓冲区data写入文件流f中
size_t _IO_new_file_xsputn(FILE *f, const void *data, size_t n)
{
  const char *s = (const char *)data; // 用户缓冲区指针
  size_t to_do = n; // 写入数据长度
  int must_flush = 0; // 标志是否需要立即刷新文件流缓冲区
  size_t count = 0; 

  if (n <= 0)
    return 0;
  // 判断是否为行缓冲模式，即遇到换行符立即刷新文件流缓冲区
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
  {
    // 文件流缓冲区剩余空间大小
    count = f->_IO_buf_end - f->_IO_write_ptr;
    if (count >= n) // 若文件流缓冲区能容纳所有数据data
    {
      const char *p;
      for (p = s + n; p > s;) // 从用户数据末尾向前查找换行符
      {
        if (*--p == '\n') // 找到换行符
        {
          count = p - s + 1; // 只写入到换行符前数据
          must_flush = 1; // 立即刷新输出数据
          break;
        }
      }
    }
  }
  // 非行缓冲模式，文件流缓冲区仍有可用空间，获取剩余空间count
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr;

  if (count > 0)
  {
    if (count > to_do)
      count = to_do; // 若文件流缓冲区能容纳所有剩余数据
    // 将数据data写入到文件流缓冲区中
    f->_IO_write_ptr = __mempcpy(f->_IO_write_ptr, s, count);
    // 更新
    s += count;
    to_do -= count;
  }
  // 若需要刷新缓冲区或仍有数据未写
  if (to_do + must_flush > 0)
  {
    size_t block_size, do_write;
	// 强制输出并刷新清空文件流缓冲区
    // 实际调用了_IO_new_file_overflow
    if (_IO_OVERFLOW(f, EOF) == EOF)
      return to_do == 0 ? EOF : n - to_do;
	// 对齐
    block_size = f->_IO_buf_end - f->_IO_buf_base;
    do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

    if (do_write)
    {
      // 调用new_do_write直接输出数据
      count = new_do_write(f, s, do_write);
      to_do -= count;
      if (count < do_write)
        return n - to_do;
    }
    if (to_do) // 将剩余数据复制到文件流缓冲区
      to_do -= _IO_default_xsputn(f, s + do_write, to_do);
  }
  return n - to_do;
}
libc_hidden_ver(_IO_new_file_xsputn, _IO_file_xsputn)
```

#### _IO_new_file_overflow

```c
int _IO_new_file_overflow(_IO_FILE *f, int ch)
{
  // 检查是否允许写入
  if (f->_flags & _IO_NO_WRITES)
  {
    f->_flags |= _IO_ERR_SEEN;
    __set_errno(EBADF); // 操作失败，写入错误
    return EOF;
  }
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
  { 
    // 若未分配写入缓冲区
    if (f->_IO_write_base == NULL)
    {
      _IO_doallocbuf(f); // 初始化分配缓冲区
      _IO_setg(f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base); // 设置缓冲区起点
    }
    // 处理备份缓冲区
    if (__glibc_unlikely(_IO_in_backup(f)))
    {
      size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
      _IO_free_backup_area(f);
      f->_IO_read_base -= MIN(nbackup, f->_IO_read_base - f->_IO_buf_base);
      f->_IO_read_ptr = f->_IO_read_base;
    }
	
    // 若读取指针到达缓冲区末尾，重置为缓冲区起始位置
    if (f->_IO_read_ptr == f->_IO_buf_end)
      f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
    // 写入指针和缓冲区指针统一到读取指针位置
    f->_IO_write_ptr = f->_IO_read_ptr;
    f->_IO_write_base = f->_IO_write_ptr;
    f->_IO_write_end = f->_IO_buf_end;
    f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

    // 文件流进入写入模式
    f->_flags |= _IO_CURRENTLY_PUTTING;
    // 文件流处于行缓冲或无缓冲模式
    if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
      f->_IO_write_end = f->_IO_write_ptr;
  }
  if (ch == EOF) // 直接将缓冲区内容写入文件，实际调用new_do_write
    return _IO_do_write(f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base);
  // 写入指针已到达缓冲区末尾，表示缓冲区已满，调用_IO_do_flush刷新缓冲区
  if (f->_IO_write_ptr == f->_IO_buf_end)
    if (_IO_do_flush(f) == EOF)
      return EOF; // 刷新失败
  // 将ch写入当前的写入指针位置，写入指针移动
  *f->_IO_write_ptr++ = ch;
  // 无缓冲模式/行缓冲模式且写入\n，立即将缓冲区数据写入文件
  if ((f->_flags & _IO_UNBUFFERED) || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write(f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  // 返回写入的字符
  return (unsigned char)ch;
}
libc_hidden_ver(_IO_new_file_overflow, _IO_file_overflow)
```



#### new_do_write

```c
// 调用了系统调用 将data写入fp
static size_t new_do_write(FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  // 文件流处于追加模式
  if (fp->_flags & _IO_IS_APPENDING)
    fp->_offset = _IO_pos_BAD; // 偏移量设置为无效值
  
  else if (fp->_IO_read_end != fp->_IO_write_base)
  { // 读取指针和写入缓冲区基址不相同，需要调整文件偏移量
    off64_t new_pos = _IO_SYSSEEK(fp, fp->_IO_write_base - fp->_IO_read_end, 1); // 移到写缓冲区基址
    if (new_pos == _IO_pos_BAD)
      return 0;
    fp->_offset = new_pos;
  }
  // 系统调用，data指向的to_do字节数据写入文件流fp
  count = _IO_SYSWRITE(fp, data, to_do);
  // 若当前流的列信息存在且成功写入数据
  if (fp->_cur_column && count)
    // 调整列信息
    fp->_cur_column = _IO_adjust_column(fp->_cur_column - 1, data, count) + 1;
  // 重置读缓冲区
  _IO_setg(fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  // 初始化写入缓冲区
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0 && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
                           ? fp->_IO_buf_base
                           : fp->_IO_buf_end);
  return count; // 返回写入字节数
}
```



### fclose

#### fclose

```c
#define fclose(fp) _IO_new_fclose (fp)
```

#### _IO_new_fclose

```c
int _IO_new_fclose (FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
  if (_IO_vtable_offset (fp) != 0)
    return _IO_old_fclose (fp);
#endif
  if (fp->_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp); // 将文件结构体从_IO_list_all链表中取下

  _IO_acquire_lock (fp);
  if (fp->_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp); // 关闭文件，释放文件流缓冲区
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  if (fp->_mode > 0)
    {
      struct _IO_codecvt *cc = fp->_codecvt;

      __libc_lock_lock (__gconv_lock);
      __gconv_release_step (cc->__cd_in.step);
      __gconv_release_step (cc->__cd_out.step);
      __libc_lock_unlock (__gconv_lock);
    }
  else
    {
      if (_IO_have_backup (fp))
	_IO_free_backup_area (fp);
    }
  _IO_deallocate_file (fp);
  return status;
}
```

#### _IO_un_link

```c
void _IO_un_link (struct _IO_FILE_plus *fp)
{
  if (fp->file._flags & _IO_LINKED)
    {
      FILE **f;
#ifdef _IO_MTSAFE_IO
      _IO_cleanup_region_start_noarg (flush_cleanup);
      _IO_lock_lock (list_all_lock);
      run_fp = (FILE *) fp;
      _IO_flockfile ((FILE *) fp);
#endif
      if (_IO_list_all == NULL)
	;
      else if (fp == _IO_list_all)
	_IO_list_all = (struct _IO_FILE_plus *) _IO_list_all->file._chain;
      else
	for (f = &_IO_list_all->file._chain; *f; f = &(*f)->_chain)
	  if (*f == (FILE *) fp)
	    {
	      *f = fp->file._chain;
	      break;
	    }
      fp->file._flags &= ~_IO_LINKED;
#ifdef _IO_MTSAFE_IO
      _IO_funlockfile ((FILE *) fp);
      run_fp = NULL;
      _IO_lock_unlock (list_all_lock);
      _IO_cleanup_region_end (0);
#endif
    }
}
libc_hidden_def (_IO_un_link)
```

#### _IO_new_file_close_it

```c
int _IO_new_file_close_it(FILE *fp)
{
  int write_status;
  if (!_IO_file_is_open(fp))
    return EOF;

  if ((fp->_flags & _IO_NO_WRITES) == 0 && (fp->_flags & _IO_CURRENTLY_PUTTING) != 0)
    write_status = _IO_do_flush(fp);
  else
    write_status = 0;

  _IO_unsave_markers(fp);

  int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0
                          ? _IO_SYSCLOSE(fp) // 系统调用关闭文件
                          : 0);
  // 释放文件流缓冲区
  if (fp->_mode > 0)
  {
    if (_IO_have_wbackup(fp))
      _IO_free_wbackup_area(fp);
    _IO_wsetb(fp, NULL, NULL, 0);
    _IO_wsetg(fp, NULL, NULL, NULL);
    _IO_wsetp(fp, NULL, NULL);
  }
  _IO_setb(fp, NULL, NULL, 0);
  _IO_setg(fp, NULL, NULL, NULL);
  _IO_setp(fp, NULL, NULL);

  _IO_un_link((struct _IO_FILE_plus *)fp);
  fp->_flags = _IO_MAGIC | CLOSED_FILEBUF_FLAGS;
  fp->_fileno = -1;
  fp->_offset = _IO_pos_BAD;

  return close_status ? close_status : write_status;
}
libc_hidden_ver(_IO_new_file_close_it, _IO_file_close_it)
```

### puts

#### _IO_puts

```c
int _IO_puts(const char *str)
{
  int result = EOF;
  _IO_size_t len = strlen(str);
  _IO_acquire_lock(_IO_stdout);

  if ((_IO_vtable_offset(_IO_stdout) != 0 || _IO_fwide(_IO_stdout, -1) == -1) 
    && _IO_sputn(_IO_stdout, str, len) == len
    && _IO_putc_unlocked('\n', _IO_stdout) != EOF)
    result = MIN(INT_MAX, len + 1);

  _IO_release_lock(_IO_stdout);
  return result;
}
```

#### _IO_sputn

```c
// 2.27 宏展开
((IO_validate_vtable (
	*(struct _IO_jump_t **) ( // 转换为_IO_jump_t * 类型指针最终传入IO_validate_vtable
		(void *) &(
            // 由 char * 转换为 vtable 对应类型
            *(__typeof__ (((struct _IO_FILE_plus){}).vtable) *)(
                // 获取_IO_stdout基地址，计算出vtable成员在_IO_stdout结构体地址
                ((char *) ((_IO_stdout))) + __builtin_offsetof (struct _IO_FILE_plus, vtable)
            )
        ) 
  		+ (_IO_stdout)->_vtable_offset // 一般为0，应对特殊情况偏移
  	)
))->__xsputn) (_IO_stdout, str, len);
```

#### IO_validate_vtable

```c
// 2.27 检查传入的 vtable 指针是否指向 libc 库中定义的有效的 I/O 操作函数表
static inline const struct _IO_jump_t *IO_validate_vtable(const struct _IO_jump_t *vtable)
{
   // 计算 I/O 操作函数表在内存中总大小
   uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
   const char *ptr = (const char *)vtable; // 强制转换类型以计算偏移
   uintptr_t offset = ptr - __start___libc_IO_vtables; // 计算偏移量
   if (__glibc_unlikely(offset >= section_length)) // 判断是否超过总大小
      _IO_vtable_check(); // 最终报错
   return vtable;
}
```

#### _IO_vtable_check

```c
void attribute_hidden _IO_vtable_check (void)
{
#ifdef SHARED // 仅共享库模式下编译
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
#ifdef PTR_DEMANGLE // 处理函数指针的混淆或解混淆
  PTR_DEMANGLE (flag); // 解码函数指针flag值
#endif
  if (flag == &_IO_vtable_check)
    return;
  {
    Dl_info di; // 存储动态链接器返回的信息，例如符号名和地址
    struct link_map *l;
    if (!rtld_active () // 检查运行时动态链接器是否处于活动状态
        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }

#else // 非共享库模式
  if (__dlopen != NULL)
    return;
#endif
  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```

#### rtld_active

```c
#  define GLRO(name) _rtld_local_ro._##name

static inline bool rtld_active (void)
{
  return GLRO(dl_init_all_dirs) != NULL;
}
```

#### _dl_addr

```c
int _dl_addr(const void *address, Dl_info *info,
             struct link_map **mapp, const ElfW(Sym) * *symbolp)
{
  const ElfW(Addr) addr = DL_LOOKUP_ADDRESS(address);
  int result = 0;
/*
    libc-lockP.h 关键exit-hook
    # define __rtld_lock_lock_recursive(NAME) \
      __libc_maybe_call (__pthread_mutex_lock, (&(NAME).mutex), 0)
     替换:
    (({
        __typeof(__pthread_mutex_lock) *_fn = (__pthread_mutex_lock);
        _fn != ((void *) 0) ? (*_fn)(&(_dl_load_lock).mutex) : 0;
    }))
*/
  __rtld_lock_lock_recursive(GL(dl_load_lock));

  struct link_map *l = _dl_find_dso_for_object(addr);

  if (l)
  {
    determine_info(addr, l, info, mapp, symbolp);
    result = 1;
  }

  __rtld_lock_unlock_recursive(GL(dl_load_lock));

  return result;
}
libc_hidden_def(_dl_addr)
```



### flush

#### _IO_flush_all_lockp

```c
// 程序退出时会调用
int _IO_flush_all_lockp(int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start(do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock(list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *)_IO_list_all; // 获取fp
  while (fp != NULL)
  {
    run_fp = fp;
    if (do_lock)
      _IO_flockfile(fp);

    if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
         || (_IO_vtable_offset(fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base))
#endif
             ) &&
        _IO_OVERFLOW(fp, EOF) == EOF) // 调用_IO_OVERFLOW， 参数为fp，即_IO_FILE结构体指针
      result = EOF;

    if (do_lock)
      _IO_funlockfile(fp);
    run_fp = NULL;

    if (last_stamp != _IO_list_all_stamp)
    {
      /* Something was added to the list.  Start all over again.  */
      fp = (_IO_FILE *)_IO_list_all;
      last_stamp = _IO_list_all_stamp;
    }
    else
      fp = fp->_chain;
  }

#ifdef _IO_MTSAFE_IO
  if (do_lock)
    _IO_lock_unlock(list_all_lock);
  __libc_cleanup_region_end(0);
#endif

  return result;
}
```

#### _IO_str_overflow

```c
int _IO_str_overflow (FILE *fp, int c)
{
  int flush_only = c == EOF;
  size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF)
	return EOF;
      else
	{
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base;
	  size_t old_blen = _IO_blen (fp); // _IO_buf_end - _IO_buf_base
	  size_t new_size = 2 * old_blen + 100; // 获取新大小
	  if (new_size < old_blen)
	    return EOF;
	  new_buf = malloc (new_size); // 使用malloc申请新的内存，从tcache中获取
	  if (new_buf == NULL)
	    {
	      return EOF;
	    }
	  if (old_buf)
	    {
	      memcpy (new_buf, old_buf, old_blen); // 从old_buf内容拷贝到新的buf中
	      free (old_buf); // 释放old_buf
	      fp->_IO_buf_base = NULL;
	    }
	  memset (new_buf + old_blen, '\0', new_size - old_blen);

	  _IO_setb (fp, new_buf, new_buf + new_size, 1);
	  fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
	  fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
	  fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
	  fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);

	  fp->_IO_write_base = new_buf;
	  fp->_IO_write_end = fp->_IO_buf_end;
	}
    }

  if (!flush_only)
    *fp->_IO_write_ptr++ = (unsigned char) c;
  if (fp->_IO_write_ptr > fp->_IO_read_end)
    fp->_IO_read_end = fp->_IO_write_ptr;
  return c;
}
libc_hidden_def (_IO_str_overflow)
```



#### _IO_fflush

```c
int _IO_fflush(FILE *fp)
{
  if (fp == NULL)
    return _IO_flush_all(); // 刷新所有打开可用的文件流
  else
  { // 处理单个流
    int result;
    CHECK_FILE(fp, EOF); // 验证是否有效
    _IO_acquire_lock(fp);
/*
#define _IO_SYNC(FP) JUMP0 (__sync, FP)
扩展到:
((IO_validate_vtable ((*(__typeof__ (((struct _IO_FILE_plus){}).vtable) *)(((char *) ((fp))) + __builtin_offsetof (struct _IO_FILE_plus, vtable)))))->__sync) (fp)
*/
    result = _IO_SYNC(fp) ? EOF : 0; // 调用vtable中的函数: 文件流的 __sync 函数指针
    _IO_release_lock(fp);
    return result;
  }
}
libc_hidden_def(_IO_fflush)
```



### printf

#### __fxprintf

```c
int __fxprintf(FILE *fp, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int res = __vfxprintf(fp, fmt, ap, 0);
  va_end(ap);
  return res;
}
```

#### __vfxprintf

```c
int __vfxprintf(FILE *fp, const char *fmt, va_list ap,
                unsigned int mode_flags)
{
  if (fp == NULL)
    fp = stderr;
  _IO_flockfile(fp);
  int res = locked_vfxprintf(fp, fmt, ap, mode_flags);
  _IO_funlockfile(fp);
  return res;
}
```

#### locked_vfxprintf

```c
// # define vfprintf	__vfprintf_internal

static int
locked_vfxprintf(FILE *fp, const char *fmt, va_list ap,
                 unsigned int mode_flags)
{
  if (_IO_fwide(fp, 0) <= 0)
    return __vfprintf_internal(fp, fmt, ap, mode_flags);

  wchar_t *wfmt;
  mbstate_t mbstate;
  int res;
  int used_malloc = 0;
  size_t len = strlen(fmt) + 1;

  if (__glibc_unlikely(len > SIZE_MAX / sizeof(wchar_t)))
  {
    __set_errno(EOVERFLOW);
    return -1;
  }
  if (__libc_use_alloca(len * sizeof(wchar_t)))
    wfmt = alloca(len * sizeof(wchar_t));
  else if ((wfmt = malloc(len * sizeof(wchar_t))) == NULL)
    return -1;
  else
    used_malloc = 1;

  memset(&mbstate, 0, sizeof mbstate);
  res = __mbsrtowcs(wfmt, &fmt, len, &mbstate);

  if (res != -1)
    res = __vfwprintf_internal(fp, wfmt, ap, mode_flags);

  if (used_malloc)
    free(wfmt);

  return res;
}
```

#### __printf

```c
int __printf (const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vfprintf_internal (stdout, format, arg, 0);
  va_end (arg);

  return done;
}
```

#### __register_printf_function

```c
int __register_printf_function(int spec, printf_function converter, 
                               printf_arginfo_function arginfo){
	return __register_printf_specifier(spec, converter,
                                       (printf_arginfo_size_function *)arginfo);
}
weak_alias(__register_printf_function, register_printf_function)
```

#### __register_printf_specifier

```c
int __register_printf_specifier(int spec, printf_function converter,
                                printf_arginfo_size_function arginfo){
  // spec: fmt的ascii码, converter与arginfo: 要绑定的函数与参数指针
  if (spec < 0 || spec > (int)UCHAR_MAX) // UCHAR_MAX: SCHAR_MAX[0x7f] * 2 + 1 = 0xff
  {
    __set_errno(EINVAL);
    return -1;
  }

  int result = 0;
  __libc_lock_lock(lock);
  
  // 若该表是空的
  if (__printf_function_table == NULL)
  {
    // calloc分配一块内存对arginfo表进行初始化，一次性分配两个指针份的堆块
    __printf_arginfo_table = (printf_arginfo_size_function **)
        calloc(UCHAR_MAX + 1, sizeof(void *) * 2);// void * 为8字节，共申请0x10 * 0x100
    if (__printf_arginfo_table == NULL)
    {
      result = -1;
      goto out;
    }
	// 初始化function表，紧邻arginfo表
    __printf_function_table = (printf_function **)(__printf_arginfo_table + UCHAR_MAX + 1);
  }
  // 绑定
  __printf_function_table[spec] = converter;
  __printf_arginfo_table[spec] = arginfo;

out:
  __libc_lock_unlock(lock);

  return result;
}
libc_hidden_def(__register_printf_specifier)
    weak_alias(__register_printf_specifier, register_printf_specifier)
```

### assert

#### __malloc_assert

```c
static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);
  abort ();
}
```

### cookie

#### _IO_cookie_read

```c
static ssize_t
_IO_cookie_read(FILE *fp, void *buf, ssize_t size)
{
  // 将fp转换为_IO_cookie_file *类型的cfile结构体
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *)fp;
  // 通过偏移取出存放在read对应对象中的函数指针
  cookie_read_function_t *read_cb = cfile->__io_functions.read;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE(read_cb); // 进行了加密
#endif

  if (read_cb == NULL)
    return -1;

  return read_cb(cfile->__cookie, buf, size); // 调用该指针，传入参数为__cookie
}
```

#### _IO_cookie_write

```c
static ssize_t
_IO_cookie_write(FILE *fp, const void *buf, ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *)fp;
  cookie_write_function_t *write_cb = cfile->__io_functions.write;
#ifdef PTR_DEMANGLE
  // 对指针进行加密：取出对应函数指针，将函数指针循环右移11位，并与`fs:[0x30]`异或得到真正函数地址
  PTR_DEMANGLE(write_cb); 
#endif

  if (write_cb == NULL)
  {
    fp->_flags |= _IO_ERR_SEEN;
    return 0;
  }

  ssize_t n = write_cb(cfile->__cookie, buf, size);
  if (n < size)
    fp->_flags |= _IO_ERR_SEEN;

  return n;
}
```

#### _IO_cookie_close

```c
static int
_IO_cookie_close(FILE *fp)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *)fp;
  cookie_close_function_t *close_cb = cfile->__io_functions.close;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE(close_cb);
#endif

  if (close_cb == NULL)
    return 0;

  return close_cb(cfile->__cookie);
}
```



#### _IO_cookie_seek

```c
static off64_t
_IO_cookie_seek(FILE *fp, off64_t offset, int dir)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *)fp;
  cookie_seek_function_t *seek_cb = cfile->__io_functions.seek;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE(seek_cb);
#endif

  return ((seek_cb == NULL || (seek_cb(cfile->__cookie, &offset, dir) == -1) || offset == (off64_t)-1)
              ? _IO_pos_BAD
              : offset);
}
```

### house of apple

记录相关一些函数

#### _IO_wstrn_overflow

```c
static wint_t _IO_wstrn_overflow (FILE *fp, wint_t c)
{
  // 先将 fp 强制转换为_IO_wstrnfile *指针
  _IO_wstrnfile *snf = (_IO_wstrnfile *) fp;

  if (fp->_wide_data->_IO_buf_base != snf->overflow_buf) // 一般都成立
    {
      _IO_wsetb (fp, snf->overflow_buf,
		 snf->overflow_buf + (sizeof (snf->overflow_buf)
				      / sizeof (wchar_t)), 0);
	  // 成立会对以下四个值赋值为`snf->overflow_buf`或相关偏移值
      fp->_wide_data->_IO_write_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_ptr = snf->overflow_buf;
      fp->_wide_data->_IO_read_end = (snf->overflow_buf
				      + (sizeof (snf->overflow_buf)
					 / sizeof (wchar_t)));
    }
  // 赋值
  fp->_wide_data->_IO_write_ptr = snf->overflow_buf;
  fp->_wide_data->_IO_write_end = snf->overflow_buf;

  return c;
}
```

#### _IO_wsetb

```c
void _IO_wsetb (FILE *f, wchar_t *b, wchar_t *eb, int a)
{
  if (f->_wide_data->_IO_buf_base && !(f->_flags2 & _IO_FLAGS2_USER_WBUF))
    free (f->_wide_data->_IO_buf_base); // 其不为0的时候不要执行到这里
  f->_wide_data->_IO_buf_base = b;
  f->_wide_data->_IO_buf_end = eb;
  if (a)
    f->_flags2 &= ~_IO_FLAGS2_USER_WBUF;
  else
    f->_flags2 |= _IO_FLAGS2_USER_WBUF;
}

```

#### __libio_codecvt_in

```c
enum __codecvt_result
__libio_codecvt_in (struct _IO_codecvt *codecvt, __mbstate_t *statep,
		    const char *from_start, const char *from_end,
		    const char **from_stop,
		    wchar_t *to_start, wchar_t *to_end, wchar_t **to_stop)
{
  enum __codecvt_result result;

  struct __gconv_step *gs = codecvt->__cd_in.step; // // gs 源自第一个参数
  int status;
  size_t dummy;
  const unsigned char *from_start_copy = (unsigned char *) from_start;

  codecvt->__cd_in.step_data.__outbuf = (unsigned char *) to_start;
  codecvt->__cd_in.step_data.__outbufend = (unsigned char *) to_end;
  codecvt->__cd_in.step_data.__statep = statep;

  __gconv_fct fct = gs->__fct;
  // 若其不为空，用__pointer_guard解密，设置为NULL可绕过解密
  if (gs->__shlib_handle != NULL)
    PTR_DEMANGLE (fct);
  // 函数指针调用，该宏实际调用fct(gs, ...)
  status = DL_CALL_FCT (fct,
			(gs, &codecvt->__cd_in.step_data, &from_start_copy,
			 (const unsigned char *) from_end, NULL,
			 &dummy, 0, 0));

  *from_stop = (const char *) from_start_copy;
  *to_stop = (wchar_t *) codecvt->__cd_in.step_data.__outbuf;

  switch (status)
    {
    case __GCONV_OK:
    case __GCONV_EMPTY_INPUT:
      result = __codecvt_ok;
      break;

    case __GCONV_FULL_OUTPUT:
    case __GCONV_INCOMPLETE_INPUT:
      result = __codecvt_partial;
      break;

    default:
      result = __codecvt_error;
      break;
    }

  return result;
}
```



## ld.so

### 结构

#### rtld_global

```c
struct rtld_global
{
#endif
#ifdef SHARED
# define DL_NNS 16
#else
# define DL_NNS 1
#endif
  EXTERN struct link_namespaces
  {
    struct link_map *_ns_loaded;
    unsigned int _ns_nloaded;
    struct r_scope_elem *_ns_main_searchlist;

    unsigned int _ns_global_scope_alloc;
    unsigned int _ns_global_scope_pending_adds;

    struct link_map *libc_map;
    struct unique_sym_table
    {
      __rtld_lock_define_recursive (, lock)
      struct unique_sym
      {
	uint32_t hashval;
	const char *name;
	const ElfW(Sym) *sym;
	const struct link_map *map;
      } *entries;
      size_t size;
      size_t n_elements;
      void (*free) (void *);
    } _ns_unique_sym_table;

    struct r_debug_extended _ns_debug;
  } _dl_ns[DL_NNS];

  EXTERN size_t _dl_nns;
  ......
```



#### _rtld_global

可用 gdb 查看`p _rtld_global`

```c
// glibc-2.38 rtld.c 该变量在 ld.so 内存地址范围内

struct rtld_global _rtld_global =
  {
#include <dl-procruntime.c>
    ._dl_stack_flags = DEFAULT_STACK_PERMS,
#ifdef _LIBC_REENTRANT
    ._dl_load_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
    ._dl_load_write_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
    ._dl_load_tls_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
#endif
    ._dl_nns = 1,
    ._dl_ns =
    {
#ifdef _LIBC_REENTRANT
      [LM_ID_BASE] = { ._ns_unique_sym_table
		       = { .lock = _RTLD_LOCK_RECURSIVE_INITIALIZER } }
#endif
    }
  };
```

#### _dl_ns

```c
// _dl_ns 为 link_namespaces 结构体 16 项数组
pwndbg> p &_rtld_global._dl_ns
$1 = (struct link_namespaces (*)[16]) 0x7ffff7ffd040 <_rtld_local>

pwndbg> p _rtld_global._dl_ns
$2 = {{
    _ns_loaded = 0x7ffff7ffe168,
    _ns_nloaded = 4,
    _ns_main_searchlist = 0x7ffff7ffe420,
    _ns_global_scope_alloc = 0,
    _ns_unique_sym_table = {
      lock = {
        mutex = {
          __data = {
            __lock = 0,
            __count = 0,
            __owner = 0,
            __nusers = 0,
            __kind = 1,
            __spins = 0,
            __elision = 0,
            __list = {
              __prev = 0x0,
              __next = 0x0
            }
          },
          __size = '\000' <repeats 16 times>, "\001", '\000' <repeats 22 times>,
          __align = 0
        }
      },
      entries = 0x0,
      size = 0,
      n_elements = 0,
      free = 0x0
    },
    _ns_debug = {
      r_version = 0,
      r_map = 0x0,
      r_brk = 0,
      r_state = RT_CONSISTENT,
      r_ldbase = 0
    }
  }, {
    _ns_loaded = 0x0,
    _ns_nloaded = 0,
    _ns_main_searchlist = 0x0,
    _ns_global_scope_alloc = 0,
    _ns_unique_sym_table = {
      lock = {
        mutex = {
          __data = {
            __lock = 0,
            __count = 0,
            __owner = 0,
            __nusers = 0,
            __kind = 0,
            __spins = 0,
            __elision = 0,
            __list = {
              __prev = 0x0,
              __next = 0x0
            }
          },
          __size = '\000' <repeats 39 times>,
          __align = 0
        }
      },
      entries = 0x0,
      size = 0,
      n_elements = 0,
      free = 0x0
    },
    _ns_debug = {
      r_version = 0,
      r_map = 0x0,
      r_brk = 0,
      r_state = RT_CONSISTENT,
      r_ldbase = 0
    }
  } <repeats 15 times>}
```

**第 0 项**

```c
pwndbg> p _rtld_global._dl_ns[0]
$9 = {
  _ns_loaded = 0x7ffff7ffe168, // (struct link_map *) 指向 link_map 结构体的指针
  _ns_nloaded = 4, // 表示 _ns_nloaded 有多少 link_map 结构体
  _ns_main_searchlist = 0x7ffff7ffe420,
  _ns_global_scope_alloc = 0,
  _ns_unique_sym_table = {
    lock = {
      mutex = {
        __data = {
          __lock = 0,
          __count = 0,
          __owner = 0,
          __nusers = 0,
          __kind = 1,
          __spins = 0,
          __elision = 0,
          __list = {
            __prev = 0x0,
            __next = 0x0
          }
        },
        __size = '\000' <repeats 16 times>, "\001", '\000' <repeats 22 times>,
        __align = 0
      }
    },
    entries = 0x0,
    size = 0,
    n_elements = 0,
    free = 0x0
  },
  _ns_debug = {
    r_version = 0,
    r_map = 0x0,
    r_brk = 0,
    r_state = RT_CONSISTENT,
    r_ldbase = 0
  }
}
```



#### _dl_nns

```c
pwndbg> p &_rtld_global._dl_nns
$3 = (size_t *) 0x7ffff7ffd940 <_rtld_local+2304>
pwndbg> p _rtld_global._dl_nns
$4 = 1 // 表明 _dl_ns 数组中有效的项，一般为第0项
```



#### link_map

```c
struct link_map
{
   ElfW(Addr) l_addr; // 程序加载的内存基址
   char *l_name;
   ElfW(Dyn) * l_ld;
   struct link_map *l_next, *l_prev; // 双向链表结构，分别指向下一个和前一个link_map结构体

   struct link_map *l_real; // 标识该共享库的真实映射

   Lmid_t l_ns;

   struct libname_list *l_libname;
   // l_info 指向 ELF 文件的Dynamic节，包括指向 DT_INIT、DT_FINI、DT_FINI_ARRAY 和其他Dynamic节的指针
   ElfW(Dyn) * l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
   const ElfW(Phdr) * l_phdr;
   ElfW(Addr) l_entry;
   ElfW(Half) l_phnum;
   ElfW(Half) l_ldnum;

   struct r_scope_elem l_searchlist;

   struct r_scope_elem l_symbolic_searchlist;

   struct link_map *l_loader;

   struct r_found_version *l_versions;
   unsigned int l_nversions;

   Elf_Symndx l_nbuckets;
   Elf32_Word l_gnu_bitmask_idxbits;
   Elf32_Word l_gnu_shift;
   const ElfW(Addr) * l_gnu_bitmask;
   union
   {
      const Elf32_Word *l_gnu_buckets;
      const Elf_Symndx *l_chain;
   };
   union
   {
      const Elf32_Word *l_gnu_chain_zero;
      const Elf_Symndx *l_buckets;
   };

   unsigned int l_direct_opencount;
   enum
   {
      lt_executable,
      lt_library,
      lt_loaded
   } l_type : 2;
   unsigned int l_dt_relr_ref : 1;
   unsigned int l_relocated : 1;
   unsigned int l_init_called : 1;
   unsigned int l_global : 1;
   unsigned int l_reserved : 2;
   unsigned int l_main_map : 1;
   unsigned int l_visited : 1;
   unsigned int l_map_used : 1;
   unsigned int l_map_done : 1;
   unsigned int l_phdr_allocated : 1;
   unsigned int l_soname_added : 1;
   unsigned int l_faked : 1;
   unsigned int l_need_tls_init : 1;
   unsigned int l_auditing : 1;
   unsigned int l_audit_any_plt : 1;
   unsigned int l_removed : 1;
   unsigned int l_contiguous : 1;
   unsigned int l_free_initfini : 1;
   unsigned int l_ld_readonly : 1;
   unsigned int l_find_object_processed : 1;
   bool l_nodelete_active;
   bool l_nodelete_pending;

#include <link_map.h>

   struct r_search_path_struct l_rpath_dirs;

   struct reloc_result
   {
      DL_FIXUP_VALUE_TYPE addr;
      struct link_map *bound;
      unsigned int boundndx;
      uint32_t enterexit;
      unsigned int flags;
      unsigned int init;
   } *l_reloc_result;

   ElfW(Versym) * l_versyms;

   const char *l_origin;

   ElfW(Addr) l_map_start, l_map_end;

   ElfW(Addr) l_text_end;

   struct r_scope_elem *l_scope_mem[4];

   size_t l_scope_max;
   struct r_scope_elem **l_scope;

   struct r_scope_elem *l_local_scope[2];

   struct r_file_id l_file_id;
   struct r_search_path_struct l_runpath_dirs;

   struct link_map **l_initfini;
   struct link_map_reldeps
   {
      unsigned int act;
      struct link_map *list[];
   } *l_reldeps;
   unsigned int l_reldepsmax;

   unsigned int l_used;

   ElfW(Word) l_feature_1;
   ElfW(Word) l_flags_1;
   ElfW(Word) l_flags;

   int l_idx;

   struct link_map_machine l_mach;

   struct
   {
      const ElfW(Sym) * sym;
      int type_class;
      struct link_map *value;
      const ElfW(Sym) * ret;
   } l_lookup_cache;

   void *l_tls_initimage;
   size_t l_tls_initimage_size;
   size_t l_tls_blocksize;
   size_t l_tls_align;
   size_t l_tls_firstbyte_offset;
#ifndef NO_TLS_OFFSET
#define NO_TLS_OFFSET 0
#endif
#ifndef FORCED_DYNAMIC_TLS_OFFSET
#if NO_TLS_OFFSET == 0
#define FORCED_DYNAMIC_TLS_OFFSET -1
#elif NO_TLS_OFFSET == -1
#define FORCED_DYNAMIC_TLS_OFFSET -2
#else
#error "FORCED_DYNAMIC_TLS_OFFSET is not defined"
#endif
#endif
   ptrdiff_t l_tls_offset;
   size_t l_tls_modid;
   size_t l_tls_dtor_count;
   ElfW(Addr) l_relro_addr;
   size_t l_relro_size;

   unsigned long long int l_serial;
};
```



### 2.38

#### _dl_fini

程序退出或动态库卸载时调用所有已加载共享库（ `.so` 文件）的析构函数

```c
void _dl_fini (void)
{
#ifdef SHARED
  int do_audit = 0; // 标记是否进行审计操作
 again: // 用于重试的逻辑
#endif
  // GL(dl_nns): 命名空间的数量，一般为 1，此时 ns 为 0
  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns) // 从最后一个命名空间开始遍历所有命名空间
    {
      __rtld_lock_lock_recursive (GL(dl_load_lock)); // 加锁

      unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded; // 当前命名空间中加载的共享对象数量, 即多少个link_map
      if (nloaded == 0
#ifdef SHARED
	  || GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
#endif
	  )
	__rtld_lock_unlock_recursive (GL(dl_load_lock)); // 释放锁
      else
	{
#ifdef SHARED
	  _dl_audit_activity_nsid (ns, LA_ACT_DELETE); // 审计活动标记为删除(LA_ACT_DELETE), 	记录审计日志
#endif

	  struct link_map *maps[nloaded]; // maps 数组收集当前命名空间中所有加载的共享对象

	  unsigned int i;
	  struct link_map *l;
	  assert (nloaded != 0 || GL(dl_ns)[ns]._ns_loaded == NULL);
      // 遍历链表中每一个link_map结构体
	  for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
	    if (l == l->l_real) // 需要指向自身
	      {
		assert (i < nloaded);

		maps[i] = l; // 将指针存到 maps 中初始化
		l->l_idx = i; // 赋值索引
		++i; // 索引自增
		++l->l_direct_opencount;
	      }
      // 检查	ns = 0, LM_ID_BASE = 0
	  assert (ns != LM_ID_BASE || i == nloaded);
	  assert (ns == LM_ID_BASE || i == nloaded || i == nloaded - 1);
	  unsigned int nmaps = i;

      // 对 maps 数组中共享对象进行排序，确保按正确的顺序调用析构函数
	  _dl_sort_maps (maps, nmaps, (ns == LM_ID_BASE), true); // 伪造变化可能卡在此处

	  __rtld_lock_unlock_recursive (GL(dl_load_lock));

	  for (i = 0; i < nmaps; ++i) // 遍历maps数组
	    {
	      struct link_map *l = maps[i]; // 取出结构体

	      if (l->l_init_called)
		{
		  _dl_call_fini (l); // 调用每个加载对象的析构函数
#ifdef SHARED
		  _dl_audit_objclose (l);
#endif
		}
	      --l->l_direct_opencount;
	    }

#ifdef SHARED
	  _dl_audit_activity_nsid (ns, LA_ACT_CONSISTENT);
#endif
	}
    }

#ifdef SHARED
  if (! do_audit && GLRO(dl_naudit) > 0)
    {
      do_audit = 1;
      goto again;
    }

  if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_STATISTICS))
    _dl_debug_printf ("\nruntime linker statistics:\n"
		      "           final number of relocations: %lu\n"
		      "final number of relocations from cache: %lu\n",
		      GL(dl_num_relocations),
		      GL(dl_num_cache_relocations));
#endif
}
```

#### _dl_call_fini

```c
void _dl_call_fini(void *closure_map)
{
  struct link_map *map = closure_map;

  if (__glibc_unlikely(GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))
    _dl_debug_printf("\ncalling fini: %s [%lu]\n\n", map->l_name, map->l_ns);

  map->l_init_called = 0;

  ElfW(Dyn) *fini_array = map->l_info[DT_FINI_ARRAY]; // 取出第26项
  if (fini_array != NULL)
  {
    ElfW(Addr) *array = (ElfW(Addr) *)(map->l_addr + fini_array->d_un.d_ptr); // 相加找到array指针数组
    size_t sz = (map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof(ElfW(Addr))); // 第28项获取大小size

    while (sz-- > 0) // 从后往前依次调用array数组中的函数
      ((fini_t)array[sz])();
  }

  ElfW(Dyn) *fini = map->l_info[DT_FINI];
  if (fini != NULL)
    DL_CALL_DT_FINI(map, ((void *)map->l_addr + fini->d_un.d_ptr));
}
```

## TLS

### 结构

#### tcbhead_t

```c
typedef struct {
  void *tcb;    /* 指向TCB */
  dtv_t *dtv;       /* 指向dtv数组 */
  void *self;   /* 指向自身  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;    /* canary值 */
  uintptr_t pointer_guard;  /* 用于保护指针 */
  //...
} tcbhead_t;
```


