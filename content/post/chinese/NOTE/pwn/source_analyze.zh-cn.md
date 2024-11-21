---
title: "源码分析"
description: 
date: 2024-11-19
image: /img/note.jpg
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - pwn
    - notes

typora-root-url: ..\..\..\..\..\static
---

## 结构

### malloc_par

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

### heap_info

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

## malloc

### 2.23

#### 宏

```c
SIZE_SZ				// sizeof( size_t ) 1字节大小
MALLOC_ALIGN_MASK	// ( 2 * SIZE_SZ ) - 1 = 2 * 8 - 1 = 0x10 - 1
MINSIZE 			// ( MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK ) & ~MALLOC_ALIGN_MASK 向下取整
MIN_CHUNK_SIZE 		// offsetof( struct malloc_chunk, fd_nextsize ) 0x20字节
```

#### __libc_malloc

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

#### _int_malloc

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

#### checked_request2size

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

<img src="/img/source_analyze.zh-cn.assets/image-20241119131202911.png" alt="image-20241119131202911" style="zoom:80%;" />

#### get_max_fast

```c
#define get_max_fast() global_max_fast

#define set_max_fast(s) 
	global_max_fast = (((s) == 0) ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))

set_max_fast(DEFAULT_MXFAST); // malloc_init_state函数中

#define DEFAULT_MXFAST (64 * SIZE_SZ / 4) // 64*8/4=128=0x80
```

#### fastbin_index

```c
#define fastbin_index(sz) ((((unsigned int)(sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
// 64位下 申请size右移4位再减2，最小的size为0x20，则0x20/16-2=0索引
```

#### chunk_size

```c
#define chunksize(p) ((p)->size & ~(SIZE_BITS)) // 去除3个标志位后得到chunk的size
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

#### chunk2mem

```c
#define chunk2mem(p) ((void *)((char *)(p) + 2 * SIZE_SZ))
// 将指向 prev_size 的指针偏移2个机器字长后指向 fd
```

#### in_smallbin_range

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

#### malloc_consolidate

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

#### malloc_init_state

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

#### unlink

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

### 2.27

#### __libc_malloc

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

#### _int_malloc

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

#### REMOVE_FB

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



#### tcache_init

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

#### tcache_get

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

#### tcache_put

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



## sysmalloc

### 2.23

#### sysmalloc

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
      old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK; // 预留两个头来作为标记，防止错误
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

#### MMAP

```c
#define MMAP(addr, size, prot, flags)
	__mmap((addr), (size), (prot), (flags) | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
```

#### initial_top

```c
// 为方便，unsorted bin在第一次调用时可作为虚假的top chunk
#define initial_top(M) (unsorted_chunks(M))
#define unsorted_chunks(M) (bin_at(M, 1))
```

#### heap_for_ptr

```c
#define heap_for_ptr(ptr) 
	((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))
/* 
	非主线程的堆都按照 HEAP_MAX_SIZE对齐分配，
	ptr & ~0xfffff 即将ptr的后5位置0，可以获取 heap_info 结构体的起始地址
*/
#  define HEAP_MAX_SIZE (1024 * 1024) /* 0x100000，必须是2的幂 */
```

#### grow_heap

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

#### new_heap

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

#### MORECORE

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



## free



## calloc



## realloc

