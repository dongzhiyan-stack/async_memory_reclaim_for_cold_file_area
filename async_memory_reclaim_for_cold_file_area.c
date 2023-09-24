#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/vmpressure.h>
#include <linux/vmstat.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/mm_inline.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/compaction.h>
#include <linux/notifier.h>
#include <linux/rwsem.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/delayacct.h>
#include <linux/sysctl.h>
#include <linux/oom.h>
#include <linux/pagevec.h>
#include <linux/prefetch.h>
#include <linux/printk.h>
#include <linux/dax.h>
#include <linux/psi.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>

#include <linux/swapops.h>
#include <linux/balloon_compaction.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/mm_inline.h>
#include <linux/proc_fs.h>
//#include <linux/slub_def.h>
//#include <linux/slab_def.h> 能添加，编译同时报错invalid use of undefined type ‘const struct slab’

//一个file_stat结构里缓存的热file_area结构个数
#define FILE_AREA_CACHE_COUNT 3
//置1才允许异步内存回收
#define ASYNC_MEMORY_RECLAIM_ENABLE 0
//置1说明说明触发了drop_cache，此时禁止异步内存回收线程处理gloabl drop_cache_file_stat_head链表上的file_stat
#define ASYNC_DROP_CACHES 1
//异步内存回收周期，单位s
#define ASYNC_MEMORY_RECLIAIM_PERIOD 60
//最大文件名字长度
#define MAX_FILE_NAME_LEN 100
//当一个文件file_stat长时间不被访问，释放掉了所有的file_area，再过FILE_STAT_DELETE_AGE_DX个周期，则释放掉file_stat结构
#define FILE_STAT_DELETE_AGE_DX  10
//一个 file_area 包含的page数，默认4个
#define PAGE_COUNT_IN_AREA_SHIFT 2
#define PAGE_COUNT_IN_AREA (1UL << PAGE_COUNT_IN_AREA_SHIFT)

#define TREE_MAP_SHIFT	6
#define TREE_MAP_SIZE	(1UL << TREE_MAP_SHIFT)
#define TREE_MAP_MASK (TREE_MAP_SIZE - 1)
#define TREE_ENTRY_MASK 3
#define TREE_INTERNAL_NODE 1

//热file_area经过FILE_AREA_HOT_to_TEMP_AGE_DX个周期后，还没有被访问，则移动到file_area_temp链表
#define FILE_AREA_HOT_to_TEMP_AGE_DX  3
//发生refault的file_area经过FILE_AREA_REFAULT_TO_TEMP_AGE_DX个周期后，还没有被访问，则移动到file_area_temp链表
#define FILE_AREA_REFAULT_TO_TEMP_AGE_DX 10
//普通的file_area在FILE_AREA_TEMP_TO_COLD_AGE_DX个周期内没有被访问则被判定是冷file_area，然后释放这个file_area的page
#define FILE_AREA_TEMP_TO_COLD_AGE_DX  5
//一个冷file_area，如果经过FILE_AREA_FREE_AGE_DX个周期，仍然没有被访问，则释放掉file_area结构
#define FILE_AREA_FREE_AGE_DX  5
//当一个file_area在一个周期内访问超过FILE_AREA_HOT_LEVEL次数，则判定是热的file_area
#define FILE_AREA_HOT_LEVEL (PAGE_COUNT_IN_AREA << 1)

struct hot_cold_file_shrink_counter
{
	/**get_file_area_from_file_stat_list()函数******/
	//扫描的file_area个数
	unsigned int scan_file_area_count;
	//扫描的file_stat个数
	unsigned int scan_file_stat_count;
	//扫描到的处于delete状态的file_stat个数
	unsigned int scan_delete_file_stat_count;
	//扫描的冷file_stat个数
	unsigned int scan_cold_file_area_count;
	//扫描到的大文件转小文件的个数
	unsigned int scan_large_to_small_count;
	//本次扫描到但没有冷file_area的file_stat个数
	unsigned int scan_fail_file_stat_count;

	/**free_page_from_file_area()函数******/
	//释放的page个数
	unsigned int free_pages;
	//隔离的page个数
	unsigned int isolate_lru_pages;
	//file_stat的refault链表转移到temp链表的file_area个数
	unsigned int file_area_refault_to_temp_list_count;
	//释放的file_area结构个数
	unsigned int file_area_free_count;
	//file_stat的hot链表转移到temp链表的file_area个数
	unsigned int file_area_hot_to_temp_list_count;

	/**free_page_from_file_area()函数******/
	//file_stat的hot链表转移到temp链表的file_area个数
	unsigned int file_area_hot_to_temp_list_count2;
	//释放的file_stat个数
	unsigned int del_file_stat_count;
	//释放的file_area个数
	unsigned int del_file_area_count;

	/**async_shrink_free_page()函数******/
	unsigned int lock_fail_count;
	unsigned int writeback_count;
	unsigned int dirty_count;
	unsigned int page_has_private_count;
	unsigned int mapping_count;
	unsigned int free_pages_count;
	unsigned int free_pages_fail_count;
	unsigned int page_unevictable_count; 

	/**file_stat_has_zero_file_area_manage()函数****/
	unsigned int scan_zero_file_area_file_stat_count;

	//进程抢占lru_lock锁的次数
    unsigned int lru_lock_contended_count;
    //释放的file_area但是处于hot_file_area_cache数组的file_area个数
	unsigned int file_area_delete_in_cache_count;
	//从hot_file_area_cache命中file_area次数
	unsigned int file_area_cache_hit_count;

	//file_area内存回收期间file_area被访问的次数
	unsigned int file_area_access_count_in_free_page;
	//在内存回收期间产生的热file_area个数
	unsigned int hot_file_area_count_in_free_page;
	//在内存回收期间产生的refault file_area个数
	unsigned int refault_file_area_count_in_free_page;

	//一个周期内产生的热file_area个数
	unsigned int hot_file_area_count_one_period;
	//一个周期内产生的refault file_area个数
	unsigned int refault_file_area_count_one_period;
	//每个周期执行hot_file_update_file_status函数访问所有文件的所有file_area总次数
    unsigned int all_file_area_access_count;
	//每个周期直接从file_area_tree找到file_area并且不用加锁次数加1
    unsigned int find_file_area_from_tree_not_lock_count;
};
//一个file_area表示了一片page范围(默认6个page)的冷热情况，比如page索引是0~5、6~11、12~17各用一个file_area来表示
struct file_area
{
	//不同取值表示file_area当前处于哪种链表
	unsigned char file_area_state;
	//该file_area最近被访问时的global_age，长时间不被访问则与global age差很多，则判定file_area是冷file_area，然后释放该file_area的page
	unsigned long file_area_age;
	//该file_area当前周期被访问的次数
	//unsigned int access_count;
	atomic_t   access_count;

	//该file_area里的某个page最近一次被回收的时间点，单位秒
	unsigned int shrink_time;
	//file_area通过file_area_list添加file_stat的各种链表
	struct list_head file_area_list;
	/*指向父hot_cold_file_area_tree_node节点，作用是在cold_file_area_detele()函数把file_area从hot file tree剔除时，顺便剔除没有成员的父节点，
	 * 并且逐级向上剔除父节点，最终删除整个hot file tree。其实这个parent可以没有，因为可以根据file_area的start_index从hot file tree找到它的父
	 * 节点，也能实现同样效果呢。但是这样耗时比较多，并且根据file_area的start_index从hot file tree找到它的父节点需要file_stat_lock加锁，
	 * 稍微耗时，影响hot_file_update_file_status()获取file_stat_lock锁*/
	struct hot_cold_file_area_tree_node *parent;
	//该file_area代表的N个连续page的起始page索引
	pgoff_t start_index;
};
struct hot_cold_file_area_tree_node
{
	//与该节点树下最多能保存多少个page指针有关
	unsigned char   shift;
	//在节点在父节点中的偏移
	unsigned char   offset;
	//指向父节点
	struct hot_cold_file_area_tree_node *parent;
	//该节点下有多少个成员
	unsigned int    count;
	//是叶子节点时保存file_area结构，是索引节点时保存子节点指针
	void    *slots[TREE_MAP_SIZE];
};
struct hot_cold_file_area_tree_root
{
	unsigned int  height;//树高度
	struct hot_cold_file_area_tree_node __rcu *root_node;
};
//热点文件统计信息，一个文件一个
struct file_stat
{
	struct address_space *mapping;
	//file_stat通过hot_cold_file_list添加到hot_cold_file_global的file_stat_hot_head链表
	struct list_head hot_cold_file_list;
	//file_stat状态
	unsigned long file_stat_status;
	//总file_area个数
	unsigned int file_area_count;
	//热file_area个数
	unsigned int file_area_hot_count;
	//文件的file_area结构按照索引保存到这个radix tree
	struct hot_cold_file_area_tree_root hot_cold_file_area_tree_root_node;
	//file_stat锁
	spinlock_t file_stat_lock;
	//file_stat里age最大的file_area的age，调试用
	unsigned long max_file_area_age;
	//file_stat最近一次被异步内存回收访问时的age，调试用
	unsigned long recent_access_age;

	//频繁被访问的文件page对应的file_area存入这个头结点
	struct list_head file_area_hot;
	//不冷不热处于中间状态的file_area结构添加到这个链表，新分配的file_area就添加到这里
	struct list_head file_area_temp;
	//每轮扫描被释放内存page的file_area结构临时先添加到这个链表。file_area_free_temp有存在的必要
	struct list_head file_area_free_temp;
	//所有被释放内存page的file_area结构最后添加到这个链表，如果长时间还没被访问，就释放file_area结构。
	struct list_head file_area_free;
	//file_area的page被释放后，但很快又被访问，发生了refault，于是要把这种page添加到file_area_refault链表，短时间内不再考虑扫描和释放
	struct list_head file_area_refault;

	//把最近访问的file_stat保存到hot_file_area_cache缓存数组，
    struct file_area * hot_file_area_cache[FILE_AREA_CACHE_COUNT];
	//最近一次访问的热file_area以hot_file_area_cache_index为下标保存到hot_file_area_cache数组
	unsigned char hot_file_area_cache_index;
};
/*hot_cold_file_node_pgdat结构体每个内存节点分配一个，内存回收前，从lruvec lru链表隔离成功page，移动到每个内存节点绑定的
 * hot_cold_file_node_pgdat结构的pgdat_page_list链表上.然后参与内存回收。内存回收后把pgdat_page_list链表上内存回收失败的
 * page在putback移动回lruvec lru链表。这样做的目的是减少内存回收失败的page在putback移动回lruvec lru链表时，可以减少
 * lruvec->lru_lock或pgdat->lru_lock加锁，详细分析见cold_file_isolate_lru_pages()函数。但实际测试时，内存回收失败的page是很少的，
 * 这个做法的意义又不太大!其实完全可以把参与内存回收的page移动到一个固定的链表也可以！*/
struct hot_cold_file_node_pgdat
{
	pg_data_t *pgdat;
	struct list_head pgdat_page_list;
};
//热点文件统计信息全局结构体
struct hot_cold_file_global
{
	/*被判定是热文本的file_stat添加到file_stat_hot_head链表,超过50%或者80%的file_area都是热的，则该文件就是热文件，
	 * 文件的file_stat要移动到global的file_stat_hot_head链表*/
	struct list_head file_stat_hot_head;
	//新分配的文件file_stat默认添加到file_stat_temp_head链表
	struct list_head file_stat_temp_head;
	/*如果文件file_stat上的page cache数太多，被判定为大文件，则把file_stat移动到这个链表。将来内存回收时，优先遍历这种file_stat，
	 *因为file_area足够多，能遍历到更多的冷file_area，回收到内存page*/
	struct list_head file_stat_temp_large_file_head;
	struct list_head cold_file_head;
	//inode被删除的文件的file_stat移动到这个链表
	struct list_head file_stat_delete_head;
	//0个file_area的file_stat移动到这个链表
	struct list_head file_stat_zero_file_area_head;
	//触发drop_cache后的没有file_stat的文件，分配file_stat后保存在这个链表
	struct list_head drop_cache_file_stat_head;
    
	//触发drop_cache后的没有file_stat的文件个数
    unsigned int drop_cache_file_count;
	/*当file_stat的file_area个数达到file_area_count_for_large_file时，表示该文件的page cache数太多，被判定为大文件。但一个file_area
	 *包含了多个page，一个file_area并不能填满page，因此实际file_stat的file_area个数达到file_area_count_for_large_file时，实际该文件的的page cache数会少点*/
	int file_area_count_for_large_file;
    //热文件file_stat个数
	unsigned int file_stat_hot_count;
	//大文件file_stat个数
	unsigned int file_stat_large_count;
	//文件file_stat个数
	unsigned int file_stat_count;
	//0个file_area的file_stat个数
	unsigned int file_stat_count_zero_file_area;

	struct kmem_cache *file_stat_cachep;
	struct kmem_cache *file_area_cachep;
	//保存文件file_stat所有file_area的radix tree
	struct kmem_cache *hot_cold_file_area_tree_node_cachep;
	struct hot_cold_file_node_pgdat *p_hot_cold_file_node_pgdat;
	//异步内存回收线程
	struct task_struct *hot_cold_file_thead;
	int node_count;

	//有多少个进程在执行hot_file_update_file_status函数使用文件file_stat、file_area
	atomic_t   ref_count;
	//有多少个进程在执行__destroy_inode_handler_post函数，正在删除文件inode
	atomic_t   inode_del_count;
	//内存回收各个参数统计
	struct hot_cold_file_shrink_counter hot_cold_file_shrink_counter;
	//proc文件系统根节点
	struct proc_dir_entry *hot_cold_file_proc_root;

	spinlock_t global_lock;
    //全局age，每个周期加1
	unsigned long global_age;
	//异步内存回收周期，单位s
	unsigned int global_age_period;
	//热file_area经过file_area_refault_to_temp_age_dx个周期后，还没有被访问，则移动到file_area_temp链表
	unsigned int file_area_hot_to_temp_age_dx;
	//发生refault的file_area经过file_area_refault_to_temp_age_dx个周期后，还没有被访问，则移动到file_area_temp链表
	unsigned int file_area_refault_to_temp_age_dx;
	//普通的file_area在file_area_temp_to_cold_age_dx个周期内没有被访问则被判定是冷file_area，然后释放这个file_area的page
	unsigned int file_area_temp_to_cold_age_dx;
	//一个冷file_area，如果经过file_area_free_age_dx_fops个周期，仍然没有被访问，则释放掉file_area结构
	unsigned int file_area_free_age_dx;
	//当一个文件file_stat长时间不被访问，释放掉了所有的file_area，再过file_stat_delete_age_dx个周期，则释放掉file_stat结构
	unsigned int file_stat_delete_age_dx;
};


/*******file_area状态**********************************************************/
enum file_area_status{//file_area_state是char类型，只有8个bit位可设置
	F_file_area_in_temp_list,
	F_file_area_in_hot_list,
	//F_file_area_in_free_temp_list,
	F_file_area_in_free_list,
	F_file_area_in_refault_list,
	F_file_area_in_cache,//file_area保存在ile_stat->hot_file_area_cache[]数组里
};
//不能使用 clear_bit_unlock、test_and_set_bit_lock、test_bit，因为要求p_file_area->file_area_state是64位数据，但实际只是u8型数据

#define MAX_FILE_AREA_LIST_BIT F_file_area_in_refault_list
#define FILE_AREA_LIST_MASK ((1 << (MAX_FILE_AREA_LIST_BIT + 1)) - 1)
//清理file_area的状态，在哪个链表
#define CLEAR_FILE_AREA_LIST_STATUS(list_name) \
	static inline void clear_file_area_in_##list_name(struct file_area *p_file_area)\
    { p_file_area->file_area_state &= ~(1 << F_file_area_in_##list_name);}
//设置file_area在哪个链表的状态
#define SET_FILE_AREA_LIST_STATUS(list_name) \
	static inline void set_file_area_in_##list_name(struct file_area *p_file_area)\
    { p_file_area->file_area_state |= (1 << F_file_area_in_##list_name);}
//测试file_area在哪个链表
#define TEST_FILE_AREA_LIST_STATUS(list_name) \
	static inline int file_area_in_##list_name(struct file_area *p_file_area)\
    {return p_file_area->file_area_state & (1 << F_file_area_in_##list_name);}

#define TEST_FILE_AREA_LIST_STATUS_ERROR(list_name) \
	static inline int file_area_in_##list_name##_error(struct file_area *p_file_area)\
    {return p_file_area->file_area_state & (~(1 << F_file_area_in_##list_name) & FILE_AREA_LIST_MASK);}

#define FILE_AREA_LIST_STATUS(list_name)     \
	CLEAR_FILE_AREA_LIST_STATUS(list_name) \
	SET_FILE_AREA_LIST_STATUS(list_name)  \
	TEST_FILE_AREA_LIST_STATUS(list_name) \
	TEST_FILE_AREA_LIST_STATUS_ERROR(list_name)

FILE_AREA_LIST_STATUS(temp_list)
FILE_AREA_LIST_STATUS(hot_list)
//FILE_AREA_LIST_STATUS(free_temp_list)
FILE_AREA_LIST_STATUS(free_list)
FILE_AREA_LIST_STATUS(refault_list)

//清理file_area的状态，在哪个链表
#define CLEAR_FILE_AREA_STATUS(status) \
	static inline void clear_file_area_in_##status(struct file_area *p_file_area)\
    { p_file_area->file_area_state &= ~(1 << F_file_area_in_##status);}
//设置file_area在哪个链表的状态
#define SET_FILE_AREA_STATUS(status) \
	static inline void set_file_area_in_##status(struct file_area *p_file_area)\
    { p_file_area->file_area_state |= (1 << F_file_area_in_##status);}
//测试file_area在哪个链表
#define TEST_FILE_AREA_STATUS(status) \
	static inline int file_area_in_##status(struct file_area *p_file_area)\
    {return p_file_area->file_area_state & (1 << F_file_area_in_##status);}

#define FILE_AREA_STATUS(status)     \
	CLEAR_FILE_AREA_STATUS(status) \
	SET_FILE_AREA_STATUS(status)  \
	TEST_FILE_AREA_STATUS(status) 

FILE_AREA_STATUS(cache)


/*******file_stat状态**********************************************************/
enum file_stat_status{//file_area_state是long类型，只有64个bit位可设置
	F_file_stat_in_file_stat_hot_head_list,
	F_file_stat_in_file_stat_temp_head_list,
	F_file_stat_in_zero_file_area_list,
	F_file_stat_in_drop_cache,
	F_file_stat_in_free_page,//正在遍历file_stat的file_area的page，尝试释放page
	F_file_stat_in_free_page_done,//正在遍历file_stat的file_area的page，完成了page的内存回收,
	F_file_stat_in_delete,
	F_file_stat_in_large_file,
	F_file_stat_lock,
	F_file_stat_lock_not_block,//这个bit位置1，说明inode在删除的，但是获取file_stat锁失败
};
//不能使用 clear_bit_unlock、test_and_set_bit_lock、test_bit，因为要求p_file_stat->file_stat_status是64位数据，但这里只是u8型数据

#define MAX_FILE_STAT_LIST_BIT F_file_stat_in_free_page_done
#define FILE_STAT_LIST_MASK ((1 << (MAX_FILE_STAT_LIST_BIT + 1)) - 1)

//清理file_stat的状态，在哪个链表
#define CLEAR_FILE_STAT_STATUS(name)\
	static inline void clear_file_stat_in_##name##_list(struct file_stat *p_file_stat)\
    {p_file_stat->file_stat_status &= ~(1 << F_file_stat_in_##name##_list);}
//设置file_stat在哪个链表的状态
#define SET_FILE_STAT_STATUS(name)\
	static inline void set_file_stat_in_##name##_list(struct file_stat *p_file_stat)\
    {p_file_stat->file_stat_status |= (1 << F_file_stat_in_##name##_list);}
//测试file_stat在哪个链表
#define TEST_FILE_STAT_STATUS(name)\
	static inline int file_stat_in_##name##_list(struct file_stat *p_file_stat)\
    {return (p_file_stat->file_stat_status & (1 << F_file_stat_in_##name##_list));}
#define TEST_FILE_STAT_STATUS_ERROR(name)\
	static inline int file_stat_in_##name##_list##_error(struct file_stat *p_file_stat)\
    {return p_file_stat->file_stat_status & (~(1 << F_file_stat_in_##name##_list) & FILE_STAT_LIST_MASK);}

#define FILE_STAT_STATUS(name) \
	CLEAR_FILE_STAT_STATUS(name) \
	SET_FILE_STAT_STATUS(name) \
	TEST_FILE_STAT_STATUS(name) \
	TEST_FILE_STAT_STATUS_ERROR(name)

FILE_STAT_STATUS(file_stat_hot_head)
FILE_STAT_STATUS(file_stat_temp_head)
FILE_STAT_STATUS(zero_file_area)

//清理文件的状态，大小文件等
#define CLEAR_FILE_STATUS(name)\
    static inline void clear_file_stat_in_##name(struct file_stat *p_file_stat)\
    {p_file_stat->file_stat_status &= ~(1 << F_file_stat_in_##name);}
//设置文件的状态，大小文件等
#define SET_FILE_STATUS(name)\
    static inline void set_file_stat_in_##name(struct file_stat *p_file_stat)\
    {p_file_stat->file_stat_status |= (1 << F_file_stat_in_##name);}
//测试文件的状态，大小文件等
#define TEST_FILE_STATUS(name)\
    static inline int file_stat_in_##name(struct file_stat *p_file_stat)\
    {return (p_file_stat->file_stat_status & (1 << F_file_stat_in_##name));}
#define TEST_FILE_STATUS_ERROR(name)\
    static inline int file_stat_in_##name##_error(struct file_stat *p_file_stat)\
    {return p_file_stat->file_stat_status & (~(1 << F_file_stat_in_##name) & FILE_STAT_LIST_MASK);}

#define FILE_STATUS(name) \
	CLEAR_FILE_STATUS(name) \
	SET_FILE_STATUS(name) \
	TEST_FILE_STATUS(name)\
	TEST_FILE_STATUS_ERROR(name)

FILE_STATUS(large_file)
//FILE_STATUS(delete)
FILE_STATUS(drop_cache)

//清理文件的状态，大小文件等
#define CLEAR_FILE_STATUS_ATOMIC(name)\
    static inline void clear_file_stat_in_##name(struct file_stat *p_file_stat)\
    {clear_bit_unlock(F_file_stat_in_##name,&p_file_stat->file_stat_status);}
//设置文件的状态，大小文件等
#define SET_FILE_STATUS_ATOMIC(name)\
    static inline void set_file_stat_in_##name(struct file_stat *p_file_stat)\
    {if(test_and_set_bit_lock(F_file_stat_in_##name,&p_file_stat->file_stat_status)) \
		/*如果这个file_stat的bit位被多进程并发设置，不可能,应该发生了某种异常，触发crash*/  \
	    panic("file_stat:0x%llx status:0x%lx alreay set %d bit\n",(u64)p_file_stat,p_file_stat->file_stat_status,F_file_stat_in_##name); \
	}
//测试文件的状态，大小文件等
#define TEST_FILE_STATUS_ATOMIC(name)\
    static inline int file_stat_in_##name(struct file_stat *p_file_stat)\
    {return test_bit(F_file_stat_in_##name,&p_file_stat->file_stat_status);}
#define TEST_FILE_STATUS_ATOMIC_ERROR(name)\
    static inline int file_stat_in_##name##_error(struct file_stat *p_file_stat)\
    {return p_file_stat->file_stat_status & (~(1 << F_file_stat_in_##name) & FILE_STAT_LIST_MASK);}

#define FILE_STATUS_ATOMIC(name) \
	CLEAR_FILE_STATUS_ATOMIC(name) \
	SET_FILE_STATUS_ATOMIC(name) \
	TEST_FILE_STATUS_ATOMIC(name) \
	TEST_FILE_STATUS_ATOMIC_ERROR(name) \
/* 为什么 file_stat的in_free_page、free_page_done的状态要使用test_and_set_bit_lock/clear_bit_unlock，主要是get_file_area_from_file_stat_list()函数开始内存回收，
 * 要把file_stat设置成in_free_page状态，此时hot_file_update_file_status()里就不能再把这些file_stat的file_area跨链表移动。而把file_stat设置成
 * in_free_page状态，只是加了global global_lock锁，没有加file_stat->file_stat_lock锁。没有加锁file_stat->file_stat_lock锁，就无法避免
 * hot_file_update_file_status()把把这些file_stat的file_area跨链表移动。因此，file_stat的in_free_page、free_page_done的状态设置要考虑原子操作吧，
 * 并且此时要避免此时有进程在执行hot_file_update_file_status()函数。这些在hot_file_update_file_status()和get_file_area_from_file_stat_list()函数
 * 有说明其实file_stat设置in_free_page、free_page_done 状态都有spin lock加锁，不使用test_and_set_bit_lock、clear_bit_unlock也行，
 * 目前暂定先用test_and_set_bit_lock、clear_bit_unlock吧，后续再考虑其他优化*/
FILE_STATUS_ATOMIC(free_page)
FILE_STATUS_ATOMIC(free_page_done)
FILE_STATUS_ATOMIC(delete)


/*因为buffer io write的page不会调用到mark_page_accessed()，因此考虑kprobe pagecache_get_page。但是分析generic_file_buffered_read()源码，有概率
 * goto no_cached_page分支，导致本次读的文件页不会调用到find_get_page()->pagecache_get_page()。考虑再三把kprobe的函数换成buffer io read/write 
 * 会执行到拷贝用户空间数据的两个函数*/
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
/*static struct kprobe kp_mark_page_accessed = {
	.symbol_name    = "mark_page_accessed",
};*/
static struct kprobe kp_read_cache_func = {
	.symbol_name    = "iov_iter_copy_from_user_atomic",//buffer io write把数据写入文件页page执行到
};
static struct kprobe kp_write_cache_func = {
	.symbol_name    = "copy_page_to_iter",//buffer io read读取文件页page数据执行到
};
#else
/*static struct kprobe kp_mark_page_accessed = {
	.symbol_name    = "folio_mark_accessed",
};*/
static struct kprobe kp_read_cache_func = {
	.symbol_name    = "copy_page_from_iter_atomic",//buffer io write把数据写入文件页page执行到
};
static struct kprobe kp_write_cache_func = {
	.symbol_name    = "copy_page_to_iter",//buffer io read读取文件页page数据执行到 copy_folio_to_iter()
};
#endif
static struct kprobe kp__destroy_inode = {
	.symbol_name    = "__destroy_inode",
};

static struct kprobe kp_kallsyms_lookup_name = {
	.symbol_name    = "kallsyms_lookup_name",
};
static void kallsyms_lookup_name_handler_post(struct kprobe *p, struct pt_regs *regs,
		unsigned long flags)
{
}

struct hot_cold_file_global hot_cold_file_global_info;
//置1会把内存回收信息详细打印出来
static int shrink_page_printk_open1 = 0;
//不怎么关键的调试信息
static int shrink_page_printk_open = 0;
static unsigned long async_memory_reclaim_status = 1;

static int hot_cold_file_init(void);
static int hot_cold_file_print_all_file_stat(struct hot_cold_file_global *p_hot_cold_file_global,struct seq_file *m,int is_proc_print);
static void printk_shrink_param(struct hot_cold_file_global *p_hot_cold_file_global,struct seq_file *m,int is_proc_print);
static void iterate_supers_async(void);
static void inline cold_file_stat_delete(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat_del);

static inline void lock_file_stat(struct file_stat * p_file_stat,int not_block){
	//如果有其他进程对file_stat的lock加锁，while成立，则休眠等待这个进程释放掉lock，然后自己加锁
	while(test_and_set_bit_lock(F_file_stat_lock, &p_file_stat->file_stat_status)){
		if(not_block){//if成立说明inode在删除的，但是获取file_stat锁失败，此时正获取file_stat锁的进程要立即释放掉file_stat锁
		    if(test_and_set_bit_lock(F_file_stat_lock_not_block,&p_file_stat->file_stat_status)){
				//F_file_stat_lock_not_block这个bit位可能被多进程并发设置，如果已经被设置了，先不考虑触发crash
		        //panic("file_stat:0x%llx status:0x%x alreay set stat_lock_not_block\n",(u64)p_file_stat,p_file_stat->file_stat_status);
			}
			not_block = 0;
		}
		/*其实好点是每个file_stat都有休眠等待队列，进程获取file_stat失败则再休眠等待队列休眠，而不是直接msleep，后期改进吧?????*/
		msleep(1);
		//dump_stack();
	}
}
static inline void unlock_file_stat(struct file_stat * p_file_stat){
	//如果file_stat被设置了not_block标记，则要先清理掉
	test_and_clear_bit(F_file_stat_lock_not_block,&p_file_stat->file_stat_status);
	clear_bit_unlock(F_file_stat_lock, &p_file_stat->file_stat_status);
}

/*************以下代码不同内核版本有差异******************************************************************************************/

/*******以下是红帽8.3 4.18.0-240内核针对内核原生内存回收函数在本ko驱动的适配********************************************/
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
struct scan_control_async {
	unsigned long nr_to_reclaim;
	gfp_t gfp_mask;
	int order;
	nodemask_t	*nodemask;
	struct mem_cgroup *target_mem_cgroup;
	int priority;
	enum zone_type reclaim_idx;
	unsigned int may_writepage:1;
	unsigned int may_unmap:1;
	unsigned int may_swap:1;
	unsigned int memcg_low_reclaim:1;
	unsigned int memcg_low_skipped:1;
	unsigned int hibernation_mode:1;
	unsigned int compaction_ready:1;
	unsigned long nr_scanned;
	unsigned long nr_reclaimed;
	struct {
		unsigned int dirty;
		unsigned int unqueued_dirty;
		unsigned int congested;
		unsigned int writeback;
		unsigned int immediate;
		unsigned int file_taken;
		unsigned int taken;
	} nr;
};

static int (*__isolate_lru_page_async)(struct page *page, isolate_mode_t mode);
static int (*page_evictable_async)(struct page *page);
static int (*__remove_mapping_async)(struct address_space *mapping, struct page *page,bool reclaimed);
static void (*mem_cgroup_update_lru_size_async)(struct lruvec *lruvec, enum lru_list lru,int zid, int nr_pages);
static struct lruvec *(*mem_cgroup_page_lruvec_async)(struct page *page, struct pglist_data *pgdat);
static void (*__mod_lruvec_state_async)(struct lruvec *lruvec, enum node_stat_item idx,int val);
static void (*free_unref_page_list_async)(struct list_head *list);
static void (*mem_cgroup_uncharge_list_async)(struct list_head *page_list);
static void (*__count_memcg_events_async)(struct mem_cgroup *memcg, enum vm_event_item idx,unsigned long count);

static unsigned long (*kallsyms_lookup_name_async)(const char *name);
static void (*try_to_unmap_flush_async)(void);
static struct mem_cgroup *root_mem_cgroup_async;
static void (*putback_lru_page_async)(struct page *page);
static void (*mem_cgroup_uncharge_async)(struct page *page);
compound_page_dtor * (*compound_page_dtors_async)[NR_COMPOUND_DTORS];

static spinlock_t *sb_lock_async;
static struct list_head *super_blocks_async;
static void (*security_sb_free_async)(struct super_block *sb);
static void (*destroy_super_rcu_async)(struct rcu_head *head);
static inline compound_page_dtor *get_compound_page_dtor_async(struct page *page)
{
	VM_BUG_ON_PAGE(page[1].compound_dtor >= NR_COMPOUND_DTORS, page);
	//compound_page_dtors_async[page[1].compound_dtor]  就是编译通不过，为啥，现在这样才通过
	return (*compound_page_dtors_async)[page[1].compound_dtor];
}
//源码跟内核count_memcg_events()一样，只是改了名字
//static inline void count_memcg_events(struct mem_cgroup *memcg,
static inline void count_memcg_events_async(struct mem_cgroup *memcg,
		enum vm_event_item idx,
		unsigned long count)
{
	unsigned long flags;

	local_irq_save(flags);
	//源码跟内核__count_memcg_events()一样，只是改了名字
	__count_memcg_events_async(memcg, idx, count);
	local_irq_restore(flags);
}
//源码跟内核count_memcg_page_event()一样，只是改了名字
static inline void count_memcg_page_event_async(struct page *page,
		enum vm_event_item idx)
{
	if (page->mem_cgroup)
		count_memcg_events_async(page->mem_cgroup, idx, 1);
}
static __always_inline void __update_lru_size_async(struct lruvec *lruvec,
		enum lru_list lru, enum zone_type zid,
		int nr_pages)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	__mod_lruvec_state_async(lruvec, NR_LRU_BASE + lru, nr_pages);
	__mod_zone_page_state(&pgdat->node_zones[zid],
			NR_ZONE_LRU_BASE + lru, nr_pages);
}
static __always_inline void update_lru_size_async(struct lruvec *lruvec,
		enum lru_list lru, enum zone_type zid,
		int nr_pages)
{
	__update_lru_size_async(lruvec, lru, zid, nr_pages);
#ifdef CONFIG_MEMCG
	mem_cgroup_update_lru_size_async(lruvec, lru, zid, nr_pages);
#endif
}
static __always_inline void del_page_from_lru_list_async(struct page *page,
		struct lruvec *lruvec, enum lru_list lru)
{
	list_del(&page->lru);
	update_lru_size_async(lruvec, lru, page_zonenum(page), -hpage_nr_pages(page));
}
static __always_inline void add_page_to_lru_list_async(struct page *page,
		struct lruvec *lruvec, enum lru_list lru)
{
	update_lru_size_async(lruvec, lru, page_zonenum(page), hpage_nr_pages(page));
	list_add(&page->lru, &lruvec->lists[lru]);
}
//源码来自内核shrink_page_list()，但是针对pagecache内存回收简化很多,执行该函数回收内存的page大部分都是长时间未访问的clean pagecache
static unsigned int async_shrink_free_page(struct pglist_data *pgdat,struct lruvec *lruvec,struct list_head *page_list,
		struct scan_control_async *sc,struct reclaim_stat *stat)
{
	LIST_HEAD(ret_pages);
	LIST_HEAD(free_pages);
	int pgactivate = 0;

	unsigned nr_unqueued_dirty = 0;
	unsigned nr_dirty = 0;
	unsigned nr_congested = 0;
	unsigned nr_reclaimed = 0;
	unsigned nr_writeback = 0;
	unsigned nr_immediate = 0;
	unsigned nr_ref_keep = 0;
	unsigned nr_unmap_fail = 0;

	unsigned int lock_fail_count = 0;
	unsigned int writeback_count = 0;
	unsigned int dirty_count = 0;
	unsigned int page_has_private_count = 0;
	unsigned int mapping_count = 0;
	unsigned int free_pages_fail_count = 0;

	while (!list_empty(page_list)) {
		struct address_space *mapping;
		struct page *page;
		int may_enter_fs;

		cond_resched();

		page = lru_to_page(page_list);
		list_del(&page->lru);

		if (!trylock_page(page)){
			lock_fail_count ++;
			goto keep;
		}
		mapping = page_mapping(page);
		may_enter_fs = (sc->gfp_mask & __GFP_FS);

		/****page是witeback页*********************/
		if (PageWriteback(page)) {
			writeback_count ++;

			if(!PageReclaim(page)){
				SetPageReclaim(page);
				nr_writeback += 1;
			}else if (PageReclaim(page) &&test_bit(PGDAT_WRITEBACK, &pgdat->flags)){
				nr_immediate += 1;
			}
		}

		/****page是脏页*********************/
		if (PageDirty(page)) {
			dirty_count ++;

			nr_dirty++;
			goto activate_locked;	       
			//这里goto keep 分支，忘了unlock_page()了，导致其他进程访问到该page时因为page lock就休眠了
			//goto keep;
		}

		/*******释放page的bh******************/
		if (page_has_private(page)) {
			page_has_private_count ++;

			if (!try_to_release_page(page,sc->gfp_mask)){
				goto activate_locked;
			}
			if (!mapping && page_count(page) == 1) {
				unlock_page(page);
				if (put_page_testzero(page)){
					goto free_it;
				}
				else {
					nr_reclaimed++;
					continue;
				}
			}
		}
		/********把page从radix tree剔除************************/
		if (!mapping || !__remove_mapping_async(mapping, page, true)){
			mapping_count ++;

			goto keep_locked;
		}


		unlock_page(page);
free_it:
		nr_reclaimed++;
		//如果要释放的page引用计数不是0，那就有问题了，主动触发crash
		if(atomic_read(&page->_refcount) != 0){
			panic("page:0x%llx refcount:%d error!!!!!\n",(u64)page,atomic_read(&page->_refcount));
		}
		list_add(&page->lru, &free_pages);
		continue;
activate_locked:
		if (!PageMlocked(page)) {
			SetPageActive(page);
			pgactivate++;
			/*page要添加到active lru链表，这里增加对应的memory cgroup中在active lru链表的page统计数-------------*/
			//count_memcg_page_event(page, PGACTIVATE);
			count_memcg_page_event_async(page, PGACTIVATE);
		}
keep_locked:
		unlock_page(page);
keep:
		list_add(&page->lru, &ret_pages);
		free_pages_fail_count ++;
	}
	mem_cgroup_uncharge_list_async(&free_pages);
	try_to_unmap_flush_async();

	free_unref_page_list_async(&free_pages);

	/*共有pgactivate个page要添加到active lru链表，这里增加全局的在active lru链表的page统计数---------------*/
	list_splice(&ret_pages, page_list);
	count_vm_events(PGACTIVATE, pgactivate);

	if (stat) {
		stat->nr_dirty = nr_dirty;
		stat->nr_congested = nr_congested;
		stat->nr_unqueued_dirty = nr_unqueued_dirty;
		stat->nr_writeback = nr_writeback;
		stat->nr_immediate = nr_immediate;
		stat->nr_activate = pgactivate;
		stat->nr_ref_keep = nr_ref_keep;
		stat->nr_unmap_fail = nr_unmap_fail;
	}
	hot_cold_file_global_info.hot_cold_file_shrink_counter.lock_fail_count += lock_fail_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.lock_fail_count += lock_fail_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.writeback_count += writeback_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.dirty_count += dirty_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.page_has_private_count += page_has_private_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.mapping_count += mapping_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_count += nr_reclaimed;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_fail_count += free_pages_fail_count;

	return nr_reclaimed;
}
static int __hot_cold_file_isolate_lru_pages(pg_data_t *pgdat,struct page * page,struct list_head *dst,isolate_mode_t mode)
{
	struct lruvec *lruvec;
	int lru;

	lruvec = mem_cgroup_lruvec(page->mem_cgroup, pgdat);
	lru = page_lru_base_type(page);

	/*__isolate_lru_page里清除page的PageLRU属性，因为要把page从lru链表剔除了，并且令page的引用计数加1*/
	//switch (__isolate_lru_page(page, mode)) {
	switch (__isolate_lru_page_async(page, mode)) {
		case 0:
			//把page从lru链表剔除，并减少page所属lru链表的page数
			//del_page_from_lru_list(page, lruvec, lru + PageActive(page));
			del_page_from_lru_list_async(page, lruvec, lru + PageActive(page));
			//如果page在active lru链表上则要清理掉Active属性，因为内存回收的page一定是处于inactive lru链表，否则内存回收最后会因为page有PageActive属性而触发crash
			if(PageActive(page))
				ClearPageActive(page);
			//再把page添加到dst临时链表
			list_add(&page->lru,dst);
			return 0;

		case -EBUSY:
			if(shrink_page_printk_open1)
				printk("2:%s %s %d page:0x%llx page->flags:0x%lx EBUSY\n",__func__,current->comm,current->pid,(u64)page,page->flags);
			break;

		default:
			//实际测试发现，这个会成立，这个正常，因为该page可能被内核原生内存回收隔离成功，就没有了lru属性。但是这里不再触发bug，仅仅一个告警打印
			if(shrink_page_printk_open1)
				printk("3:%s %s %d page:0x%llx PageUnevictable:%d PageLRU:%d !!!!!!!!!!!!!\n",__func__,current->comm,current->pid,(u64)page,PageUnevictable(page),PageLRU(page));
#if 0
			BUG();
#endif
	}

	return -1;
}
//static void putback_inactive_pages(struct lruvec *lruvec, struct list_head *page_list)
static unsigned int hot_cold_file_putback_inactive_pages(struct pglist_data *pgdat, struct list_head *page_list)
{
	//struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	unsigned int move = 0;
	LIST_HEAD(pages_to_free);
	struct lruvec *lruvec;

	spin_lock(&pgdat->lru_lock);
	/*
	 * Put back any unfreeable pages.
	 */
	while (!list_empty(page_list)) {
		struct page *page = lru_to_page(page_list);
		int lru;

		if(shrink_page_printk_open1)
			printk("1:%s %s %d page:0x%llx page->flags:0x%lx\n",__func__,current->comm,current->pid,(u64)page,page->flags);

		VM_BUG_ON_PAGE(PageLRU(page), page);
		list_del(&page->lru);
		if (unlikely(!page_evictable_async(page))) {
			spin_unlock(&pgdat->lru_lock);
			putback_lru_page_async(page);
			spin_lock(&pgdat->lru_lock);
			continue;
		}
		/*怎么保证这些内存释放失败的page添加会原有的lru链表呢？page->mem_cgroup 是page锁绑定的memcg，再有memcg找到它的lruvec，完美*/
		lruvec = mem_cgroup_page_lruvec_async(page, pgdat);

		SetPageLRU(page);
		lru = page_lru(page);
		//add_page_to_lru_list(page, lruvec, lru);
		add_page_to_lru_list_async(page, lruvec, lru);
		move ++;
		/*if (is_active_lru(lru)) { 这段代码不需要，不用统计
		  int file = is_file_lru(lru);
		  int numpages = hpage_nr_pages(page);
		  reclaim_stat->recent_rotated[file] += numpages;
		  }*/
		if (put_page_testzero(page)) {
			if(shrink_page_printk_open1)
				printk("2:%s %s %d put_page_testzero page:0x%llx page->flags:0x%lx PageCompound:%d\n",__func__,current->comm,current->pid,(u64)page,page->flags,PageCompound(page));
			__ClearPageLRU(page);
			__ClearPageActive(page);
			//里边调用了__mod_lruvec_state、mem_cgroup_update_lru_size函数，导致“undefined!”
			//del_page_from_lru_list(page, lruvec, lru);
			del_page_from_lru_list_async(page, lruvec, lru);

			if (unlikely(PageCompound(page))) {
				spin_unlock(&pgdat->lru_lock);
				mem_cgroup_uncharge_async(page);
				(*get_compound_page_dtor_async(page))(page);
				spin_lock(&pgdat->lru_lock);
			} else
				list_add(&page->lru, &pages_to_free);
		}
	}
	spin_unlock(&pgdat->lru_lock);
	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	list_splice(&pages_to_free, page_list);
	return move;
}

/*******以下是红帽9.2 5.14.0-284.11.1内核针对内核原生内存回收函数在本ko驱动的适配********************************************/
#elif LINUX_VERSION_CODE == KERNEL_VERSION(5,14,0)
struct scan_control_async {
	unsigned long nr_to_reclaim;
	nodemask_t	*nodemask;
	struct mem_cgroup *target_mem_cgroup;
	unsigned long	anon_cost;
	unsigned long	file_cost;
#define DEACTIVATE_ANON 1
#define DEACTIVATE_FILE 2
	unsigned int may_deactivate:2;
	unsigned int force_deactivate:1;
	unsigned int skipped_deactivate:1;
	/* Writepage batching in laptop mode; RECLAIM_WRITE */
	unsigned int may_writepage:1;
	/* Can mapped pages be reclaimed? */
	unsigned int may_unmap:1;
	/* Can pages be swapped as part of reclaim? */
	unsigned int may_swap:1;
	unsigned int memcg_low_reclaim:1;
	unsigned int memcg_low_skipped:1;
	unsigned int hibernation_mode:1;
	/* One of the zones is ready for compaction */
	unsigned int compaction_ready:1;
	/* There is easily reclaimable cold cache in the current node */
	unsigned int cache_trim_mode:1;
	/* The file pages on the current node are dangerously low */
	unsigned int file_is_tiny:1;
	/* Always discard instead of demoting to lower tier memory */
	unsigned int no_demotion:1;
	/* Allocation order */
	s8 order;
	/* Scan (total_size >> priority) pages at once */
	s8 priority;
	/* The highest zone to isolate pages for reclaim from */
	s8 reclaim_idx;
	/* This context's GFP mask */
	gfp_t gfp_mask;
	/* Incremented by the number of inactive pages that were scanned */
	unsigned long nr_scanned;
	/* Number of pages freed so far during a call to shrink_zones() */
	unsigned long nr_reclaimed;
	struct {
		unsigned int dirty;
		unsigned int unqueued_dirty;
		unsigned int congested;
		unsigned int writeback;
		unsigned int immediate;
		unsigned int file_taken;
		unsigned int taken;
	} nr;
	/* for recording the reclaimed slab by now */
	struct reclaim_state reclaim_state;
};

static int(* __remove_mapping_async)(struct address_space *mapping, struct folio *folio,bool reclaimed, struct mem_cgroup *target_memcg);
static void (*mem_cgroup_update_lru_size_async)(struct lruvec *lruvec, enum lru_list lru,int zid, int nr_pages);
static void (*free_unref_page_list_async)(struct list_head *list);
static void (*__mem_cgroup_uncharge_list_async)(struct list_head *page_list);
static void (*__count_memcg_events_async)(struct mem_cgroup *memcg, enum vm_event_item idx,unsigned long count);

static unsigned long (*kallsyms_lookup_name_async)(const char *name);
static void (*putback_lru_page_async)(struct page *page);
static struct mem_cgroup *root_mem_cgroup_async;
static void (*try_to_unmap_flush_async)(void);
static void (*__mod_memcg_lruvec_state_async)(struct lruvec *lruvec, enum node_stat_item idx,int val);
static  bool (*mem_cgroup_disabled_async)(void);
extern void __mod_lruvec_page_state(struct page *page, enum node_stat_item idx,int val);

compound_page_dtor * const (*compound_page_dtors_async)[NR_COMPOUND_DTORS];
static spinlock_t *sb_lock_async;
static struct list_head *super_blocks_async;
static void (*security_sb_free_async)(struct super_block *sb);
static void (*destroy_super_rcu_async)(struct rcu_head *head);
static void (*cache_random_seq_destroy_async)(struct kmem_cache *cachep);

/* Check if a page is dirty or under writeback */
inline static void folio_check_dirty_writeback_async(struct folio *folio,
		bool *dirty, bool *writeback)
{
	struct address_space *mapping;

	/*
	 * Anonymous pages are not handled by flushers and must be written
	 * from reclaim context. Do not stall reclaim based on them
	 */
	if (!folio_is_file_lru(folio) ||
			(folio_test_anon(folio) && !folio_test_swapbacked(folio))) {
		*dirty = false;
		*writeback = false;
		return;
	}

	/* By default assume that the folio flags are accurate */
	*dirty = folio_test_dirty(folio);
	*writeback = folio_test_writeback(folio);

	/* Verify dirty/writeback state if the filesystem supports it */
	if (!folio_test_private(folio))
		return;

	mapping = folio_mapping(folio);
	if (mapping && mapping->a_ops->is_dirty_writeback)
		mapping->a_ops->is_dirty_writeback(&folio->page, dirty, writeback);
}
static inline void destroy_compound_page_async(struct page *page)
{
	VM_BUG_ON_PAGE(page[1].compound_dtor >= NR_COMPOUND_DTORS, page);
	//编译通过了，但是这种通过函数指针数组引用函数指针的格式合法吗????????????????
	(*compound_page_dtors_async[page[1].compound_dtor])(page);
}
static inline void mem_cgroup_uncharge_list_async(struct list_head *page_list)
{
	/*绝了，mem_cgroup_disabled()源码里是inline类型，但cat /proc/kallsyms 却可以看到mem_cgroup_disabled()。并且可以直接在ko里用
	 * 看着mem_cgroup_disabled()函数就是export的非inline类型函数，服了，有这结果估计是编译搞的?????*/
	if (mem_cgroup_disabled_async())
		return;
	__mem_cgroup_uncharge_list_async(page_list);
}
static inline void count_memcg_events_async(struct mem_cgroup *memcg,
		enum vm_event_item idx,
		unsigned long count)
{
	unsigned long flags;
	local_irq_save(flags);
	__count_memcg_events_async(memcg, idx, count);
	local_irq_restore(flags);
}
static inline void count_memcg_page_event_async(struct page *page,
		enum vm_event_item idx)
{
	struct mem_cgroup *memcg = page_memcg(page);
	if (memcg)
		count_memcg_events_async(memcg, idx, 1);
}
static void __mod_lruvec_state_async(struct lruvec *lruvec, enum node_stat_item idx,
		int val)
{
	/* Update node */
	__mod_node_page_state(lruvec_pgdat(lruvec), idx, val);
	if (!mem_cgroup_disabled_async())
		__mod_memcg_lruvec_state_async(lruvec, idx, val);
}    
static __always_inline void update_lru_size_async(struct lruvec *lruvec,
		enum lru_list lru, enum zone_type zid,
		long nr_pages)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	__mod_lruvec_state_async(lruvec, NR_LRU_BASE + lru, nr_pages);
	__mod_zone_page_state(&pgdat->node_zones[zid],
			NR_ZONE_LRU_BASE + lru, nr_pages);
#ifdef CONFIG_MEMCG
	mem_cgroup_update_lru_size_async(lruvec, lru, zid, nr_pages);
#endif
}
static __always_inline void lruvec_add_folio_async(struct lruvec *lruvec, struct folio *folio)
{
	enum lru_list lru = folio_lru_list(folio);

	update_lru_size_async(lruvec, lru, folio_zonenum(folio),
			folio_nr_pages(folio));
	if (lru != LRU_UNEVICTABLE)
		list_add(&folio->lru, &lruvec->lists[lru]);
}
static __always_inline void add_page_to_lru_list_async(struct page *page,
		struct lruvec *lruvec)
{
	lruvec_add_folio_async(lruvec, page_folio(page));
}
static __always_inline void lruvec_del_folio_async(struct lruvec *lruvec, struct folio *folio)
{
	enum lru_list lru = folio_lru_list(folio);

	if (lru != LRU_UNEVICTABLE)
		list_del(&folio->lru);
	update_lru_size_async(lruvec, lru, folio_zonenum(folio),
			-folio_nr_pages(folio));
}
static __always_inline void del_page_from_lru_list_async(struct page *page,
		struct lruvec *lruvec)
{
	lruvec_del_folio_async(lruvec, page_folio(page));
}
static inline struct lruvec *mem_cgroup_lruvec_async(struct mem_cgroup *memcg,
		struct pglist_data *pgdat)
{
	struct mem_cgroup_per_node *mz;
	struct lruvec *lruvec;

	if (mem_cgroup_disabled_async()) {
		lruvec = &pgdat->__lruvec;
		goto out;
	}

	if (!memcg)
		memcg = root_mem_cgroup_async;

	mz = memcg->nodeinfo[pgdat->node_id];
	lruvec = &mz->lruvec;
out:
	/*
	 * Since a node can be onlined after the mem_cgroup was created,
	 * we have to be prepared to initialize lruvec->pgdat here;
	 * and if offlined then reonlined, we need to reinitialize it.
	 */
	if (unlikely(lruvec->pgdat != pgdat))
		lruvec->pgdat = pgdat;
	return lruvec;
}
static inline bool page_evictable_async(struct page *page)
{
	bool ret;
	rcu_read_lock();
	ret = !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
	rcu_read_unlock();
	return ret;
}
static unsigned int async_shrink_free_page(struct pglist_data *pgdat,struct lruvec *lruvec,struct list_head *page_list,
		struct scan_control_async *sc,struct reclaim_stat *stat)
{
	LIST_HEAD(ret_pages);
	LIST_HEAD(free_pages);
#if 0
	LIST_HEAD(demote_pages);
	bool do_demote_pass;
#endif
	unsigned int nr_reclaimed = 0;
	unsigned int pgactivate = 0;

	unsigned int lock_fail_count = 0;
	unsigned int writeback_count = 0;
	unsigned int dirty_count = 0;
	unsigned int page_has_private_count = 0;
	unsigned int mapping_count = 0;
	unsigned int free_pages_fail_count = 0;
	unsigned int page_unevictable_count = 0;

	memset(stat, 0, sizeof(*stat));
	cond_resched();
#if 0
	//该场景根本用不到，注释掉得了。这里的sc是从vmscan.c直接复制过来的scan_control_async，必须要与内核的scan_control结构定义一模一样
	do_demote_pass = can_demote_async(pgdat->node_id, sc);
retry:
#endif
	while (!list_empty(page_list)) {
		struct address_space *mapping;
		struct page *page;
		struct folio *folio;
		//enum page_references references = PAGEREF_RECLAIM;
		bool dirty, writeback, may_enter_fs;
		unsigned int nr_pages;

		cond_resched();
		//注意，这里从page_list链表首先取出的是folio
		folio = lru_to_folio(page_list);
		list_del(&folio->lru);
		//通过folio得到page
		page = &folio->page;

		if (!trylock_page(page)){
			lock_fail_count ++;

			goto keep;
		}
		//这个判断要注释掉，异步内存回收的page可能处于active lru链表
		//VM_BUG_ON_PAGE(PageActive(page), page);

		nr_pages = compound_nr(page);

		/* Account the number of base pages even though THP */
		sc->nr_scanned += nr_pages;

		if (unlikely(!page_evictable_async(page))){
			page_unevictable_count ++;
			goto activate_locked;
		}
		//强制不回收mmap的page
		if (/*!sc->may_unmap &&*/ page_mapped(page))
			goto keep_locked;

		may_enter_fs = (sc->gfp_mask & __GFP_FS) ||
			(PageSwapCache(page) && (sc->gfp_mask & __GFP_IO));

		/*
		 * The number of dirty pages determines if a node is marked
		 * reclaim_congested. kswapd will stall and start writing
		 * pages if the tail of the LRU is all dirty unqueued pages.
		 */
		folio_check_dirty_writeback_async(folio, &dirty, &writeback);
		if (dirty || writeback)
			stat->nr_dirty += nr_pages;

		if (dirty && !writeback)
			stat->nr_unqueued_dirty += nr_pages;

		/*
		 * Treat this page as congested if the underlying BDI is or if
		 * pages are cycling through the LRU so quickly that the
		 * pages marked for immediate reclaim are making it to the
		 * end of the LRU a second time.
		 */
		mapping = page_mapping(page);
		if (writeback && PageReclaim(page))
			stat->nr_congested += nr_pages;

		//遇到writebak页，不做任何处理，等脏页回写进程把它落盘。然后等几分钟后变成冷page，就会被异步回收掉。我的回收策略是只回收长时间不被冷page，这种page刚被访问过
		if (PageWriteback(page)) {
			writeback_count ++;

			if(PageReclaim(page)){
				SetPageReclaim(page);
				stat->nr_writeback += nr_pages;
			}else if (PageReclaim(page) &&test_bit(PGDAT_WRITEBACK, &pgdat->flags)){
				stat->nr_immediate += nr_pages;
			}

			goto activate_locked; 
		}

		/*
		 * Before reclaiming the page, try to relocate
		 * its contents to another node.
		 */
#if 0
		if (do_demote_pass &&
				(thp_migration_supported() || !PageTransHuge(page))) {
			list_add(&page->lru, &demote_pages);
			unlock_page(page);
			continue;
		}
#endif
		/*****这段代码是新内核加的?????????????*******************************/
		/*
		 * THP may get split above, need minus tail pages and update
		 * nr_pages to avoid accounting tail pages twice.
		 *
		 * The tail pages that are added into swap cache successfully
		 * reach here.
		 */
		if ((nr_pages > 1) && !PageTransHuge(page)) {
			sc->nr_scanned -= (nr_pages - 1);
			nr_pages = 1;
		}
		//遇到脏页，不做任何处理，等脏页回写进程把它落盘。然后等几分钟后变成冷page，就会被异步回收掉。我的回收策略是只回收长时间不被冷page，这种page刚被访问过
		if (PageDirty(page)) {
			dirty_count ++;

			goto activate_locked;
			//这里goto keep 分支，忘了unlock_page()了，导致其他进程访问到该page时因为page lock就休眠了!!!!!!!!!!!!!!!!
			//goto keep;
		}

		if (page_has_private(page)) {
			page_has_private_count ++;

			if (!try_to_release_page(page, sc->gfp_mask)){
				goto activate_locked;
			}
			if (!mapping && page_count(page) == 1) {
				unlock_page(page);
				if (put_page_testzero(page))
					goto free_it;
				else {
					/*
					 * rare race with speculative reference.
					 * the speculative reference will free
					 * this page shortly, so we may
					 * increment nr_reclaimed here (and
					 * leave it off the LRU).
					 */
					nr_reclaimed++;
					continue;
				}
			}
		}

		if (!mapping || !__remove_mapping_async(mapping, folio, true,
					folio_memcg(folio)))
		{
			mapping_count ++;

			goto keep_locked;
		}
		unlock_page(page);
free_it:
		//如果要释放的page引用计数不是0，那就有问题了，主动触发crash
		if(atomic_read(&page->_refcount) != 0){
			panic("page:0x%llx refcount:%d error!!!!!\n",(u64)page,atomic_read(&page->_refcount));
		}
		/*
		 * THP may get swapped out in a whole, need account
		 * all base pages.
		 */
		nr_reclaimed += nr_pages;

		/*
		 * Is there need to periodically free_page_list? It would
		 * appear not as the counts should be low
		 */
		if (unlikely(PageTransHuge(page)))
			destroy_compound_page_async(page);
		else
			list_add(&page->lru, &free_pages);
		continue;
#if 0
activate_locked_split:
#endif
		/*
		 * The tail pages that are failed to add into swap cache
		 * reach here.  Fixup nr_scanned and nr_pages.
		 */
		if (nr_pages > 1) {
			sc->nr_scanned -= (nr_pages - 1);
			nr_pages = 1;
		}
activate_locked:
		/* Not a candidate for swapping, so reclaim swap space. */
		/*if (PageSwapCache(page) && (mem_cgroup_swap_full(page) ||
		  PageMlocked(page)))
		  try_to_free_swap(page);
		  */
		VM_BUG_ON_PAGE(PageActive(page), page);

		if (!PageMlocked(page)) {
			int type = page_is_file_lru(page);
			SetPageActive(page);
			stat->nr_activate[type] += nr_pages;
			count_memcg_page_event_async(page, PGACTIVATE);
		}
keep_locked:
		unlock_page(page);
keep:
		list_add(&page->lru, &ret_pages);
		VM_BUG_ON_PAGE(PageLRU(page) || PageUnevictable(page), page);
		free_pages_fail_count ++;
	}
	/* 'page_list' is always empty here */
#if 0 
	/* Migrate pages selected for demotion */
	nr_reclaimed += demote_page_list(&demote_pages, pgdat);
	/* Pages that could not be demoted are still in @demote_pages */
	if (!list_empty(&demote_pages)) {
		printk("%s %s %d demote_pages:0x%llx\n",__func__,current->comm,current->pid,(u64)&demote_pages);
		/* Pages which failed to demoted go back on @page_list for retry: */
		list_splice_init(&demote_pages, page_list);
		do_demote_pass = false;
		goto retry;
	}
#endif
	pgactivate = stat->nr_activate[0] + stat->nr_activate[1];

	mem_cgroup_uncharge_list_async(&free_pages);
	try_to_unmap_flush_async();
	free_unref_page_list_async(&free_pages);

	list_splice(&ret_pages, page_list);
	count_vm_events(PGACTIVATE, pgactivate);

	hot_cold_file_global_info.hot_cold_file_shrink_counter.lock_fail_count += lock_fail_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.lock_fail_count += lock_fail_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.writeback_count += writeback_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.dirty_count += dirty_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.page_has_private_count += page_has_private_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.mapping_count += mapping_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_count += nr_reclaimed;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_fail_count += free_pages_fail_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.page_unevictable_count += page_unevictable_count;

	return nr_reclaimed;
}
static unsigned int hot_cold_file_putback_inactive_pages(struct pglist_data *pgdat, struct list_head *page_list)
{
	int nr_pages, nr_moved = 0;
	LIST_HEAD(pages_to_free);
	struct page *page;
	struct lruvec *lruvec = NULL,*lruvec_new;

	while (!list_empty(page_list)) {
		page = lru_to_page(page_list);

		lruvec_new = mem_cgroup_lruvec_async(page_memcg(page),pgdat);
		if(unlikely(lruvec != lruvec_new)){
			if(lruvec){
				spin_unlock(&lruvec->lru_lock);
			}
			lruvec = lruvec_new;
			//对新的page所属的pgdat进行spin lock
			spin_lock(&lruvec->lru_lock);
		}

		VM_BUG_ON_PAGE(PageLRU(page), page);
		list_del(&page->lru);
		if (unlikely(!page_evictable_async(page))) {
			spin_unlock(&lruvec->lru_lock);
			putback_lru_page_async(page);
			spin_lock(&lruvec->lru_lock);
			continue;
		}
		SetPageLRU(page);

		if (unlikely(put_page_testzero(page))) {
			__clear_page_lru_flags(page);

			if (unlikely(PageCompound(page))) {
				spin_unlock(&lruvec->lru_lock);
				destroy_compound_page_async(page);
				spin_lock(&lruvec->lru_lock);
			} else
				list_add(&page->lru, &pages_to_free);

			continue;
		}

		/*
		 * All pages were isolated from the same lruvec (and isolation
		 * inhibits memcg migration).
		 */
		VM_BUG_ON_PAGE(!folio_matches_lruvec(page_folio(page), lruvec), page);
		add_page_to_lru_list_async(page, lruvec);
		nr_pages = thp_nr_pages(page);
		nr_moved += nr_pages;
#if 0//异步内存回收先不影响page age，这段代码需要注释掉
		if (PageActive(page))
			workingset_age_nonresident(lruvec, nr_pages);
#endif
	}
	if(lruvec)
		spin_unlock(&lruvec->lru_lock);
	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	list_splice(&pages_to_free, page_list);

	return nr_moved;
}
static int  __hot_cold_file_isolate_lru_pages(pg_data_t *pgdat,struct page * page,struct list_head *dst,isolate_mode_t mode)
{
	struct lruvec *lruvec;
	//int lru;

	//prefetchw_prev_lru_page(page, src, flags); 不需要

	if (!PageLRU(page))
		return -1;
	//源头已经确保page不是mmap的，这里不用重复判断。但是想想还是加上吧，因为怕page中途被设置成mmap了。
#if 1
	if (/*!sc->may_unmap &&*/ page_mapped(page))
		return -1;
#endif
	/*
	 * Be careful not to clear PageLRU until after we're
	 * sure the page is not being freed elsewhere -- the
	 * page release code relies on it.
	 */
	//page引用计数不是0则加1并返回true。否则说明page应用计数是0，返回false，这种page已经没进程在使用了，已经不在lRU链表了
	if (unlikely(!get_page_unless_zero(page)))
		return -1;

	if (!TestClearPageLRU(page)) {
		/* Another thread is already isolating this page */
		put_page(page);
		return -1;
	}
	lruvec = mem_cgroup_lruvec_async(page_memcg(page), pgdat);
	//把page从lru链表剔除，同时更新各种page在lru链表有关的各种统计计数
	del_page_from_lru_list_async(page, lruvec);
	//如果page在active lru链表上则要清理掉Active属性，因为内存回收的page一定是处于inactive lru链表，否则内存回收最后会因为page有PageActive属性而触发crash
	if(PageActive(page))
		ClearPageActive(page);
	//再把page添加到dst临时链表 
	list_add(&page->lru,dst);

	return 0;
}
#else
//# error Need LINUX_VERSION_CODE
#endif

//该函数把内存回收相关的没有EXPORT_SYMBAL的内核函数，通过kallsyms_lookup_name()找到这些函数的函数指针，然后本ko里就可以直接用这些函数了
static int look_up_not_export_function(void)
{
   /*由于5.1*内核kallsyms_lookup_name函数不再export了，无法再ko使用。没办法只能利用kprobe计数获取内核kallsyms_lookup_name()函数的指针并保存到
   *kallsyms_lookup_name_async。用它替代内核原生kallsyms_lookup_name函数。低版本的内核不用这么操作，但为了保持兼容只能用
   kallsyms_lookup_name_async替代kallsyms_lookup_name*/
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
	__isolate_lru_page_async = (void*)kallsyms_lookup_name_async("__isolate_lru_page");
	page_evictable_async = (void*)kallsyms_lookup_name_async("page_evictable");
	__remove_mapping_async = (void*)kallsyms_lookup_name_async("__remove_mapping");
	mem_cgroup_update_lru_size_async = (void*)kallsyms_lookup_name_async("mem_cgroup_update_lru_size");
	mem_cgroup_page_lruvec_async = (void*)kallsyms_lookup_name_async("mem_cgroup_page_lruvec");
	__mod_lruvec_state_async = (void*)kallsyms_lookup_name_async("__mod_lruvec_state");
	free_unref_page_list_async = (void*)kallsyms_lookup_name_async("free_unref_page_list");
	mem_cgroup_uncharge_list_async = (void*)kallsyms_lookup_name_async("mem_cgroup_uncharge_list");
	__count_memcg_events_async = (void*)kallsyms_lookup_name_async("__count_memcg_events");
	//新加的
	putback_lru_page_async = (void *)kallsyms_lookup_name_async("putback_lru_page");
	try_to_unmap_flush_async = (void*)kallsyms_lookup_name_async("try_to_unmap_flush");
	mem_cgroup_uncharge_async = (void*)kallsyms_lookup_name_async("mem_cgroup_uncharge");
	compound_page_dtors_async= (compound_page_dtor *  (*)[])kallsyms_lookup_name_async("compound_page_dtors");

	if(!__isolate_lru_page_async || !page_evictable_async || !__remove_mapping_async || !mem_cgroup_update_lru_size_async || !mem_cgroup_page_lruvec_async || !__mod_lruvec_state_async || !free_unref_page_list_async || !mem_cgroup_uncharge_list_async || !__count_memcg_events_async || !putback_lru_page_async || !try_to_unmap_flush_async || !compound_page_dtors_async || !mem_cgroup_uncharge_async){
		printk("!!!!!!!!!! error __isolate_lru_page_async:0x%llx page_evictable_async:0x%llx __remove_mapping_async:0x%llx mem_cgroup_update_lru_size:0x%llx mem_cgroup_page_lruvec:0x%llx __mod_lruvec_state:0x%llx free_unref_page_list:0x%llx mem_cgroup_uncharge_list:0x%llx __count_memcg_events:0x%llx putback_lru_page_async:0x%llx try_to_unmap_flush_async:0x%llx compound_page_dtors_async:0x%llx mem_cgroup_uncharge_async:0x%llx\n",(u64)__isolate_lru_page_async,(u64)page_evictable_async,(u64)__remove_mapping_async,(u64)mem_cgroup_update_lru_size_async,(u64)mem_cgroup_page_lruvec_async,(u64)__mod_lruvec_state_async,(u64)free_unref_page_list_async,(u64)mem_cgroup_uncharge_list_async,(u64)__count_memcg_events_async,(u64)putback_lru_page_async,(u64)try_to_unmap_flush_async,(u64)compound_page_dtors_async,(u64)mem_cgroup_uncharge_async);
		return -1;
	}
#else
	__remove_mapping_async = (void*)kallsyms_lookup_name_async("__remove_mapping");
	mem_cgroup_update_lru_size_async = (void*)kallsyms_lookup_name_async("mem_cgroup_update_lru_size");
	free_unref_page_list_async = (void*)kallsyms_lookup_name_async("free_unref_page_list");
	__count_memcg_events_async = (void*)kallsyms_lookup_name_async("__count_memcg_events");

	//新加的
	mem_cgroup_disabled_async = (void *)kallsyms_lookup_name_async("mem_cgroup_disabled");
	__mod_memcg_lruvec_state_async = (void *)kallsyms_lookup_name_async("__mod_memcg_lruvec_state");
	putback_lru_page_async = (void *)kallsyms_lookup_name_async("putback_lru_page");
	try_to_unmap_flush_async = (void*)kallsyms_lookup_name_async("try_to_unmap_flush");
	__mem_cgroup_uncharge_list_async = (void*)kallsyms_lookup_name_async("__mem_cgroup_uncharge_list");
	root_mem_cgroup_async = (struct mem_cgroup *)kallsyms_lookup_name_async("root_mem_cgroup");
	compound_page_dtors_async= (compound_page_dtor *  (*)[NR_COMPOUND_DTORS])kallsyms_lookup_name_async("compound_page_dtors");
	cache_random_seq_destroy_async = (void *)kallsyms_lookup_name_async("cache_random_seq_destroy");

	if(!__remove_mapping_async || !mem_cgroup_update_lru_size_async  || !free_unref_page_list_async || !__count_memcg_events_async  || !mem_cgroup_disabled_async  || !__mod_memcg_lruvec_state_async  || !putback_lru_page_async  || !try_to_unmap_flush_async  || !root_mem_cgroup_async || !compound_page_dtors_async || !__mem_cgroup_uncharge_list_async || !cache_random_seq_destroy_async){
		printk("!!!!!!!!!! error __remove_mapping_async:0x%llx mem_cgroup_update_lru_size_async:0x%llx free_unref_page_list_async:0x%llx __count_memcg_events_async:0x%llx mem_cgroup_disabled_async:0x%llx __mod_memcg_lruvec_state_async:0x%llx putback_lru_page_async:0x%llx try_to_unmap_flush_async:0x%llx root_mem_cgroup_async:0x%llx compound_page_dtors_async:0x%llx __mem_cgroup_uncharge_list_async:0x%llx cache_random_seq_destroy_async:0x%llx",(u64)__remove_mapping_async,(u64)mem_cgroup_update_lru_size_async,(u64)free_unref_page_list_async ,(u64)__count_memcg_events_async ,(u64)mem_cgroup_disabled_async ,(u64)__mod_memcg_lruvec_state_async,(u64)putback_lru_page_async,(u64)try_to_unmap_flush_async ,(u64)root_mem_cgroup_async,(u64)compound_page_dtors_async,(u64)__mem_cgroup_uncharge_list_async,(u64)cache_random_seq_destroy_async);
		return -1;
	}
    
	/*mem_cgroup_disabled明明是inline类型，但是cat /proc/kallsyms却可以看到它的函数指针。并且还可以在ko里直接用mem_cgroup_disabled()函数。
	 * 但是测试表明，cat /proc/kallsyms看到的mem_cgroup_disabled()函数指针  和 在驱动里直接打印mem_cgroup_disabled()函数指针，竟然不一样，
	 * 奇葩了，神奇了!!为了安全还是用cat /proc/kallsyms看到的函数指针吧!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
	if((u64)mem_cgroup_disabled_async != (u64)mem_cgroup_disabled){
		printk("mem_cgroup_disabled_async:0x%llx != mem_cgroup_disabled:0x%llx %d\n",(u64)mem_cgroup_disabled_async,(u64)mem_cgroup_disabled,mem_cgroup_disabled_async());
		//return -1;
	}
#endif
	
	sb_lock_async = (spinlock_t *)kallsyms_lookup_name_async("sb_lock");
    super_blocks_async = (struct list_head *)kallsyms_lookup_name_async("super_blocks");
    security_sb_free_async = (void*)kallsyms_lookup_name_async("security_sb_free");
    destroy_super_rcu_async = (void*)kallsyms_lookup_name_async("destroy_super_rcu");
	if(!sb_lock_async || !super_blocks_async || !security_sb_free_async || !destroy_super_rcu_async){
	    printk("sb_lock_async:0x%llx super_blocks_async:0x%llx security_sb_free_async:0x%llx destroy_super_rcu_async:0x%llx\n",(u64)sb_lock_async,(u64)super_blocks_async,(u64)security_sb_free_async,(u64)destroy_super_rcu_async);
	}

	if(shrink_page_printk_open1)
	    printk("kallsyms_lookup_name:0x%llx root_mem_cgroup:0x%llx\n",(u64)(kp_kallsyms_lookup_name.addr),(u64)root_mem_cgroup_async);
	return 0;
}
//遍历p_file_stat对应文件的file_area_free链表上的file_area结构，找到这些file_area结构对应的page，这些page被判定是冷页，可以回收
static unsigned long cold_file_isolate_lru_pages(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,
		struct list_head *file_area_free)
{
	struct file_area *p_file_area,*tmp_file_area;
	int i;
	struct address_space *mapping = NULL;
	isolate_mode_t mode = ISOLATE_UNMAPPED;
	pg_data_t *pgdat = NULL;
	struct page *page;
	unsigned int isolate_pages = 0;
	int traverse_file_area_count = 0;  
	struct list_head *dst;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
	struct lruvec *lruvec = NULL,*lruvec_new = NULL;
#endif 

	//对file_stat加锁
	lock_file_stat(p_file_stat,0);
	//如果文件inode和mapping已经释放了，则不能再使用mapping了，必须直接return
	if(file_stat_in_delete(p_file_stat) || (NULL == p_file_stat->mapping))
		goto err;
	mapping = p_file_stat->mapping;

	/*!!隐藏非常深的地方，这里遍历file_area_free(即)链表上的file_area时，可能该file_area在hot_file_update_file_status()中被访问而移动到了temp链表
	  这里要用list_for_each_entry_safe()，不能用list_for_each_entry!!!!!!!!!!!!!!!!!!!!!!!!*/
	list_for_each_entry_safe(p_file_area,tmp_file_area,file_area_free,file_area_list){

        /*如果遍历16个file_area,则检测一次是否有其他进程获取lru_lock锁失败而阻塞.有的话就释放lru_lock锁，先休眠5ms再获取锁,防止那些进程阻塞太长时间.
		 *是否有必要释放lru_lock锁时，也lock_file_stat()释放file_stat锁呢？此时可能处要使用lock_file_stat，1:inode删除 2：
		 *hot_cold_file_print_all_file_stat打印file_stat信息3:file_stat因为0个file_area而要删除.但这里仅休眠5ms不会造成太大阻塞。故不释放file_stat锁*/
		if(traverse_file_area_count++ >= 16){
			    traverse_file_area_count = 0;
			#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
				//使用pgdat->lru_lock锁，且有进程阻塞在这把锁上
				if(pgdat && spin_is_contended(&pgdat->lru_lock)){
					spin_unlock(&pgdat->lru_lock); 
					msleep(5);
					spin_lock(&pgdat->lru_lock);
					p_hot_cold_file_global->hot_cold_file_shrink_counter.lru_lock_contended_count ++;
				}
            #else
				//使用 lruvec->lru_lock 锁，且有进程阻塞在这把锁上
				if(lruvec && spin_is_contended(&lruvec->lru_lock)){
					spin_unlock(&lruvec->lru_lock); 
					msleep(5);
					spin_lock(&lruvec->lru_lock);
					p_hot_cold_file_global->hot_cold_file_shrink_counter.lru_lock_contended_count ++;
				}
            #endif
		}
		/*如果在遍历file_stat的file_area过程，__destroy_inode_handler_post()里释放该file_stat对应的inode和mapping，则对file_stat加锁前先
		 *p_file_stat->mapping =NULL.然后这里立即goto err并释放file_stat锁，最后__destroy_inode_handler_post()可以立即获取file_stat锁*/
		if(file_stat_in_delete(p_file_stat) || (NULL == p_file_stat->mapping)){
			printk("file_stat:0x%llx inode already delete\n",(u64)p_file_stat);
			goto err;
        }
		//if成立说明有inode删除lock_file_stat()获取锁失败。这里立即结束遍历file_stat的file_area，因为inode都要删除了
		if(test_bit(F_file_stat_lock_not_block,&p_file_stat->file_stat_status))
		{
			printk("file_stat:0x%llx inode is in delete\n",(u64)p_file_stat);
			goto err;
		}

		/*对p_file_area->shrink_time的赋值不再加锁，
		 *情况1:如果这里先对p_file_area->shrink_time赋值,然后1s内hot_file_update_file_status()函数访问该file_area,则file_area被判定是refault file_area
		 *情况2:先有hot_file_update_file_status()函数访问该file_area,但p_file_area->shrink_time还是0，则file_area无法被判定是refault file_area.
		 但因为file_area处于file_stat->file_area_free_temp链表上，故把file_area移动到file_stat->file_area_temp链表。然后这里执行到
		 if(!file_area_in_free_list(p_file_area))，if成立，则不再不再回收该file_area的page。这种情况也没事

		 *情况3:如果这里快要对p_file_area->shrink_time赋值，但是先有hot_file_update_file_status()函数访问该file_area，但p_file_area->shrink_time还是0，
		 则file_area无法被判定是refault file_area.但因为file_area处于file_stat->file_area_free_temp链表上，故把file_area移动到file_stat->file_area_temp
		 链表。但是，在把file_area移动到file_stat->file_area_free_temp链表上前，这里并发先执行了对p_file_area->shrink_time赋值当前时间和
		 if(!file_area_in_free_list(p_file_area))，但if不成立。然后该file_area的page还要继续走内存回收流程。相当于刚访问过的file_area却被回收内存page了.
		 这种情况没有办法。只有在hot_file_update_file_status()函数中，再次访问该file_area时，发现p_file_area->shrink_time不是0，说明刚该file_area经历过
		 一次重度refault现象，于是也要把file_area移动到refault链表。注意，此时file_area处于file_stat->file_area_free_temp链表。
		 * */

		//获取file_area内存回收的时间，ktime_to_ms获取的时间是ms，右移10近似除以1000，变成单位秒
		p_file_area->shrink_time = ktime_to_ms(ktime_get()) >> 10;
		smp_mb();
		//正常此时file_area处于file_stat->file_area_free_temp链表，但如果正好此时该file_area被访问了，则就要移动到file_stat->file_area_temp链表。
		//这种情况file_area的page就不能被释放了
		if(!file_area_in_free_list(p_file_area)){
			p_file_area->shrink_time = 0;
			continue;
		}
        
		/*遍历radix tree前需要标记进入rcu宽限期，这样其他进程此时就无法释放该radix tree的node节点结构，否则这里遍历radix tree指向
		 *的node节点内存就可能是无效的，将发生crash。但是实际看xa_load源码里边已经有rcu_read_lock了，这里就不用再重复rcu_read_lock了*/
		//rcu_read_lock();

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
		//得到file_area对应的page
		for(i = 0;i < PAGE_COUNT_IN_AREA;i ++){
			page = xa_load(&mapping->i_pages, p_file_area->start_index + i);
			if (page && !xa_is_value(page)) {

				/*对page加锁,lock_page执行后只能有两种情况,1:page被其他进程内存回收了,于是这里lock_page后,if(page->mapping!=mapping)不成立,
				 *就可以过滤掉这个page  2:page没有被其他进程回收，但是一直到lru_lock锁成功后,再unlock_page.这样就可以防止 
				 *这段时间page被其他进程释放了,也不用担心page memcg没有一个page了而释放掉memcg和lruvec.因为至少还有这1个page因为lock_page了,
				 *释放不了,那就释放不了memcg和lruvec。之后因为已经lru_lock加锁成功，更不用担心page被其他进程释放了。
				 */
				if (!trylock_page(page)){
				    continue;
				}
				//如果page被其他进程回收了，这里不成立，直接过滤掉page
				if(page->mapping != mapping){
					unlock_page(page);
					continue;
                }

			   /*正常情况每个文件的page cache的page都应该属于同一个node,进行一次spin_lock(&pgdat->lru_lock)就行,但是也有可能属于不同的内存节点node，
				那就需要每次出现新的page所属的内存节点node的pgdat=page_pgdat(page)时,那就把老的pgdat=page_pgdat(page)解锁，对新的pgdat=page_pgdat(page)加锁
				pgdat != page_pgdat(page)成立说明前后两个page所属node不一样,那就要把前一个page所属pgdat spin unlock,然后对新的page所属pgdat spin lock*/
				if(unlikely(pgdat != page_pgdat(page)))
				{
					//第一次进入这个if，pgdat是NULL，此时不用spin unlock，只有后续的page才需要
					if(pgdat){
						//对之前page所属pgdat进行spin unlock
						spin_unlock_irq(&pgdat->lru_lock);
					}
					//pgdat最新的page所属node节点对应的pgdat
					pgdat = page_pgdat(page);
					if(pgdat != p_hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat)
						panic("pgdat not equal\n");
					//对新的page所属的pgdat进行spin lock。内核遍历lru链表都是关闭中断的，这里也关闭中断
					spin_lock_irq(&pgdat->lru_lock);
				}
				unlock_page(page);

				/*这里又是另外一个核心点。由于现在前后两次的page不能保证处于同一个内存node、同一个memory、同一个lruvec，因此
				 * 只能每来一个page，都执行类似原版内存回收的isolate_lru_pages函数：判断能否隔离，可以隔离的话。再计算当前page所属的
				 * pgdat、lruvec、active/inacitve lru编号，然后把page从lru链表剔除，再令lru链表的page数减1。内核的isolate_lru_pages函数，
				 * 进行隔离的多个page一定来自同一个pgdat、lruvec、active/inacitve lru编号，就不用针对隔离的每个page再计算这些参数了。
				 * 并且把所有page都隔离后，同一执行update_lru_sizes()令lru链表的page数减去隔离成功的page数。显然，这样更节省cpu，
				 * 我的方法稍微有点耗cpu，尤其是隔离page多的情况下

				 * 还有一点，这里__hot_cold_file_isolate_lru_pages()每次只隔离一个page，然后把page移动到该page所在内存节点的pgdat_page_list链表，
				 * pgdat->node_id是该page所在内存节点的编号。这样做的目的是，4.1*原生内核在的内存回收，是遍历lruvec lru链表上的page时，先加
				 * pgdat->lru_lock锁，就是每个内存节点的锁。然后隔离出来一定数目的page，尝试回收这些page。接着，回收失败的page，先pgdat->lru_lock
				 * 加锁，然后再把page按照page所在lruvec，putback移动回lruvec lru链表。这是原生内核的内存回收流程，当前这个基于冷热文件的内存回收
				 * 方案，是遍历一个文件上文件页page，这些page可能属于不同的内存节点，不同的lruvec。太乱了。于是我想，在隔离这些文件页page时，按照
				 * page所属内存节点pgdat进行隔离。先对第1个文件页所属内存节点pgdat->lru_lock加锁，然后把page移动到它所属内存节点的pgdat_page_list
				 * 链表。后续隔离page时，如果page属于不同的内存节点，那就对新的内存节点pgdat->lru_lock加锁，然后把page移动到它所属内存节点的
				 * pgdat_page_list链表。这样做的效果是，每个隔离出来的page都移动到了它所属的内存节点对应的pgdat_page_list链表。等内存回收后，
				 * 对每个内存节点对应的pgdat_page_list链表上的page进行回收。内存回收后，每个内存节点pgdat_page_list链表上都会有回收失败的page。
				 * 然后再依次把内存节点pgdat_page_list回收失败的page依次putback移动回lruvec lru链表，移动前要对这个内存节点pgdat->lru_lock加锁。
				 * 如果有2个内存节点，此时只用pgdat->lru_lock加锁加锁两次。之前的努力就是为了此时putback的少加锁!否则，在putback把page移动回
				 * lruvec lru链表时，每处理一个page，都要判断这个page跟上一个是否属于同一个内存节点，不属于就要再pgdat->lru_lock加锁。这样如果
				 * putback的page属于不同的内存节点，就要多次pgdat->lru_lock加锁。下边的else分支的5.14内核就是做的，没办法，因为它不再使用
				 * pgdat->lru_lock锁了，而是使用lruvec->lru_lock锁。两个方法其实都可以，只要保证page从lruvec lru链表隔离出来，或者把page putback
				 * 移动回lruvec lru链表，一定要pgdat->lru_lock或者lruvec->lru_lock加锁就行了。如把从lruvec lru链表隔离出来的page是否要移动到它所在
				 * 的内存节点的pgdat_page_list链表，还是只移动到一个固定的链表，都可以，无所谓，区别时回收失败的page putback移动回lruvec lru链表时，
				 * 是否会频繁pgdat->lru_lock或lruvec->lru_lock加锁*/
				dst = &p_hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat_page_list;
				//隔离page，隔离成功的page移动到对应内存节点的hot_cold_file_node_pgdat链表上
				if(__hot_cold_file_isolate_lru_pages(pgdat,page,dst,mode) != 0){
					//goto err; 到这里说明page busy，不能直接goto err返回错误，继续遍历page，否则就中断了整个内存回收流程，完全没必要
					continue;
				}
				isolate_pages ++;
			}
		}
#else
		//得到file_area对应的page
		for(i = 0;i < PAGE_COUNT_IN_AREA;i ++){
			page = xa_load(&mapping->i_pages, p_file_area->start_index + i);
			if (page && !xa_is_value(page)) {

				//这里lock_page的原因上边有解释
				if (!trylock_page(page)){
				    continue;
				}
				//如果page被其他进程回收了，这里不成立，直接过滤掉page
				if(page->mapping != mapping){
					unlock_page(page);
					continue;
                }
				//为了保持兼容，还是把每个内存节点的page都移动到对应hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat_page_list链表上
				if(pgdat != page_pgdat(page))
					pgdat = page_pgdat(page);

				lruvec_new = mem_cgroup_lruvec_async(page_memcg(page),pgdat);
				if(unlikely(lruvec != lruvec_new)){
					if(lruvec){
						spin_unlock_irq(&lruvec->lru_lock);
					}
					lruvec = lruvec_new;
					//对新的page所属的pgdat进行spin lock
					spin_lock_irq(&lruvec->lru_lock);
				}
				unlock_page(page);

				dst = &p_hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat_page_list;
				if(__hot_cold_file_isolate_lru_pages(pgdat,page,dst,mode) != 0){
					//goto err; 到这里说明page busy，不能直接goto err返回错误，继续遍历page，否则就中断了整个内存回收流程，完全没必要
					continue;
				}
				isolate_pages ++;
			}
		}
#endif
		//rcu_read_unlock();
    }
err:   

	//file_stat解锁
	unlock_file_stat(p_file_stat);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
	if(pgdat)
		spin_unlock_irq(&pgdat->lru_lock);
#else
	if(lruvec)
		spin_unlock_irq(&lruvec->lru_lock);
#endif
	return isolate_pages;
}
//file_area_hot_to_temp_age_dx
static int file_area_hot_to_temp_age_dx_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", hot_cold_file_global_info.file_area_hot_to_temp_age_dx);
	return 0;
}
static int file_area_hot_to_temp_age_dx_open(struct inode *inode, struct file *file)
{
	return single_open(file, file_area_hot_to_temp_age_dx_show, NULL);
}
static ssize_t file_area_hot_to_temp_age_dx_write(struct file *file,
				const char __user *buffer, size_t count, loff_t *ppos)
{
    int rc;
	unsigned int val;
	rc = kstrtouint_from_user(buffer, count, 10,&val);
	if (rc)
	    return rc;

    if(val < 100)
	    hot_cold_file_global_info.file_area_hot_to_temp_age_dx = val;
	else
		return -EINVAL;

	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations file_area_hot_to_temp_age_dx_fops = {
    .open		= file_area_hot_to_temp_age_dx_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= file_area_hot_to_temp_age_dx_write,
};
#else
static const struct proc_ops file_area_hot_to_temp_age_dx_fops = {
    .proc_open		= file_area_hot_to_temp_age_dx_open,
	.proc_read		= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write		= file_area_hot_to_temp_age_dx_write,
};
#endif
//file_area_refault_to_temp_age_dx
static int file_area_refault_to_temp_age_dx_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", hot_cold_file_global_info.file_area_refault_to_temp_age_dx);
	return 0;
}
static int file_area_refault_to_temp_age_dx_open(struct inode *inode, struct file *file)
{
	return single_open(file, file_area_refault_to_temp_age_dx_show, NULL);
}
static ssize_t file_area_refault_to_temp_age_dx_write(struct file *file,
				const char __user *buffer, size_t count, loff_t *ppos)
{
    int rc;
	unsigned int val;
	rc = kstrtouint_from_user(buffer, count, 10,&val);
	if (rc)
	    return rc;

    if(val < 100)
	    hot_cold_file_global_info.file_area_refault_to_temp_age_dx = val;
	else
		return -EINVAL;

	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations file_area_refault_to_temp_age_dx_fops = {
    .open		= file_area_refault_to_temp_age_dx_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= file_area_refault_to_temp_age_dx_write,
};
#else
static const struct proc_ops file_area_refault_to_temp_age_dx_fops = {
    .proc_open		= file_area_refault_to_temp_age_dx_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release	= single_release,
	.proc_write		= file_area_refault_to_temp_age_dx_write,
};
#endif
//file_area_temp_to_cold_age_dx
static int file_area_temp_to_cold_age_dx_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", hot_cold_file_global_info.file_area_temp_to_cold_age_dx);
	return 0;
}
static int file_area_temp_to_cold_age_dx_open(struct inode *inode, struct file *file)
{
	return single_open(file, file_area_temp_to_cold_age_dx_show, NULL);
}
static ssize_t file_area_temp_to_cold_age_dx_write(struct file *file,
				const char __user *buffer, size_t count, loff_t *ppos)
{
    int rc;
	unsigned int val;
	rc = kstrtouint_from_user(buffer, count, 10,&val);
	if (rc)
	    return rc;

    if(val < 100)
	    hot_cold_file_global_info.file_area_temp_to_cold_age_dx = val;
	else
		return -EINVAL;

	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations file_area_temp_to_cold_age_dx_fops = {
    .open		= file_area_temp_to_cold_age_dx_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= file_area_temp_to_cold_age_dx_write,
};
#else
static const struct proc_ops file_area_temp_to_cold_age_dx_fops = {
    .proc_open		= file_area_temp_to_cold_age_dx_open,
	.proc_read		= seq_read,
	.proc_lseek     = seq_lseek,
	.proc_release	= single_release,
	.proc_write		= file_area_temp_to_cold_age_dx_write,
};
#endif
//file_area_free_age_dx
static int file_area_free_age_dx_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", hot_cold_file_global_info.file_area_free_age_dx);
	return 0;
}
static int file_area_free_age_dx_open(struct inode *inode, struct file *file)
{
	return single_open(file, file_area_free_age_dx_show, NULL);
}
static ssize_t file_area_free_age_dx_write(struct file *file,
				const char __user *buffer, size_t count, loff_t *ppos)
{
    int rc;
	unsigned int val;
	rc = kstrtouint_from_user(buffer, count, 10,&val);
	if (rc)
	    return rc;

    if(val < 100)
	    hot_cold_file_global_info.file_area_free_age_dx = val;
	else
		return -EINVAL;

	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations file_area_free_age_dx_fops = {
    .open		= file_area_free_age_dx_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= file_area_free_age_dx_write,
};
#else
static const struct proc_ops file_area_free_age_dx_fops = {
    .proc_open		= file_area_free_age_dx_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release	= single_release,
	.proc_write		= file_area_free_age_dx_write,
};
#endif
//file_stat_delete_age_dx
static int file_stat_delete_age_dx_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", hot_cold_file_global_info.file_stat_delete_age_dx);
	return 0;
}
static int file_stat_delete_age_dx_open(struct inode *inode, struct file *file)
{
	return single_open(file, file_stat_delete_age_dx_show, NULL);
}
static ssize_t file_stat_delete_age_dx_write(struct file *file,
				const char __user *buffer, size_t count, loff_t *ppos)
{
    int rc;
	unsigned int val;
	rc = kstrtouint_from_user(buffer, count, 10,&val);
	if (rc)
	    return rc;

    if(val < 100)
	    hot_cold_file_global_info.file_stat_delete_age_dx = val;
	else
		return -EINVAL;

	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations file_stat_delete_age_dx_fops = {
    .open		= file_stat_delete_age_dx_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= file_stat_delete_age_dx_write,
};
#else
static const struct proc_ops file_stat_delete_age_dx_fops = {
    .proc_open		= file_stat_delete_age_dx_open,
	.proc_read		= seq_read,
	.proc_lseek     = seq_lseek,
	.proc_release	= single_release,
	.proc_write		= file_stat_delete_age_dx_write,
};
#endif
//global_age_period
static int global_age_period_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", hot_cold_file_global_info.global_age_period);
	return 0;
}
static int global_age_period_open(struct inode *inode, struct file *file)
{
	return single_open(file, global_age_period_show, NULL);
}
static ssize_t global_age_period_write(struct file *file,
				const char __user *buffer, size_t count, loff_t *ppos)
{
    int rc;
	unsigned int val;
	rc = kstrtouint_from_user(buffer, count, 10,&val);
	if (rc)
	    return rc;

    if(val >= 10 && val <= 60)
	    hot_cold_file_global_info.global_age_period = val;
	else
		return -EINVAL;

	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations global_age_period_fops = {
    .open		= global_age_period_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= global_age_period_write,
};
#else
static const struct proc_ops global_age_period_fops = {
    .proc_open		= global_age_period_open,
	.proc_read		= seq_read,
	.proc_lseek     = seq_lseek,
	.proc_release	= single_release,
	.proc_write		= global_age_period_write,
};
#endif
//open_print
static int open_print_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", shrink_page_printk_open1);
	return 0;
}
static int open_print_open(struct inode *inode, struct file *file)
{
	return single_open(file, open_print_show, NULL);
}
static ssize_t open_print_write(struct file *file,
				const char __user *buffer, size_t count, loff_t *ppos)
{
    int rc;
	unsigned int val;
	rc = kstrtouint_from_user(buffer, count, 10,&val);
	if (rc)
	    return rc;

    if(val <= 1)
	    shrink_page_printk_open1 = val;
	else
		return -EINVAL;

	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations open_print_fops = {
    .open		= open_print_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= open_print_write,
};
#else
static const struct proc_ops open_print_fops = {
    .proc_open		= open_print_open,
	.proc_read		= seq_read,
	.proc_lseek	    = seq_lseek,
	.proc_release	= single_release,
	.proc_write		= open_print_write,
};
#endif
//async_drop_caches
static int async_drop_caches_show(struct seq_file *m, void *v)
{
	seq_printf(m, "drop_cache_file_count:%d\n",hot_cold_file_global_info.drop_cache_file_count);
	return 0;
}
static int async_drop_caches_open(struct inode *inode, struct file *file)
{
	return single_open(file,async_drop_caches_show, NULL);
}
static ssize_t async_drop_caches_write(struct file *file,
				const char __user *buffer, size_t count, loff_t *ppos)
{
	//只有把上次drop_cache的文件的pagecache全释放完，drop_cache_file_count才会降低为0
    if(hot_cold_file_global_info.drop_cache_file_count != 0 || test_bit(ASYNC_MEMORY_RECLAIM_ENABLE,&async_memory_reclaim_status) == 0){
	    printk("drop_cache files:%d not reclaim\n",hot_cold_file_global_info.drop_cache_file_count);
		return -EBUSY;
	}

    /*把async_memory_reclaim_status的bit1置1，说明在进行异步drop_cache处理，分配文件file_stat添加到global drop_cache_file_stat_head链表，
	  此时禁止异步内存回收线程处理global drop_cache_file_stat_head链表上的file_stat。防止并发操作*/
    if(test_and_set_bit_lock(ASYNC_DROP_CACHES, &async_memory_reclaim_status))
		//ASYNC_DROP_CACHES这个bit位不可能被多进程并发设置，如果已经被设置了，应该发生了某种异常，触发crash
	    panic("async_memory_reclaim_status:0x%lx alreay set ASYNC_DROP_CACHES\n",async_memory_reclaim_status);

    iterate_supers_async();
	//异步drop_cache处理完了，清0。此时不会再向global drop_cache_file_stat_head链表添加新的file_stat。此时异步内存回收线程可以处理该链表上的file_stat了。
    clear_bit_unlock(ASYNC_DROP_CACHES, &async_memory_reclaim_status);
	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations async_drop_caches_fops = {
    .open		= async_drop_caches_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= async_drop_caches_write,
};
#else
static const struct proc_ops async_drop_caches_fops = {
    .proc_open		= async_drop_caches_open,
	.proc_read		= seq_read,
	.proc_lseek	    = seq_lseek,
	.proc_release	= single_release,
	.proc_write		= async_drop_caches_write,
};
#endif
static int async_memory_reclaime_info_show(struct seq_file *m, void *v)
{
    hot_cold_file_print_all_file_stat(&hot_cold_file_global_info,m,1);
	printk_shrink_param(&hot_cold_file_global_info,m,1);
	return 0;
}
static int hot_cold_file_proc_init(struct hot_cold_file_global *p_hot_cold_file_global)
{
    struct proc_dir_entry *p,*hot_cold_file_proc_root;

    hot_cold_file_proc_root = proc_mkdir("async_memory_reclaime", NULL);
	if(!hot_cold_file_proc_root)
		return -1;

    //proc_create("allow_dio", S_IRUGO | S_IWUSR, hot_cold_file_proc_root, &adio_fops);
	p_hot_cold_file_global->hot_cold_file_proc_root = hot_cold_file_proc_root;
    p = proc_create("file_area_hot_to_temp_age_dx", S_IRUGO | S_IWUSR, hot_cold_file_proc_root, &file_area_hot_to_temp_age_dx_fops);
	if (!p){
		printk("proc_create file_area_hot_to_temp_age_dx fail\n");
		return -1;
	}
    p = proc_create("file_area_refault_to_temp_age_dx", S_IRUGO | S_IWUSR, hot_cold_file_proc_root, &file_area_refault_to_temp_age_dx_fops);
	if (!p){
		printk("proc_create file_area_refault_to_temp_age_dx fail\n");
		return -1;
	}
    p = proc_create("file_area_temp_to_cold_age_dx", S_IRUGO | S_IWUSR, hot_cold_file_proc_root, &file_area_temp_to_cold_age_dx_fops);
	if (!p){
		printk("proc_create file_area_temp_to_cold_age_dx fail\n");
		return -1;
	}
    p = proc_create("file_area_free_age_dx", S_IRUGO | S_IWUSR, hot_cold_file_proc_root, &file_area_free_age_dx_fops);
	if (!p){
		printk("proc_create file_area_free_age_dx fail\n");
		return -1;
	}
    p = proc_create("file_stat_delete_age_dx", S_IRUGO | S_IWUSR, hot_cold_file_proc_root, &file_stat_delete_age_dx_fops);
	if (!p){
		printk("proc_create file_stat_delete_age_dx fail\n");
		return -1;
	}
    p = proc_create("global_age_period", S_IRUGO | S_IWUSR, hot_cold_file_proc_root, &global_age_period_fops);
	if (!p){
		printk("proc_create global_age_period fail\n");
		return -1;
	}
    p = proc_create("open_print", S_IRUGO | S_IWUSR, hot_cold_file_proc_root, &open_print_fops);
	if (!p){
		printk("proc_create open_print fail\n");
		return -1;
	}
	p = proc_create("async_drop_caches", S_IWUSR, hot_cold_file_proc_root, &async_drop_caches_fops);
	if (!p){
		printk("proc_create open_print fail\n");
		return -1;
	}

	p = proc_create_single("async_memory_reclaime_info", S_IRUGO, hot_cold_file_proc_root,async_memory_reclaime_info_show);
	if (!p){
		printk("proc_create async_memory_reclaime_info fail\n");
		return -1;
	}

	return 0;
}
int hot_cold_file_proc_exit(struct hot_cold_file_global *p_hot_cold_file_global)
{
	//"file_area_hot_to_temp_age_dx"节点不存在也不会crash，自身做了防护
	remove_proc_entry("file_area_hot_to_temp_age_dx",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("file_area_refault_to_temp_age_dx",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("file_area_temp_to_cold_age_dx",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("file_area_free_age_dx",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("file_stat_delete_age_dx",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("global_age_period",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("open_print",p_hot_cold_file_global->hot_cold_file_proc_root);

	remove_proc_entry("async_memory_reclaime_info",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("async_drop_caches",p_hot_cold_file_global->hot_cold_file_proc_root);

	remove_proc_entry("async_memory_reclaime",NULL);
	return 0;
}
/* 该函数两个作用
 * 1：当一个file_stat的file_area都释放了，但是文件还有pagecache，因为这部分pagecache在该驱动加载前都被访问了，之后不再被访问。
 *就无法被file_area统计到，这些pagecache称为leak pagecache，该函数就是释放掉leak pagecache。
 * 2：drop_caches异步释放不再使用的文件的pagecache*/
static void file_stat_truncate_inode_pages(struct file_stat * p_file_stat)
{
	struct address_space *mapping = p_file_stat->mapping;
	//如果在释放文件pagecache过程，该文件inode被释放了怎么办？可以iget增加inode引用计数防止
	
	//直接把文件file的pagecache全部截断释放掉，后续考虑优化一下
    truncate_inode_pages_range(mapping,0,-1);
}
//释放drop cache的文件的pagecache
static int drop_cache_truncate_inode_pages(struct hot_cold_file_global *p_hot_cold_file_global)
{
	int scan_count = 0;
	struct inode *inode;

    struct file_stat * p_file_stat,*p_file_stat_temp;
    list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->drop_cache_file_stat_head,hot_cold_file_list){
		//有可能该文件又hot_file_update_file_status()中被访问了，则p_file_stat->file_area_count非0
        if(0 == p_file_stat->file_area_count){
			/*file_stat加锁，防止此时inode并发被删除了。如果删除了则p_file_stat->mapping 是NULL，不再处理。此时文件file_stat也会自动被加上
			 * delete标记，然后删除掉file_stat。并且，如果inode引用计数是0，说明inode马上也要被释放了，没人用了，这种文件file_stat也跳过
			 * 不处理*/
			lock_file_stat(p_file_stat,0);
			if(file_stat_in_delete(p_file_stat) || atomic_read(&p_file_stat->mapping->host->i_count) == 0){
unsed_inode:	
				/*可能其他进程__destroy_inode_handler_post()正在删除inode，标记file_stat删除，这里先等那些进程全都退出__destroy_inode_handler_post函数。
				 *否则，这里强行使用 p_file_stat->mapping->rh_reserved1会crash，因为mapping对应的inode可能被释放了*/
				while(atomic_read(&hot_cold_file_global_info.inode_del_count))
					msleep(1);//此时不会有进程并发向global drop_cache_file_stat_head链表添加删除成员，因此可以休眠

				/*p_file_stat->mapping非NULL说明inode还没执行__destroy_inode_handler_post被释放，那该函数先标记这个文件file_stat已经释放，
				 * 然后主动把file_stat移动到file_stat_delete_head链表等待释放。如果p_file_stat->mapping是NULL，说明__destroy_inode_handler_post
				 * 中已经标记过这个文件的file_stat被释放了。但没有移动到file_stat_delete_head链表，这里只用把它移动到file_stat_delete_head链表即可*/
				if(p_file_stat->mapping){
					//这个释放file_stat的操作与 __destroy_inode_handler_post()函数一样
				    p_file_stat->mapping->rh_reserved1 = 0;
					barrier();
				    p_file_stat->mapping = NULL;
					smp_wmb();//在这个加个内存屏障，保证前后代码隔离开。即file_stat有delete标记后，inode->i_mapping->rh_reserved1一定是0，p_file_stat->mapping一定是NULL
				}
				//file_stat可能在__destroy_inode_handler_post删除inode时已经标记了file_stat delete，这里不再重复操作，否则会crash
				if(0 == file_stat_in_delete(p_file_stat))
				    set_file_stat_in_delete(p_file_stat);
			    //smp_wmb();---set_file_stat_in_delete()现在改成 test_and_set_bit_lock原子操作设置，并且有内促屏障，这个smp_wmb就不需要了

	            hot_cold_file_global_info.drop_cache_file_count --;
				clear_file_stat_in_drop_cache(p_file_stat);
				/*__destroy_inode_handler_post函数不会把file_stat移动到global file_stat_delete_head链表，这里要主动移动。移动时不用加锁，
				 * 只有异步内存回收线程会操作file_stat_delete_head链表*/
				list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_delete_head);

				unlock_file_stat(p_file_stat);
			
				continue;
			}
			/*到这里，是否可以通过对inode引用计数加1防止inode被删除呢？这样就避免长时间使用lock_file_stat锁，因为
			 *file_stat_truncate_inode_pages()过程可能比较耗时！不行，分析见file_stat_free_leak_page函数*/
			
			//释放文件的pagecache
			inode = p_file_stat->mapping->host;
			/*inode->i_lock后再测试一次inode是否被其他进程并发iput，是的话下边if成立.到这里不用担心inode结构被其他进程释放了，因为此时
			 * lock_file_stat(p_file_stat)加锁保证，到这里inode不会被其他进程释放*/
            spin_lock(&inode->i_lock);
			if( ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW))) || atomic_read(&inode->i_count) == 0){
			    spin_unlock(&inode->i_lock);
				//unlock_file_stat(p_file_stat); unsed_inode分支已经有unlock_file_stat
				
				//如果inode已经释放了，则要goto unsed_inode分支释放掉file_stat结构
		        goto unsed_inode;
			}
            //令inode引用计数加1,下边file_stat_truncate_inode_pages不用担心inode被其他进程释放掉
			atomic_inc(&inode->i_count);
			spin_unlock(&inode->i_lock);
			//解锁file_stat lock。
			unlock_file_stat(p_file_stat);

			//释放文件的pagecache
		    file_stat_truncate_inode_pages(p_file_stat);
			//令inode引用计数减1
            iput(inode);


            /*把文件file_stat移动到file_stat_zero_file_area_head链表，如果一段时间改文件还是没被访问，则释放掉file_stat.因为此时
			 * hot_file_update_file_status()中可能并发把file_stat移动到global 热文件或者大文件链表，因此需要global_lock加锁。错了，
			 * 不用加锁，因为这些file_stat目前还没有状态，不是in temp list状态。而hot_file_update_file_status()中只有file_stat处于
			 * in temp list状态，才会移动到global 热文件和大文件链表*/

			//spin_lock(&p_hot_cold_file_global->global_lock);
			clear_file_stat_in_drop_cache(p_file_stat);
			set_file_stat_in_zero_file_area_list(p_file_stat);
			p_hot_cold_file_global->file_stat_count_zero_file_area ++;
            /*把file_stat移动到global file_stat_zero_file_area_head链表尾巴，这样file_stat可以优先被回收掉。并且回收前还会再被
			 * 强制回收一次pagecache，有点浪费性能。是否就在这里把或则file_stat释放掉得了???????????????????????????*/
            list_move_tail(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_zero_file_area_head);
			//spin_unlock(&p_hot_cold_file_global->global_lock);
		}
		else
		{
		/*到这个分支，说明drop_caches的文件被访问了，分配file_area，那就不管它了。让这个文件file_stat按照正常的异步内存回收参与回收page，
		 *等到file_area对应的page被释放完后。文件file_stat一个file_area都没有，然后被移动到p_hot_cold_file_global->file_stat_zero_file_area_head
		  链表。而如果p_hot_cold_file_global->file_stat_zero_file_area_head，链表上的file_stat还有很多pagecache，说明这些pagecache
		  没有被file_area统计到，于是就会执行file_stat_truncate_inode_pages()强制释放掉这部分pagecache。因此，这个else分支的文件file_stat的
		  所有pagecache也能被完美释放掉，就是时间比较长而已。因此，这里只用把file_stat移动到global file_stat_temp_head链表，让这个文件file_stat
		  参与正常的异步内存回收。但是这个过程需要加锁，因为file_stat设置了in temp list状态*/
			spin_lock(&p_hot_cold_file_global->global_lock);
			clear_file_stat_in_drop_cache(p_file_stat);
            set_file_stat_in_file_stat_temp_head_list(p_file_stat);
			list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);
			spin_unlock(&p_hot_cold_file_global->global_lock);
		}
		//drop_cache文件数减1
	    hot_cold_file_global_info.drop_cache_file_count --;

		//扫描drop cache的文件超过10个就停止，单次不回收太多这些文件pagecache
		if(scan_count ++ > 50)
			break;
    }

	return scan_count;
}
/*global file_stat_zero_file_area_head链表上的file_stat，一个file_area都没有，但是还有pagecache，因为这些pagecache没有访问，
 * 被文件file_stat的file_area统计到。这个函数则强制释放掉这些文件的pagecache。*/
static void file_stat_free_leak_page(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat *p_file_stat)
{
	//file_stat加锁，防止此时inode并发被删除了。如果删除了则p_file_stat->mapping 是NULL，直接return
	//并且，如果inode引用计数是0，说明inode马上也要被释放了，没人用了，这种文件file_stat也跳过不处理
	lock_file_stat(p_file_stat,0);
    if(file_stat_in_delete(p_file_stat) || (NULL == p_file_stat->mapping) || atomic_read(&p_file_stat->mapping->host->i_count) == 0){
        unlock_file_stat(p_file_stat);
		return;
	}
    /*到这里，说明文件inode没有被释放，我觉得可以模仿drop_pagecache_sb()，先spin_lock(&inode->i_lock)对inode加锁，然后执行
	 * __iget(inode)令inode引用计数加1.然后执行invalidate_mapping_pages()放心截断释放文件的pagecache。最后用完inode再令inode
	 * 引用计数减1，然后inode才可以被释放掉。不行，有个并发问题，到这里时，文件inode可能正好引用计数减1变为0，然后去释放文件inode。
	 * 我在这里对inode引用计数加1就失效了。但是全程lock_file_stat()加锁防护，可以保证inode删除执行到__destroy_inode_handler_post()时，
	 * 获取file_stat锁失败而阻塞，暂定释放inode结构，这样才没事*/

	/*如果文件mapping统计到的pagecache数大于file_stat统计到的pagecache数，则强制截断释放文件pagecache。这里会有统计误差，因为默认一个
	 * 文件file_area对应4个page。但是一个file_area实际可能只包含了1个page，因为只有一个page被访问了。不过强制截断释放文件pagecache，也没啥事。
	 * p_file_stat->file_area_count基本都是0，但是可能正好此时文件被访问了，p_file_stat->file_area_count就大于0了*/
    if(p_file_stat->mapping->nrpages > p_file_stat->file_area_count << PAGE_COUNT_IN_AREA_SHIFT){
	    file_stat_truncate_inode_pages(p_file_stat);
	}
	unlock_file_stat(p_file_stat);
}
static inline int  add_file_to_file_stat(struct address_space *mapping)
{
	//mapping->rh_reserved1 == 0 说明该文件还没有分配file_stat。mapping->i_pages > 5是为了处理pagecache比较多的文件，太少的就不理会了
    if(mapping->rh_reserved1 == 0 && mapping->nrpages > 5){
		struct file_stat * p_file_stat = NULL;

		/*这里有个问题，如果此时该文件被访问了，执行了hot_file_update_file_status()，也会为该文件分配file_stat并赋值给mapping->rh_reserved1，
		 * 这样就有问题了!!!!!!!!!!!!!一个文件分配两个file_stat，泄漏了。需要防止这种并发，用global_lock spin lock锁最简单!!!!!!!!!!!!*/
		spin_lock(&hot_cold_file_global_info.global_lock);
		/*极端情况是，先有进程在hot_file_update_file_status()获取global lock锁，分配file_stat并赋值给mapping->rh_reserved1。
		 *然后该函数获取glabal lock锁，就直接return返回了*/
		if(mapping->rh_reserved1){
            spin_unlock(&hot_cold_file_global_info.global_lock);
			return 0;
		}
		p_file_stat = kmem_cache_alloc(hot_cold_file_global_info.file_stat_cachep,GFP_ATOMIC);
		if (!p_file_stat) {
            spin_unlock(&hot_cold_file_global_info.global_lock);
			printk("%s file_stat alloc fail\n",__func__);
			goto err;
		}
		//file_stat个数加1
		hot_cold_file_global_info.file_stat_count++;

		memset(p_file_stat,0,sizeof(struct file_stat));
		//初始化file_area_hot头结点
		INIT_LIST_HEAD(&p_file_stat->file_area_hot);
		INIT_LIST_HEAD(&p_file_stat->file_area_temp);
		//INIT_LIST_HEAD(&p_file_stat->file_area_cold);
		INIT_LIST_HEAD(&p_file_stat->file_area_free_temp);
		INIT_LIST_HEAD(&p_file_stat->file_area_free);
		INIT_LIST_HEAD(&p_file_stat->file_area_refault);
        
		mapping->rh_reserved1 = (unsigned long)p_file_stat;
		p_file_stat->mapping = mapping;
		//把file_stat添加到 drop_cache_file_stat_head链表，这里不用加锁，不会并发对drop_cache_file_stat_head链表添加删除file_stat
        list_add(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.drop_cache_file_stat_head);
		set_file_stat_in_drop_cache(p_file_stat);
		spin_lock_init(&p_file_stat->file_stat_lock);

        spin_unlock(&hot_cold_file_global_info.global_lock);

		//向drop_cache_file_stat_head链表添加一个file_stat则加1
		hot_cold_file_global_info.drop_cache_file_count ++;
	}
	return 0;
err:
	return -1;
}
static void __iget_async(struct inode *inode)
{
    atomic_inc(&inode->i_count);
}
static int drop_pagecache_sb_async(struct super_block *sb, void *unused)
{
	struct inode *inode, *toput_inode = NULL;
    int ret = 0;
    unsigned long start_time,dx;

	start_time = jiffies;
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		/*
		 * We must skip inodes in unusual state. We may also skip
		 * inodes without pages but we deliberately won't in case
		 * we need to reschedule to avoid softlockups.
		 */
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages == 0 && !need_resched())) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		//令inode引用计数加1，之后即便在这个for循环里休眠，也不用担心inode也不会被其他进程iput释放掉。为什么在这个for循环里，使用inode时必须保证
		//inode不能被释放掉。因为inode在sb->s_inodes链表上，它被释放的话，通过这个inode找到链表上的下一个inode，就要crash了，因为inode已经被释放
		__iget_async(inode);
		spin_unlock(&inode->i_lock);
		//spin_unlock(&sb->s_inode_list_lock);

		//invalidate_mapping_pages(inode->i_mapping, 0, -1);
		//对文件inode分配file_stat并添加到global drop_cache_file_stat_head链表，之后开启异步内存回收
        ret = add_file_to_file_stat(inode->i_mapping);
		iput(toput_inode);
		toput_inode = inode;

		if(ret < 0)
		    break;

		dx = jiffies_to_msecs(jiffies - start_time);
        //1:如果有进程阻塞在sb->s_inode_list_lock锁上，这里立即释放锁并休眠
		//2:如果这个for循环加锁时间过长 或者 需要调度，则强制休眠
		if(spin_is_contended(&sb->s_inode_list_lock) || need_resched()/*|| dx > 100*/){
            spin_unlock(&sb->s_inode_list_lock);
			//msleep(2);//休眠对性能损耗比较大，先不休眠，而是cond_resched()
			cond_resched();
	        start_time = jiffies;
			spin_lock(&sb->s_inode_list_lock);
		}
		//cond_resched();
		//spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(toput_inode);

	return ret;
}
static void __put_super_async(struct super_block *s)
{
	if (!--s->s_count) {
		list_del_init(&s->s_list);
		WARN_ON(s->s_dentry_lru.node);
		WARN_ON(s->s_inode_lru.node);
		WARN_ON(!list_empty(&s->s_mounts));
		security_sb_free_async(s);
		put_user_ns(s->s_user_ns);
		kfree(s->s_subtype);
		call_rcu(&s->rcu, destroy_super_rcu_async);
	}
}
static inline int is_support_file_system_type(struct super_block *sb)
{
	const char *sb_name;

	sb_name = sb->s_type->name;
	//异步drop_cache bdev的文件inode 的pagecahce，会导致umount ext4文件系统卡死、crash的问题，要过滤掉
	if(strcmp(sb_name,"bdev") == 0)
		return 0;

	/*ext4、xfs、fuse 是测试过异步drop_cache没事的文件系统，如果你想支持新的文件系统，在这里添加即可。其他形如
	 cgroup、tmpfs等常规文件系统，为了异步drop_cache安全还是过滤掉*/
    if(strcmp(sb_name,"ext4") == 0 || strcmp(sb_name,"xfs") == 0 || strcmp(sb_name,"fuse") == 0 /*||strcmp(sb_name,"f2fs") == 0*/){
	    return 1;
	}
	return 0;
}
/*在加载该异步内存回收前，可能已经有文件产生了pagecache，这部分文件页page就无法转换成file_area了，因为不再被读写，无法执行
 * hot_file_update_file_status函数被统计到。该函数通过所有文件系统的super_block遍历每一个文件的inode，看哪个文件的pagecache很多
 * 但是没有被该异步内存回收模块的file_stat和file_area接管。那就强制释放这些文件的pagecache，因为这些文件很长时间不被访问了，
 * 但是还占着很大的内存空间。由于一个linux系统有很多文件inode，遍历这些文件inode时，不能一直spin lock加锁，会导致系统调度异常，
 * 本函数针对这点做了很大优化*/
static void iterate_supers_async(void)
{
	struct super_block *sb, *p = NULL;
    int ret = 0;
	unsigned int super_block_count = 0;

	spin_lock(sb_lock_async);
	list_for_each_entry(sb, super_blocks_async, s_list) {
		if (hlist_unhashed(&sb->s_instances))
			continue;
		//令sb的引用计数加1，保证在这个for循环里，使用sb时sb无法被释放，否则就不用通过sb在链表中找到下一个sb
		sb->s_count++;
		spin_unlock(sb_lock_async);

		down_read(&sb->s_umount);
		if (sb->s_root && (sb->s_flags & SB_BORN) && is_support_file_system_type(sb))
			ret = drop_pagecache_sb_async(sb, NULL);
		up_read(&sb->s_umount);

		spin_lock(sb_lock_async);
		if (p)
			__put_super_async(p);
		p = sb;

		super_block_count++;
		if(ret < 0)
			break;
	}
	if (p)
	    __put_super_async(p);
	spin_unlock(sb_lock_async);

	if(shrink_page_printk_open1)
	    printk("drop_cache super_blocks:%d files:%d\n",super_block_count,hot_cold_file_global_info.drop_cache_file_count);
}
/*************以上代码不同内核版本有差异******************************************************************************************/


/*************以下代码不同内核版本保持一致******************************************************************************************/
static inline unsigned long hot_cold_file_area_tree_shift_maxindex(unsigned int shift)
{
	return (TREE_MAP_SIZE << shift) - 1;
}
//计算以当前节点node为基准，它下边的子树能容纳多少个page有关的file_area。如果是跟节点，则表示整个tree最多容纳多少个file_area
static inline unsigned long hot_cold_file_area_tree_node_maxindex(struct hot_cold_file_area_tree_node *node)
{
	return  hot_cold_file_area_tree_shift_maxindex(node->shift);
}
static inline bool hot_cold_file_area_tree_is_internal_node(void *ptr)
{
	return ((unsigned long)ptr & TREE_ENTRY_MASK) == TREE_INTERNAL_NODE;
}
static inline struct hot_cold_file_area_tree_node *entry_to_node(void *ptr)
{
	return (void *)((unsigned long)ptr & ~TREE_INTERNAL_NODE);
}
static inline void *node_to_entry(void *ptr)
{
	return (void *)((unsigned long)ptr | TREE_INTERNAL_NODE);
}
static int hot_cold_file_area_tree_extend(struct hot_cold_file_area_tree_root *root,unsigned long area_index,unsigned int shift)
{
	struct hot_cold_file_area_tree_node *slot;
	unsigned int maxshift;

	maxshift = shift;
	//file_area_tree要扩增1层时，这个循环不成立.扩增2层时循环成立1次，其他类推
	while (area_index > hot_cold_file_area_tree_shift_maxindex(maxshift))
		maxshift += TREE_MAP_SHIFT;

	slot = root->root_node;
	if (!slot)
		goto out;

	do {
		/*在分配radix tree node前，是spin lock加了file_stat->file_stat_lock锁的，故这里分配内存禁止休眠，否则低内存场景就会占着spin锁休眠，
		 * 然后导致其他进程获取spin lock失败而soft lockup*/
		struct hot_cold_file_area_tree_node* node = kmem_cache_alloc(hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep,GFP_ATOMIC);
		if (!node)
			return -ENOMEM;
		memset(node,0,sizeof(struct hot_cold_file_area_tree_node));
		node->shift = shift;
		node->offset = 0;
		node->count = 1;
		node->parent = NULL;
		if (hot_cold_file_area_tree_is_internal_node(slot))
			entry_to_node(slot)->parent = node;
		/*当file_area tree只保存索引是0的file_area时，file_area指针是保存在root->root_node指针里。后续file_area tree添加其他成员时，就需要增加tree
		 *层数，就在这个循环完成。可能file_area tree一次只增加一层，或者增加多层。这行代码是限制，当第一层增加tree层数时，slot是root->root_node，
		 *并且slot保存的是索引是0的file_area指针，不是节点。则hot_cold_file_area_tree_is_internal_node(slot)返回flase，然后执行slot->parent = node
		 *令索引是0的file_area的parent指向父节点。没有这样代码，该file_area就成没有父亲的孤儿了，后续释放tree就会有问题
		 */
		else if(slot == root->root_node && !hot_cold_file_area_tree_is_internal_node(slot))
			/*此时根节点root->root_node保存的是file_area指针，并不是hot_cold_file_area_tree_node指针，要强制转换成file_area指针并令其parent成员
			 *指向父节点。否则还是以hot_cold_file_area_tree_node->parent=node形式赋值，实际赋值到了file_area->file_area_age成员那里，内存越界了,
			 * 导致它很大!!这个else if只在tree由0层向1层增加时才成立，只会成立这一次，后续tree再增长高度，这里都不成立。此时slot=root->root_node
			 * 保存的file_area指针,bit1是0，不是internal_node.后续到这里slot都是internal_node，bit0是1。下边的赋值不能直接slot->parent = node; 
			 * 因为此时根节点root->root_node保存的是file_area指针，并不是hot_cold_file_area_tree_node指针，故要强制转换成file_area指针*/
			((struct file_area *)slot)->parent = node;

		node->slots[0] = slot;
		slot = node_to_entry(node);
		rcu_assign_pointer(root->root_node, slot);
		shift += TREE_MAP_SHIFT;
	}while (shift <= maxshift);
out:
	return maxshift + RADIX_TREE_MAP_SHIFT;    
}
//按照索引area_index从radix tree查找file_area
static struct hot_cold_file_area_tree_node *hot_cold_file_area_tree_lookup_and_create(struct hot_cold_file_area_tree_root *root,
		unsigned long area_index,void ***page_slot_in_tree)
{
	unsigned int shift, offset = 0;
	unsigned long max_area_index;
	struct hot_cold_file_area_tree_node *node = NULL, *child;
	void **slot = (void **)&root->root_node;
	int ret;
	
	//file_area_tree根节点，radix tree原本用的是rcu_dereference_raw，为什么?????????????需要研究下
	node = rcu_dereference_raw(root->root_node);

	//file_area_tree至少有一层，不是空的树
	if (likely(hot_cold_file_area_tree_is_internal_node(node))){
		/*此时的根节点node指针的bit0是1，表示是个节点，并不是真正的hot_cold_file_area_tree_node指针，此时node->shift永远错误是0。下边每次
		 *就有很大概率执行hot_cold_file_area_tree_extend()反复创建tree新的层数，即便对应的层数之前已经创建过了*/
		node = entry_to_node(node);
		//file_area_tree根节点的的shift+6
		shift = node->shift + TREE_MAP_SHIFT;
		max_area_index = hot_cold_file_area_tree_shift_maxindex(node->shift);
		/*这里要把node的bit0置1，否则下边child = node后，child的bit0是0，不再表示根节点，导致下边的while循环中直接走
		 *else if (!hot_cold_file_area_tree_is_internal_node(child))分支,这样每次都无法遍历tree，返回的*/
		node = node_to_entry(node);
	}
	else//到这里说明file_area_tree 是空的，没有根节点
	{
		shift = 0;
		max_area_index = 0;
	}
	//此时child指向根节点
	child = node;
	/*这里再赋值NULL是为了保证shift=0的场景，就是tree没有一个节点，只有索引是0的成员保存在root->root_node根节点，此时到这里shift是0，
	 *下边的while (shift > 0)不成立。此时该函数返回的父节点node应是NULL，因为返回的slot就指向根节点的root->root_node，它的父节点是NULL*/
	node = NULL;

	//当本次查找的file_area索引太大，file_area_tree树能容纳的最大file_area索引不能容纳本次要查找的file_area索引
	if(area_index > max_area_index){//file_area_tree 是空树时，这里不成立，二者都是0
		ret = hot_cold_file_area_tree_extend(root,area_index,shift);
		if (ret < 0)
			return ERR_PTR(ret);
		shift = ret;
		child = root->root_node;
	}

	//node是父节点，slot指向父节点node的某个槽位，这个槽位保存child这个节点指针 或者file_area_tree树最下层节点的file_area_tree指针
	while (shift > 0) {
		shift -= TREE_MAP_SHIFT;

		//当前遍历指向radix tree层数的节点是NULL则分配一个新的节点，这里的child肯定是file_area_tree的节点
		if (child == NULL) {
			/*在分配radix tree node前，是spin lock加了file_stat->file_stat_lock锁的，故这里分配内存禁止休眠，否则低内存场景就会占着spin锁休眠，
			 * 然后导致其他进程获取spin lock失败而soft lockup*/
			child = kmem_cache_alloc(hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep,GFP_ATOMIC);
			if (!child)
				return ERR_PTR(-ENOMEM);
			memset(child,0,sizeof(struct hot_cold_file_area_tree_node));

			child->shift = shift;
			child->offset = offset;
			child->parent = node;
			//slot指向child所在父节点的槽位，这里是把新分配的节点hot_cold_file_area_tree_node指针保存到父节点的槽位
			rcu_assign_pointer(*slot, node_to_entry(child));
			if (node)
				node->count++;//父节点的子成员树加1
		}
		//这里成立说明child不是file_area_tree的节点，而是树最下层的节点保存的数据
		else if (!hot_cold_file_area_tree_is_internal_node(child))
			break;

		node = entry_to_node(child);
		//根据area_index索引计算在父节点的槽位索引offset
		offset = (area_index >> node->shift) & TREE_MAP_MASK;
		//根据area_index索引计算在父节点的槽位索引offset，找到在父节点的槽位保存的数据，可能是子节点 或者 保存在file_area_tree树最下层节点的file_area指针
		child = rcu_dereference_raw(node->slots[offset]);
		//根据area_index索引计算在父节点的槽位索引offset，令slot指向在父节点的槽位
		slot = &node->slots[offset];
		//下轮循环，node= child 成为新的父节点。slot指向父节点node的某个槽位，这个槽位保存child这个节点指针 或者file_area_tree树最下层节点的file_area_tree指针
	}
	//page_slot_in_tree是3重指针，*page_slot_in_tree 和 slot 是2重指针，*page_slot_in_tree和slot才能彼此赋值。赋值后*page_slot_in_tree保存的是槽位的地址
	*page_slot_in_tree = slot;
	return node;
}
//按照索引area_index从radix tree查找file_area，查找失败则创建node节点
static struct hot_cold_file_area_tree_node *hot_cold_file_area_tree_lookup(struct hot_cold_file_area_tree_root *root,
		unsigned long area_index,void ***page_slot_in_tree)
{
	unsigned int /*shift, */offset = 0;
	unsigned long max_area_index;
	struct hot_cold_file_area_tree_node *node = NULL, *child;
	void **slot = (void **)&root->root_node;

	//file_area_tree根节点，radix tree原本用的是rcu_dereference_raw，为什么?????????????需要研究下
	node = rcu_dereference_raw(root->root_node);
	//file_area_tree至少有一层，不是空的树
	if (likely(hot_cold_file_area_tree_is_internal_node(node))){
		/*此时的根节点node指针的bit0是1，表示是个节点，并不是真正的hot_cold_file_area_tree_node指针，此时node->shift永远错误是0。下边每次
		 *就有很大概率执行hot_cold_file_area_tree_extend()反复创建tree新的层数，即便对应的层数之前已经创建过了*/
		node = entry_to_node(node);
		max_area_index = hot_cold_file_area_tree_shift_maxindex(node->shift);
		/*这里要把node的bit0置1，否则下边child = node后，child的bit0是0，不再表示根节点，导致下边的while循环中直接走
		 *else if (!hot_cold_file_area_tree_is_internal_node(child))分支,这样每次都无法遍历tree，返回的*/
		node = node_to_entry(node);
	}
	else//到这里说明file_area_tree 是空的，没有根节点
	{
		max_area_index = 0;
	}
	//此时child指向根节点
	child = node;
	/*这里再赋值NULL是为了保证file_area_tree没有一个节点的情况，只有索引是0的file_area指针保存在root->root_node根节点,
	 *下边的while不成立。此时该函数返回的父节点node应是NULL，因为返回的slot就指向根节点的root->root_node，它的父节点是NULL*/
	node = NULL;

	//当本次查找的file_area索引太大，file_area_tree树能容纳的最大file_area索引不能容纳本次要查找的file_area索引，直接返回NULL
	if(area_index > max_area_index){//file_area_tree 是空树时，这里不成立，二者都是0
		return NULL;
	}

	//node是父节点，slot指向父节点node的某个槽位，这个槽位保存child这个节点指针 或者file_area_tree树最下层节点的file_area_tree指针
	while (hot_cold_file_area_tree_is_internal_node(child)) {

		node = entry_to_node(child);
		//根据area_index索引计算在父节点的槽位索引offset
		offset = (area_index >> node->shift) & TREE_MAP_MASK;
		//根据area_index索引计算在父节点的槽位索引offset，找到在父节点的槽位保存的数据，可能是子节点 或者 保存在file_area_tree树最下层节点的file_area指针
		child = rcu_dereference_raw(node->slots[offset]);
		//根据area_index索引计算在父节点的槽位索引offset，令slot指向在父节点的槽位
		slot = &node->slots[offset];
		//下轮循环，node= child 成为新的父节点。slot指向父节点node的某个槽位，这个槽位保存child这个节点指针 或者file_area_tree树最下层节点的file_area_tree指针
	}
	/*page_slot_in_tree是3重指针，*page_slot_in_tree 和 slot 是2重指针，*page_slot_in_tree和slot才能彼此赋值。赋值后*page_slot_in_tree保存的是槽位的地址.
	 *到这里只有两种情况，1：找到area_index索引对应的file_area，*page_slot_in_tree指向这个file_area在radix tree的槽位。2：没有找到，则*page_slot_in_tree = slot
	 *赋值后，*page_slot_in_tree指向的槽位里的数据是NULL，这是肯定的*/
	*page_slot_in_tree = slot;
	return node;
}

//释放file_area结构，返回0说明释放成功，返回1说明file_area此时又被访问了，没有释放
static int cold_file_area_detele(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct file_area *p_file_area)
{
	struct hot_cold_file_area_tree_node *p_hot_cold_file_area_tree_node = p_file_area->parent;
	struct hot_cold_file_area_tree_node * p_hot_cold_file_area_tree_node_tmp;
	int file_area_index = p_file_area->start_index >>PAGE_COUNT_IN_AREA_SHIFT;
	//取出file_area在父节点的槽位号，这个计算方法是错误的，p_file_area->start_index是起始page的索引，不是file_area索引，这样会导致计算出的
	//槽位号slot_number是错误的，这样会导致错剔除其他的file_area
	//int slot_number = p_file_area->start_index & TREE_MAP_MASK;
	int slot_number = file_area_index & TREE_MAP_MASK;
	int i;
	int find = 0;

	/*这是在遍历file_stat->file_area_free链表上的file_area期间，如果file_area长时间没访问就要执行该函数释放掉file_stat结构。
	 *但是如果这个file_stat在p_file_stat->hot_file_area_cache数组，就要清理掉。但是如果此时有进程正执行hot_file_update_file_status()使用
	  这个file_area,就阻塞所有执行hot_file_update_file_status函数的进程退出后(由p_hot_cold_file_global.ref_count为0保证)，再释放掉file_area*/
	if(file_area_in_cache(p_file_area))
	{
		find = 0;
	    for( i = 0;i < FILE_AREA_CACHE_COUNT;i ++){
			/*存在一种可能得情况，先有hot_file_update_file_status()把p_file_stat->hot_file_area_cache[i] = NULL设置NULL，但是没有同步给
			 *异步内存回收线程所在cpu，导致这个if还是成立。但是这个file_area->file_area_age会被赋值global_age，下边直接return 1，不会释放这个file_area*/
			if(p_file_area == p_file_stat->hot_file_area_cache[i]){
				p_file_stat->hot_file_area_cache[i] = NULL;
				//加这个内存屏障，是保证其他进程看到file_area被清理了in cache状态状态后，p_file_stat->hot_file_area_cache[i] = NULL
				//这个赋值所有cpu也都同步给其他cpu了
				smp_wmb();
				//clear_file_area_in_cache(p_file_area);
				//置1表示从p_file_stat->hot_file_area_cache[i]找到本次要释放的file_area
				find = 1;
			}
		}
		/*file_area由in-cache状态，但是不一定在p_file_stat->hot_file_area_cache数组，因为hot_file_update_file_status()会根据
		 * p_file_stat->hot_file_area_cache_index 指引把它覆盖掉!因此，只要file_stat由in-cache状态，在删除前就清理掉*/
		clear_file_area_in_cache(p_file_area);
		smp_wmb();
        //释放的file_area但是处于hot_file_area_cache数组的file_area个数
        p_hot_cold_file_global->hot_cold_file_shrink_counter.file_area_delete_in_cache_count ++; 
	    /*等所有进程退出hot_file_update_file_status()函数，不再使用p_file_stat->hot_file_area_cache[i]里的file_area了再执行下边的释放file_area
		 *的代码。等新的进程再执行hot_file_update_file_status()函数使用，要先smp_rmb()，此时p_file_stat->hot_file_area_cache[i]=NULL就所有cpu
		  生效了。不用再担心p_file_stat->hot_file_area_cache[i] = NULL没有同步给其他cpu了*/
	    while(/*find &&*/ atomic_read(&p_hot_cold_file_global->ref_count))//退出条件用不用加上find，为了安全先不加吧
		    msleep(1);
	}


	//在释放file_area时，可能正有进程执行hot_file_update_file_status()遍历file_area_tree树中p_file_area指向的file_area结构，
	//这里又在释放file_area结构，因此需要加锁。
	spin_lock(&p_file_stat->file_stat_lock);
	//如果近期file_area被访问了
	if(hot_cold_file_global_info.global_age - p_file_area->file_area_age < 2 ){
		/*那就把它再移动回file_stat->file_area_temp链表头。有这个必要吗？没有必要的!因为该file_area是在file_stat->file_area_free链表上，如果
		  被访问了而执行hot_file_update_file_status()函数，会把这个file_area立即移动到file_stat->file_area_temp链表，这里就没有必要做了!!!!!*/

		spin_unlock(&p_file_stat->file_stat_lock);
		return 1;
	}
	/*该文件file_stat的file_area个数减1，这个过程已经加了锁。这个减1要放到这里，保证"仅有一个索引是0的file_area指针保存在根节点
	 * file_stat->hot_cold_file_area_tree_root_node.root_node"的file_area结构释放时，也能令file_stat总file_area个数减1*/
	p_file_stat->file_area_count --;

	/*这个if成立，说明当前hot file tree是空树，仅有一个索引是0的file_area指针保存在根节点file_stat->hot_cold_file_area_tree_root_node.root_node，
	  现在这个file_area被剔除了，仅仅把file_stat->hot_cold_file_area_tree_root_node.root_node设置成NULL即可，表示之后该
	  hot file tree一个file_area都没保存*/
	if(p_hot_cold_file_area_tree_node == NULL){
		list_del(&p_file_area->file_area_list);
		//此时也要把"仅有一个索引是0的file_area"结构体释放掉，否则就内存泄漏了
		kmem_cache_free(p_hot_cold_file_global->file_area_cachep,p_file_area);
		p_file_stat->hot_cold_file_area_tree_root_node.root_node = NULL;
		spin_unlock(&p_file_stat->file_stat_lock);
		return 1;
	}

	if(p_hot_cold_file_area_tree_node->slots[slot_number] != p_file_area)
		panic("%s p_hot_cold_file_area_tree_node->slots[%d]:0x%llx != p_file_area:0x%llx\n",__func__,slot_number,(u64)p_hot_cold_file_area_tree_node->slots[slot_number],(u64)p_file_area);
	//从file_area tree释放file_area结构，同时也要从file_area_list链表剔除，这个过程还要p_file_stat->file_stat_lock加锁
	list_del(&p_file_area->file_area_list);
	kmem_cache_free(p_hot_cold_file_global->file_area_cachep,p_file_area);

	p_hot_cold_file_area_tree_node->slots[slot_number] = NULL;
	p_hot_cold_file_area_tree_node->count --;//父节点的子成员数减1

	//如果 p_hot_cold_file_area_tree_node没有成员了，则释放p_hot_cold_file_area_tree_node节点，并且向上逐层没有成员的hot_cold_file_area_tree_node父节点
	while(p_hot_cold_file_area_tree_node->count == 0){
		//当前节点在父节点的槽位号
		slot_number = p_hot_cold_file_area_tree_node->offset;
		p_hot_cold_file_area_tree_node_tmp = p_hot_cold_file_area_tree_node;
		//获取父节点
		p_hot_cold_file_area_tree_node = p_hot_cold_file_area_tree_node->parent;
		kmem_cache_free(p_hot_cold_file_global->hot_cold_file_area_tree_node_cachep,p_hot_cold_file_area_tree_node_tmp);
		/*如果此时p_hot_cold_file_area_tree_node是NULL，说明上一部hot file tree只有一层，p_hot_cold_file_area_tree_node指向第一层的节点，
		 *而它的父节点即p_hot_cold_file_area_tree_node->parent就是NULL。此时if成立，并且hot file tree此时唯一的节点也释放了，是空树，
		 *则要设置file_stat->hot_cold_file_area_tree_root_node.root_node=NULL，表示一个成员都没有了*/
		if(p_hot_cold_file_area_tree_node == NULL){
			p_file_stat->hot_cold_file_area_tree_root_node.root_node = NULL;
			break;	    
		}
		//子节点在父节点对应槽位设置NULL
		p_hot_cold_file_area_tree_node->slots[slot_number] = NULL;
		//父节点的子成员数减1
		p_hot_cold_file_area_tree_node->count --;
	}
	spin_unlock(&p_file_stat->file_stat_lock);

	return 0;
}
//文件被释放后，强制释放该文件file_stat的file_area结构，是cold_file_area_detele()函数的快速版本
static unsigned int cold_file_area_detele_quick(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct file_area *p_file_area)
{
	struct hot_cold_file_area_tree_node *p_hot_cold_file_area_tree_node = p_file_area->parent;
	struct hot_cold_file_area_tree_node * p_hot_cold_file_area_tree_node_tmp;

	int file_area_index = p_file_area->start_index >>PAGE_COUNT_IN_AREA_SHIFT;
	int slot_number = file_area_index & TREE_MAP_MASK;

	/*该文件file_stat的file_area个数减1，这个过程已经加了锁。这个减1要放到这里，保证"仅有一个索引是0的file_area指针保存在根节点
	 *file_stat->hot_cold_file_area_tree_root_node.root_node"的file_area结构释放时，也能令file_stat总file_area个数减1*/
	p_file_stat->file_area_count --;

	/*这个if成立，说明当前hot file tree是空树，仅有一个索引是0的file_area指针保存在根节点file_stat->hot_cold_file_area_tree_root_node.root_node，
	  现在这个file_area被剔除了，仅仅把file_stat->hot_cold_file_area_tree_root_node.root_node设置成NULL即可，表示之后该hot file tree
	  一个file_area都没保存*/
	if(p_hot_cold_file_area_tree_node == NULL){
		list_del(&p_file_area->file_area_list);
		//此时也要把"仅有一个索引是0的file_area"结构体释放掉，否则就内存泄漏了
		kmem_cache_free(p_hot_cold_file_global->file_area_cachep,p_file_area);
		p_file_stat->hot_cold_file_area_tree_root_node.root_node = NULL;
		return 1;
	}

	if(p_hot_cold_file_area_tree_node->slots[slot_number] != p_file_area)
		panic("%s p_hot_cold_file_area_tree_node->slots[%d]:0x%llx != p_file_area:0x%llx\n",__func__,slot_number,(u64)p_hot_cold_file_area_tree_node->slots[slot_number],(u64)p_file_area);
	//从file_area tree释放file_area结构，同时也要从file_area_list链表剔除，这个过程还要p_file_stat->file_stat_lock加锁
	list_del(&p_file_area->file_area_list);
	kmem_cache_free(p_hot_cold_file_global->file_area_cachep,p_file_area);

	p_hot_cold_file_area_tree_node->slots[slot_number] = NULL;
	p_hot_cold_file_area_tree_node->count --;//父节点的子成员数减1

	//如果 p_hot_cold_file_area_tree_node没有成员了，则释放p_hot_cold_file_area_tree_node节点，并且向上逐层没有成员的hot_cold_file_area_tree_node父节点
	while(p_hot_cold_file_area_tree_node->count == 0){
		//当前节点在父节点的槽位号
		slot_number = p_hot_cold_file_area_tree_node->offset;
		p_hot_cold_file_area_tree_node_tmp = p_hot_cold_file_area_tree_node;
		//获取父节点
		p_hot_cold_file_area_tree_node = p_hot_cold_file_area_tree_node->parent;
		kmem_cache_free(p_hot_cold_file_global->hot_cold_file_area_tree_node_cachep,p_hot_cold_file_area_tree_node_tmp);
		/*如果此时p_hot_cold_file_area_tree_node是NULL，说明上一部hot file tree只有一层，p_hot_cold_file_area_tree_node指向第一层的节点，
		 *而它的父节点即p_hot_cold_file_area_tree_node->parent就是NULL。此时if成立，并且hot file tree此时唯一的节点也释放了，是空树，
		  则要设置file_stat->hot_cold_file_area_tree_root_node.root_node=NULL，表示一个成员都没有了*/
		if(p_hot_cold_file_area_tree_node == NULL){
			p_file_stat->hot_cold_file_area_tree_root_node.root_node = NULL;
			break;	    
		}
		//子节点在父节点对应槽位设置NULL
		p_hot_cold_file_area_tree_node->slots[slot_number] = NULL;
		//父节点的子成员数减1
		p_hot_cold_file_area_tree_node->count --;
	}

	return 0;
}
//异步内存回收线程把file_stat从p_hot_cold_file_global的链表中剔除，释放file_stat结构，释放前需要先lock_file_stat()防止其他进程并发访问file_stat
static void inline cold_file_stat_delete(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat_del)
{
	/*lock_file_stat加锁原因是:当异步内存回收线程在这里释放file_stat结构时，同一时间file_stat对应文件inode正在被释放而执行到
	 * __destroy_inode_handler_post()函数。如果这里把file_stat释放了，__destroy_inode_handler_post()使用file_stat就要crash。
	 * 而lock_file_stat()防止这种情况。同时，__destroy_inode_handler_post()执行后会立即释放inode和mapping，然后此时这里要用到
	 * p_file_stat->mapping->rh_reserved1，此时同样也会因file_stat已经释放而crash
	 * */
	lock_file_stat(p_file_stat_del,0);
	/*如果file_stat在__destroy_inode_handler_post中被释放了，file_stat一定有delete标记。否则没有delete标记，这里先标记file_stat的delete*/
	if(0 == file_stat_in_delete(p_file_stat_del)/*p_file_stat_del->mapping*/){
		//文件inode的mapping->rh_reserved1清0表示file_stat无效，这__destroy_inode_handler_post()删除inode时，发现inode的mapping->rh_reserved1是0就不再使用file_stat了，会crash
		p_file_stat_del->mapping->rh_reserved1 = 0;
		barrier();
		p_file_stat_del->mapping = NULL;
		smp_wmb();//在这个加个内存屏障，保证前后代码隔离开。即file_stat有delete标记后，inode->i_mapping->rh_reserved1一定是0，p_file_stat->mapping一定是NULL
		set_file_stat_in_delete(p_file_stat_del);
	}
	unlock_file_stat(p_file_stat_del);

	//如果有进程正在"hot_file_update_file_status()访问file_stat"，会用到file_stat，则这里先休眠等待它用完file_stat再释放file_stat，二者可能用的是同一个file_stat
	while(atomic_read(&hot_cold_file_global_info.ref_count)){
		msleep(1);
	}
	//如果有进程正在"删除inode"，会用到file_stat，则这里先休眠等待它用完file_stat再释放file_stat，二者可能用的是同一个file_stat
	while(atomic_read(&hot_cold_file_global_info.inode_del_count)){
		msleep(1);
	}

	//使用global_lock加锁是因为要把file_stat从p_hot_cold_file_global的链表中剔除，防止此时其他进程并发向p_hot_cold_file_global的链表添加file_stat
	spin_lock(&p_hot_cold_file_global->global_lock);
#if 0//这两个操作移动到上边的lock_file_stat里了，因为有 lock_file_stat 加锁防护
	//释放file_stat后，必须要把p_file_stat->mapping清NULL
	p_file_stat_del->mapping = NULL;
	//主动删除的file_stat也要标记delete，防止这个已经被释放file_stat在hot_file_update_file_status()里被再次使用，会因file_stat有delete标记而触发crash
	set_file_stat_in_delete(p_file_stat_del);
#endif	
	//从global的链表中剔除该file_stat，这个过程需要加锁，因为同时其他进程会执行hot_file_update_file_status()向global的链表添加新的文件file_stat
	list_del(&p_file_stat_del->hot_cold_file_list);
	//释放该file_stat结构
	kmem_cache_free(p_hot_cold_file_global->file_stat_cachep,p_file_stat_del);
	//file_stat个数减1
	hot_cold_file_global_info.file_stat_count --;
	spin_unlock(&p_hot_cold_file_global->global_lock);

	if(shrink_page_printk_open1)
	    printk("%s file_stat:0x%llx delete !!!!!!!!!!!!!!!!\n",__func__,(u64)p_file_stat_del);
}
//删除p_file_stat_del对应文件的file_stat上所有的file_area，已经对应hot file tree的所有节点hot_cold_file_area_tree_node结构。最后释放掉p_file_stat_del这个file_stat数据结构
static unsigned int cold_file_stat_delete_all_file_area(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat_del)
{
	//struct file_stat * p_file_stat,*p_file_stat_temp;
	struct file_area *p_file_area,*p_file_area_temp;
	unsigned int del_file_area_count = 0;
	//refault链表
	list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_refault,file_area_list){
		if(!file_area_in_refault_list(p_file_area) || file_area_in_refault_list_error(p_file_area))
			panic("%s file_area:0x%llx status:%d not in file_area_refault\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

		cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
		del_file_area_count ++;
	}
	//hot链表
	list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_hot,file_area_list){
		if(!file_area_in_hot_list(p_file_area) || file_area_in_hot_list_error(p_file_area))
			panic("%s file_area:0x%llx status:%d not in file_area_hot\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

		cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
		del_file_area_count ++;
	}
	//temp链表
	list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_temp,file_area_list){
		if(!file_area_in_temp_list(p_file_area) || file_area_in_temp_list_error(p_file_area))
			panic("%s file_area:0x%llx status:%d not in file_area_temp\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

		cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
		del_file_area_count ++;
	}
	//free链表
	list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_free,file_area_list){
		if(!file_area_in_free_list(p_file_area) || file_area_in_free_list_error(p_file_area))
			panic("%s file_area:0x%llx status:%d not in file_area_free\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

		cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
		del_file_area_count ++;
	}
	//free_temp链表
	list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_free_temp,file_area_list){
		if(!file_area_in_free_list(p_file_area) || file_area_in_free_list_error(p_file_area))
			panic("%s file_area:0x%llx status:%d not in file_area_free_temp\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

		cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
		del_file_area_count ++;
	}

	if(p_file_stat_del->file_area_count != 0){
		panic("file_stat_del:0x%llx file_area_count:%d !=0 !!!!!!!!\n",(u64)p_file_stat_del,p_file_stat_del->file_area_count);
	}

	//把file_stat从p_hot_cold_file_global的链表中剔除，然后释放file_stat结构
	cold_file_stat_delete(p_hot_cold_file_global,p_file_stat_del);

	return del_file_area_count;
}

//如果一个文件file_stat超过一定比例(比如50%)的file_area都是热的，则判定该文件file_stat是热文件，file_stat要移动到global file_stat_hot_head链表。返回1是热文件
static int is_file_stat_hot_file(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat){
	int ret;

	//如果文件file_stat的file_area个数比较少，则比例按照50%计算
	if(p_file_stat->file_area_count < p_hot_cold_file_global->file_area_count_for_large_file){
		//超过50%的file_area是热的，则判定文件file_stat是热文件
		//if(div64_u64((u64)p_file_stat->file_area_count*100,(u64)p_file_stat->file_area_hot_count) > 50)
		if(p_file_stat->file_area_hot_count > p_file_stat->file_area_count>>1)
			ret = 1;
		else
			ret = 0;
	}else{
		//否则，文件很大，则必须热file_area超过文件总file_area数的很多很多，才能判定是热文件。因为此时file_area很多，冷file_area的数目有很多，应该遍历回收这种file_area的page
		if(p_file_stat->file_area_hot_count > (p_file_stat->file_area_count - (p_file_stat->file_area_count >>2)))
			ret  = 1;
		else
			ret =  0;
	}
	return ret;
}
//当文件file_stat的file_area个数超过阀值则判定是大文件
static int inline is_file_stat_large_file(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat)
{
	if(p_file_stat->file_area_count > hot_cold_file_global_info.file_area_count_for_large_file)
		return 1;
	else
		return 0;
}
//模仿page_mapping()判断是否是page cache
static inline struct address_space * hot_cold_file_page_mapping(struct page *page)
{
	struct address_space *mapping;
	if (unlikely(PageSlab(page)) || unlikely(PageSwapCache(page)) || PageAnon(page) || page_mapped(page) || PageCompound(page))
		return NULL;

	mapping = page->mapping;
	if ((unsigned long)mapping & PAGE_MAPPING_ANON)
		return NULL;

	return (void *)((unsigned long)mapping & ~PAGE_MAPPING_FLAGS);
}
static void inline file_area_access_count_clear(struct file_area *p_file_area)
{
#if 0	
    file_area_access_count_clear(p_file_area); 
#else
	atomic_set(&p_file_area->access_count,0);
#endif	
}
static void inline file_area_access_count_add(struct file_area *p_file_area)
{
#if 0	
    file_area_access_count_add(p_file_area); 
#else
	atomic_inc(&p_file_area->access_count);
#endif	
}
static int inline file_area_access_count_get(struct file_area *p_file_area)
{
#if 0	
    return  p_file_area->access_count; 
#else
	return atomic_read(&p_file_area->access_count);
#endif	
}

static int hot_file_update_file_status(struct page *page)
{
	struct address_space *mapping;

	//mapping = page_mapping(page);-----这个针对swapcache也是返回非NULL，不能用
	mapping = hot_cold_file_page_mapping(page);
	if(mapping && mapping->host && mapping->host->i_sb)
	{
		/*这个NULL赋值，令page_slot_in_tree指向NULL，而如果hot_cold_file_area_tree_lookup()空树时对 *page_slot_in_tree 没有赋值，
		 *就会导致直接使用if(*page_slot_in_tree)因为page_slot_in_tree是NULL而crash*/
		void **page_slot_in_tree = NULL;
		//page所在的file_area的索引
		unsigned int area_index_for_page;
		struct hot_cold_file_area_tree_node *parent_node;
		int ret = 0;
		struct file_stat * p_file_stat = NULL;
		struct file_area *p_file_area = NULL; 
		int i;

		//async_memory_reclaim_status不再使用smp_rmb内存屏障，而直接使用test_and_set_bit_lock/clear_bit_unlock原子操作
		if(!test_bit(ASYNC_MEMORY_RECLAIM_ENABLE,&async_memory_reclaim_status))
			return 0;

		atomic_inc(&hot_cold_file_global_info.ref_count);
		/*1:与 __destroy_inode_handler_post()函数mapping->rh_reserved1清0的smp_wmb()成对，获取最新的mapping->rh_reserved1数据.
		 *2:还有一个作用，上边的ref_count原子变量加1可能不能禁止编译器重排序，因此这个内存屏障可以防止reorder*/
		smp_rmb();

		/*还要再判断一次async_memory_reclaim_status是否是0，因为驱动卸载会先获取原子变量ref_count的值0，然后这里再执行
		 *atomic_inc(&hot_cold_file_global_info.ref_count)令ref_count加1.这种情况必须判断async_memory_reclaim_status是0，
		 *直接return返回。否则驱动卸载过程会释放掉file_stat结构，然后该函数再使用这个file_stat结构，触发crash*/
		if(!test_bit(ASYNC_MEMORY_RECLAIM_ENABLE,&async_memory_reclaim_status))
			goto out;
        
		//smp_rmb();这个内存屏障移动到前边
		//如果两个进程同时访问同一个文件的page0和page1，这就就有问题了，因为这个if会同时成立。然后下边针对
		if(mapping->rh_reserved1 == 0 ){

			if(!hot_cold_file_global_info.file_stat_cachep || !hot_cold_file_global_info.file_area_cachep){
				ret =  -ENOMEM;
				goto out;
			}

			/*这里有个问题，hot_cold_file_global_info.global_lock有个全局大锁，每个进程执行到这里就会获取到。合理的是
			  应该用每个文件自己的spin lock锁!比如file_stat里的spin lock锁，但是在这里，每个文件的file_stat结构还没分配!!!!!!!!!!!!*/
			spin_lock(&hot_cold_file_global_info.global_lock);
			//如果两个进程同时访问一个文件，同时执行到这里，需要加锁。第1个进程加锁成功后，分配file_stat并赋值给
			//mapping->file_stat，第2个进程获取锁后执行到这里mapping->file_stat就会成立
			if(mapping->rh_reserved1){
				spin_unlock(&hot_cold_file_global_info.global_lock);
				goto already_alloc;  
			}
			//新的文件分配file_stat,一个文件一个，保存文件热点区域访问数据
			p_file_stat = kmem_cache_alloc(hot_cold_file_global_info.file_stat_cachep,GFP_ATOMIC);
			if (!p_file_stat) {
				spin_unlock(&hot_cold_file_global_info.global_lock);
				printk("%s file_stat alloc fail\n",__func__);
				ret =  -ENOMEM;
				goto out;
			}
			//file_stat个数加1
			hot_cold_file_global_info.file_stat_count++;

			memset(p_file_stat,0,sizeof(struct file_stat));
			//初始化file_area_hot头结点
			INIT_LIST_HEAD(&p_file_stat->file_area_hot);
			INIT_LIST_HEAD(&p_file_stat->file_area_temp);
			//INIT_LIST_HEAD(&p_file_stat->file_area_cold);
			INIT_LIST_HEAD(&p_file_stat->file_area_free_temp);
			INIT_LIST_HEAD(&p_file_stat->file_area_free);
			INIT_LIST_HEAD(&p_file_stat->file_area_refault);

			//mapping->file_stat记录该文件绑定的file_stat结构，将来判定是否对该文件分配了file_stat
			mapping->rh_reserved1 = (unsigned long)p_file_stat;
			//file_stat记录mapping结构
			p_file_stat->mapping = mapping;
			//把针对该文件分配的file_stat结构添加到hot_cold_file_global_info的file_stat_temp_head链表
			list_add(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.file_stat_temp_head);
			//新分配的file_stat必须设置in_file_stat_temp_head_list链表
			set_file_stat_in_file_stat_temp_head_list(p_file_stat);
			spin_lock_init(&p_file_stat->file_stat_lock);

			spin_unlock(&hot_cold_file_global_info.global_lock);
		}

already_alloc:	    
		//根据page索引找到所在的file_area的索引，二者关系默认是 file_area的索引 = page索引/6
		area_index_for_page =  page->index >> PAGE_COUNT_IN_AREA_SHIFT;

		p_file_stat = (struct file_stat *)mapping->rh_reserved1;
		//如果mapping->rh_reserved1被其他代码使用，直接返回错误
		if(p_file_stat == NULL || p_file_stat->mapping != mapping){
			printk("%s p_file_stat:0x%llx error or p_file_stat->mapping != mapping\n",__func__,(u64)p_file_stat);
			goto out;
		}
		//如果当前正在使用的file_stat的inode已经释放了，主动触发crash 
		if(file_stat_in_delete(p_file_stat)){
			panic("%s %s %d file_stat:0x%llx status:0x%lx in delete\n",__func__,current->comm,current->pid,(u64)p_file_stat,p_file_stat->file_stat_status);
		}

		//每个周期执行hot_file_update_file_status函数访问所有文件的所有file_area总次数
        hot_cold_file_global_info.hot_cold_file_shrink_counter.all_file_area_access_count ++;

		/*先根据索引area_index_for_page从p_file_stat->hot_file_area_cache[]这个缓存buf中找到file_area，这样避免下边file_stat_lock加锁、radix tree遍历
		 *等操作。但是要注意，存在这种情况，a进程正在下边的for循环查找p_file_stat->hot_file_area_cache数组，b进程在这个for循环下边，把热file_area赋值
		 *给p_file_stat->hot_file_area_cache数组，存在这种并发。但是没关系，只要不是把这个数组里的file_area结构释放掉就没事，因为成无效内存访问了*/
		for(i = 0;i < FILE_AREA_CACHE_COUNT;i ++){
			p_file_area = p_file_stat->hot_file_area_cache[i];
			//file_area的起始page索引与file_stat->hot_file_area_cache数组的file_area起始page索引相等
		    if(p_file_area)
			{
				if(file_area_in_hot_list(p_file_area))
				{
					//从p_file_stat->hot_file_area_cache数组找到匹配的file_area，简单操作后就返回，避免下边file_stat_lock加锁，radix tree遍历等
				    if((area_index_for_page == p_file_area->start_index >> PAGE_COUNT_IN_AREA_SHIFT))
					{
						if(p_file_area->file_area_age < hot_cold_file_global_info.global_age){
							p_file_area->file_area_age = hot_cold_file_global_info.global_age;
							if(p_file_area->file_area_age > p_file_stat->max_file_area_age)
								p_file_stat->max_file_area_age = p_file_area->file_area_age;

							file_area_access_count_clear(p_file_area);
						}
						/*从p_file_stat->hot_file_area_cache[i]得到热file_area，只是令access_count加1，而没有令file_area移动到file_stat->file_area_hot
						 *链表头，因为要file_stat->file_stat_lock加锁。这样的话，如果file_area处于file_stat->file_area_hot链表尾，这个链表尾的file_area
						  正是最近访问过的。异步内存回收线程要做改进，在从file_stat->file_area_hot链表尾遍历file_area时,遍历到热file_area，不能立即
						  停止遍历，继续向前遍历file_area。因为可能只是偶发的干扰热file_area，如果连续遇到多个热file_area，再结束遍历从
						  file_stat->file_area_hot链表尾遍历file_area*/
						file_area_access_count_add(p_file_area);
						//从hot_file_area_cache命中file_area次数
                        hot_cold_file_global_info.hot_cold_file_shrink_counter.file_area_cache_hit_count ++;
						goto out;
					}
				}
				//p_file_stat->hot_file_area_cache[i]位置的file_stat不再是热的，说明启动到其他链表了，直接赋值NULL
				else
				{
				    p_file_stat->hot_file_area_cache[i] = NULL;
					//加这个内存屏障，是保证其他进程看到file_area被清理了in cache状态状态后，p_file_stat->hot_file_area_cache[i] = NULL
					//这个赋值所有cpu也都同步给其他cpu了
					smp_wmb();
					clear_file_area_in_cache(p_file_area);
					smp_wmb();
				}
			}
		}

		/*按照本次的要查找的file_area索引area_index_for_page，从file_area_tree查找。如果查找成功，则page_slot_in_tree指向保存file_area的
		 * 槽位，*page_slot_in_tree就是保存在这个槽位的file_area指针。这个过程不用file_stat->file_stat_lock加锁。首先是当进程执行到这里时
		 * hot_cold_file_global_info.ref_count原子变量大于0，cold_file_area_detele()中无法删除释放file_area_tree的node节点，不用担心这里遍历
		 * file_area_tree使用某个node节点时，这个node节点被释放了。其次，另一个并发场景是，此时另一个进程正执行下边的hot_cold_file_area_tree_lookup_and_create
		 * 函数，针对当前的area_index_for_page索引创建这个tree需要的节点node。这样也没事，此时hot_cold_file_area_tree_lookup()查找结果就
		 * 两个，查找成功*page_slot_in_tree则是file_area指针;查找失败则*page_slot_in_tree是NULL,此时只能再执行下边的hot_cold_file_area_tree_lookup_and_create
		 * 查找并创建tree，此时有了file_stat->file_stat_lock加锁，不用担心并发问题*/

		//*page_slot_in_tree = NULL;这个赋值会立即crash，因为page_slot_in_tree默认是NULL
		parent_node = hot_cold_file_area_tree_lookup(&p_file_stat->hot_cold_file_area_tree_root_node,area_index_for_page,&page_slot_in_tree);
		
		/*page_slot_in_tree默认值是NULL，而如果hot_cold_file_area_tree_lookup()空树时对 *page_slot_in_tree 没有赋值，
		 *就会导致直接使用if(*page_slot_in_tree)因为page_slot_in_tree是NULL而crash。此时只能靠返回值NULL过滤掉*/
		if(parent_node){
			if(*page_slot_in_tree){
				p_file_area = *page_slot_in_tree;
				if(p_file_area->start_index != (area_index_for_page << PAGE_COUNT_IN_AREA_SHIFT))
					panic("1:p_file_area->start_index:%ld != area_index_for_page:%d\n",p_file_area->start_index,(area_index_for_page << PAGE_COUNT_IN_AREA_SHIFT));
				
				/*hot_cold_file_global_info.global_age更新了，把最新的global age更新到本次访问的file_area->file_area_age。并对
				 * file_area->access_count清0，本周期被访问1次则加1.这段代码不管理会并发，只是一个赋值*/
				if(p_file_area->file_area_age < hot_cold_file_global_info.global_age){
					p_file_area->file_area_age = hot_cold_file_global_info.global_age;
					if(p_file_area->file_area_age > p_file_stat->max_file_area_age)
						p_file_stat->max_file_area_age = p_file_area->file_area_age;

					//file_area访问计数清0
					file_area_access_count_clear(p_file_area);
				}
				//file_area访问的次数加1，是原子操作，不用担心并发
				file_area_access_count_add(p_file_area);

				/*只有以下几种情况，才会执行下边spin_lock(&p_file_stat->file_stat_lock)里的代码
				  1：不管file_area处于哪个file_stat的哪个链表，只要是每个周期第2次访问，就要移动到所处file_stat->file_area_temp、file_area_hot、
					 file_area_refault、file_area_free_temp、file_area_free 链表头
				  2: file_area处于 tmemp链表，但是单个周期内访问计数大于热file_area阀值，要晋级为热file_area
				  3：file_area处于in-free-list 链表，要晋级到refault链表
				*/
				if(!(file_area_access_count_get(p_file_area) == 2 || 
				  (file_stat_in_file_stat_temp_head_list(p_file_stat) && file_area_access_count_get(p_file_area) > FILE_AREA_HOT_LEVEL) ||
				   file_area_in_free_list(p_file_area)))
				{
					//每个周期直接从file_area_tree找到file_area并且不用加锁次数加1
					hot_cold_file_global_info.hot_cold_file_shrink_counter.find_file_area_from_tree_not_lock_count ++;
					goto out;
				}
			}
		}

		spin_lock(&p_file_stat->file_stat_lock);
		//p_file_area不为NULL说明在上边已经找到file_area了,就不用再执行if里边代码了
		if(p_file_area == NULL){
			/*根据page索引的file_area的索引，找到对应在file area tree树的槽位，page_slot_in_tree双重指针指向这个槽位。
			  下边分配真正的file_area结构，把file_area指针保存到这个操作*/
			parent_node = hot_cold_file_area_tree_lookup_and_create(&p_file_stat->hot_cold_file_area_tree_root_node,area_index_for_page,&page_slot_in_tree);
			if(IS_ERR(parent_node)){
				spin_unlock(&p_file_stat->file_stat_lock);
				printk("%s hot_cold_file_area_tree_lookup_and_create fail\n",__func__);
				goto out;
			}
			/*两个进程并发执行该函数时，进程1获取file_stat_lock锁成功，执行file_area_tree_insert()查找page绑定的file_area的
			  在file_area_tree的槽位，*page_slot_in_tree 是NULL，然后对它赋值。进程2获取file_stat_lock锁后，*page_slot_in_tree就不是NULL了*/
			if(*page_slot_in_tree == NULL){
				/*到这里，针对当前page索引的file_area结构还没有分配,page_slot_in_tree是槽位地址，*page_slot_in_tree是槽位里的数据，就是file_area指针，
				  但是NULL，于是针对本次page索引，分配file_area结构*/
				p_file_area = kmem_cache_alloc(hot_cold_file_global_info.file_area_cachep,GFP_ATOMIC);
				if (!p_file_area) {
					spin_unlock(&p_file_stat->file_stat_lock);
					printk("%s file_area alloc fail\n",__func__);
					ret =  -ENOMEM;
					goto out;
				}
				memset(p_file_area,0,sizeof(struct file_area));
				//把根据page索引分配的file_area结构指针保存到file area tree指定的槽位
				rcu_assign_pointer(*page_slot_in_tree,p_file_area);

				//把新分配的file_area添加到file_area_temp链表
				list_add(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				//保存该file_area对应的起始page索引，一个file_area默认包含8个索引挨着依次增大page，start_index保存其中第一个page的索引
				p_file_area->start_index = area_index_for_page << PAGE_COUNT_IN_AREA_SHIFT;//area_index_for_page * PAGE_COUNT_IN_AREA;
				//新分配的file_area指向其在file_area_tree的父节点node
				p_file_area->parent = parent_node;
				//如果第一次把索引是0的file_area插入file_area tree，是把该file_area指针保存到file_area tree的根节点，此时parent_node是NULL
				if(parent_node)
					parent_node->count ++;//父节点下的file_area个数加1

				p_file_stat->file_area_count ++;//文件file_stat的file_area个数加1
				set_file_area_in_temp_list(p_file_area);//新分配的file_area必须设置in_temp_list链表
			}
			p_file_area = *page_slot_in_tree;
			if(p_file_area->start_index != (area_index_for_page << PAGE_COUNT_IN_AREA_SHIFT))
			    panic("2:p_file_area->start_index:%ld != area_index_for_page:%d\n",p_file_area->start_index,(area_index_for_page << PAGE_COUNT_IN_AREA_SHIFT));
			
			//hot_cold_file_global_info.global_age更新了，把最新的global age更新到本次访问的file_area->file_area_age。并对file_area->access_count清0，本周期被访问1次则加1
			if(p_file_area->file_area_age < hot_cold_file_global_info.global_age){
				p_file_area->file_area_age = hot_cold_file_global_info.global_age;
				if(p_file_area->file_area_age > p_file_stat->max_file_area_age)
					p_file_stat->max_file_area_age = p_file_area->file_area_age;
                //file_area访问计数清0
				file_area_access_count_clear(p_file_area);
			}
			//file_area的访问的次数加1
			file_area_access_count_add(p_file_area);
		}
		
	   /*如果file_area在当前周期第2次被访问，则把移动到file_stat->file_area_temp、file_area_hot、file_area_refault等链表头，该链表头的file_area
		*访问比较频繁，链表尾的file_area很少访问。将来walk_throuth_all_file_area()内存回收时，直接从这些链表尾遍历file_area即可，链表尾的都是冷
		 file_area。随之而来一个难题就是，file_area每个周期第几次被访问移动到链表头呢？最开始是1，现在改成每个周期第2次被访问再移动到链表头了。
		 因为可能有不少file_area一个周期就访问一次，就移动到链表头，性能损耗比较大，因为这个过程要spin_lock加锁。这样的话就又有一个新的问题，
		 如果file_area不是第一次访问就移动到链表头，那链表尾的file_area就不全是冷file_area了。因为链表头掺杂着最近刚访问但是只访问了一次的file_area，
		 这是热file_area！针对这个问题的解决方法是，在异步内存回收线程依次执行get_file_area_from_file_stat_list、free_page_from_file_area、
		 walk_throuth_all_file_area函数，从file_stat->file_area_temp、file_area_hot、file_area_refault链表尾遍历file_area时，发现了热file_area，即
		 file_area的age接近global age，但是file_area的访问次数是1，那还要继续遍历链表，直到连续遇到3~5个热file_area时，才能说明这个链表没冷file_area
		 了，再结束遍历。*/
		if(file_area_access_count_get(p_file_area) == 2)
		{
			/*如果p_file_area不在file_area_hot或file_area_temp链表头，才把它添加到file_area_hot或file_area_temp链表头
			  file_stat的file_area_hot或file_area_temp链表头的file_area是最频繁访问的，链表尾的file_area访问频次低，内存回收光顾这些链表尾的file_area*/

			if(file_area_in_temp_list(p_file_area)){
				if(!list_is_first(&p_file_area->file_area_list,&p_file_stat->file_area_temp))
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
			}else if(file_area_in_hot_list(p_file_area)){
				if(!list_is_first(&p_file_area->file_area_list,&p_file_stat->file_area_hot))
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_hot);
			}else if(file_area_in_refault_list(p_file_area)){//在refault链表的file_area如果被访问了也移动到链表头
				if(!list_is_first(&p_file_area->file_area_list,&p_file_stat->file_area_refault))
				    list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
			}
		}
		/*如果file_area处于in_free_list链表，第1次访问就移动到链表头。因为这种file_area可能被判定为refault file_araa，精度要求高*/
		else if(file_area_access_count_get(p_file_area) == 1 && file_area_in_free_list(p_file_area))
		{
			if(file_stat_in_free_page(p_file_stat)){//file_stat是in_free_page状态且file_area在file_stat->file_area_free_temp链表
				if(!list_is_first(&p_file_area->file_area_list,&p_file_stat->file_area_free_temp))
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_free_temp);
			}else if(file_stat_in_free_page_done(p_file_stat)){//file_stat是in_free_page_done状态且file_area在file_stat->file_area_free链表
				if(!list_is_first(&p_file_area->file_area_list,&p_file_stat->file_area_free))
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_free);
			}
			else{
				/*这个else分支可能成立，file_area是in_free_list状态，file_area内存后移动到file_stat->file_area_free链表。如果长时间再不被
				  访问，那就释放掉file_area。此时file_stat会移动到global file_stat_temp_head链表，file_stat是in temp_list状态。当这个file_area
				  此时被访问，这个else分支就会成立*/
				//panic("%s file_stat:0x%llx status:%d file_area:0x%llx status:%d error\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status,(u64)p_file_area,p_file_area->file_area_state);
			}
		}

        /*如果file_stat的file_area正处于正释放page状态，此时异步内存回收线程会遍历file_stat->file_area_temp、file_area_hot、file_area_refault、
		 * file_area_free_temp、file_area_free 链表上的file_area。此时禁止hot_file_update_file_status()函数里将file_stat这些链表上的file_area
		 * 跨链表移动。为什么？比如异步内存回收线程正遍历file_stat->file_area_free_temp 链表上的file_area1，但是hot_file_update_file_status()
		 * 函数里因为这个file_area1被访问了，而把file_area1移动到了file_stat->file_area_refault链表头。然后异步内存回收线程与得到
		 * file_area1在file_stat->file_area_free_temp链表的上一个file_area，此时得到到确是file_stat->file_area_refault链表头。相当于中途从
		 * file_stat->file_area_free_temp链表跳到了file_stat->file_area_refault链表，遍历file_area。这样遍历链表将陷入死循环，因为这个循环的
		 * 退出条件是遍历到最初的file_stat->file_area_free_temp链表头，但是现在只会遍历到file_stat->file_area_refault链表头，永远退不出循环。
		 * 这种现象这里称为"遍历的链表成员被移动到其他链表，因为链表头变了导致的遍历陷入死循环"*/
        if(0 == file_stat_in_free_page(p_file_stat) && 0 == file_stat_in_free_page_done(p_file_stat))
        //if(file_stat_in_file_stat_temp_head_list(p_file_stat))//这个与file_stat_in_free_page(p_file_stat) == 0效果一致
		{
			//如果p_file_area是冷热不定的，并且file_area的本轮访问次数大于阀值，则设置file_area热，并且把该file_area移动到file_area_hot链表
			if(file_area_in_temp_list(p_file_area) &&  
					//p_file_area->access_count - p_file_area->last_access_count >= FILE_AREA_HOT_LEVEL){
					file_area_access_count_get(p_file_area) > FILE_AREA_HOT_LEVEL){

					clear_file_area_in_temp_list(p_file_area);
					//设置file_area 处于 file_area_hot链表
					set_file_area_in_hot_list(p_file_area);
					//把file_area移动到file_area_hot链表头，将来这些file_area很少访问了，还会再降级移动回file_area_temp链表头
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_hot);
					//一个周期内产生的热file_area个数
					hot_cold_file_global_info.hot_cold_file_shrink_counter.hot_file_area_count_one_period ++;
					//该文件的热file_stat数加1
					p_file_stat->file_area_hot_count ++;

					/*热file_area保存到file_stat->hot_file_area_cache数组，作为缓存。在free_page_from_file_area()函数最后也会把频繁访问的
					 * file_stat->file_area_temp链表上的file_area移动到file_stat->file_area_hot链表。这个概率很低，先不加了*/
					if(p_file_stat->hot_file_area_cache_index >= FILE_AREA_CACHE_COUNT)
					    panic("%s file_stat:0x%llx hot_file_area_cache_index:%d error\n",__func__,(u64)p_file_stat,p_file_stat->hot_file_area_cache_index);
					/*这里直接根据p_file_stat->hot_file_area_cache_index指针，把新的file_area赋值给p_file_stat->hot_file_area_cache[]，但是这个
					 *数组位置可能原本就保存了一个热file_area，这就导致这个老的file_area被异常覆盖了，但是这个老的file_stat还保留着file_stat状态。那就
					  清理掉老的file_stat的in-cache状态？是否与cold_file_area_detele()释放file_area有并发风险,no!二者都file_stat->file_stat_lock加锁了*/
					if(p_file_stat->hot_file_area_cache[p_file_stat->hot_file_area_cache_index]){
						clear_file_area_in_cache(p_file_stat->hot_file_area_cache[p_file_stat->hot_file_area_cache_index]);
						p_file_stat->hot_file_area_cache[p_file_stat->hot_file_area_cache_index] = NULL;
                    }
					p_file_stat->hot_file_area_cache[p_file_stat->hot_file_area_cache_index] = p_file_area;
				    set_file_area_in_cache(p_file_area);
					//p_file_stat->hot_file_area_cache_index是否有必要做成原子变量，不用，这里加锁了file_stat->file_stat_lock锁，阻断了并发
					if(++ p_file_stat->hot_file_area_cache_index > FILE_AREA_CACHE_COUNT - 1)
						p_file_stat->hot_file_area_cache_index = 0;
			}

			//如果file_area处于file_stat的free_list或free_temp_list链表
			if(file_area_in_free_list(p_file_area)){
				if(file_area_in_free_list(p_file_area))
					clear_file_area_in_free_list(p_file_area);

				//file_area 的page被内存回收后，过了仅1s左右就又被访问则发生了refault，把该file_area移动到file_area_refault链表，不再参与内存回收扫描!!!!需要设个保护期限制
				smp_rmb();
				if(p_file_area->shrink_time && (ktime_to_ms(ktime_get()) - (p_file_area->shrink_time << 10) < 1000)){
					p_file_area->shrink_time = 0;
					set_file_area_in_refault_list(p_file_area);
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
					//一个周期内产生的refault file_area个数
					hot_cold_file_global_info.hot_cold_file_shrink_counter.refault_file_area_count_one_period ++;
				}else{
					p_file_area->shrink_time = 0;
					//file_area此时正在被内存回收而移动到了file_stat的free_list或free_temp_list链表，则直接移动到file_stat->file_area_temp链表头
					set_file_area_in_temp_list(p_file_area);
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				}
			}
			/*如果file_area处于file_area链表，但是p_file_area->shrink_time不是0.这说明该file_area在之前walk_throuth_all_file_area()函数中扫描
			  判定该file_area是冷的，然后回收内存page。但是回收内存时，正好这个file_area又被访问了，则把file_area移动到file_stat->file_area_temp
			  链表。但是内存回收流程执行到cold_file_isolate_lru_pages()函数因并发问题没发现该file_area最近被访问了，只能继续回收该file_area的page。
			  需要避免回收这种热file_area的page。于是等该file_area下次被访问，执行到这里，if成立，把该file_area移动到file_stat->file_area_refault
			  链表。这样未来一段较长时间可以避免再次回收该file_area的page。具体详情看cold_file_isolate_lru_pages()函数里的注释*/
			if(file_area_in_temp_list(p_file_area) && (p_file_area->shrink_time != 0)){//这个if现在应该成立不了了??????
				p_file_area->shrink_time = 0;
				clear_file_area_in_temp_list(p_file_area);
				set_file_area_in_refault_list(p_file_area);
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
				//一个周期内产生的refault file_area个数
				hot_cold_file_global_info.hot_cold_file_shrink_counter.refault_file_area_count_one_period ++;
			}
		}
		else
		{
			//file_area内存回收期间file_area被访问的次数
		    hot_cold_file_global_info.hot_cold_file_shrink_counter.file_area_access_count_in_free_page ++;
		}

		spin_unlock(&p_file_stat->file_stat_lock);

		/*下边两段代码:把file_stat移动到file_stat_hot_head或file_stat_temp_large_file_head链表的代码可以考虑移动到
		 *get_file_area_from_file_stat_list()函数开头遍历file_stat的for循环里以降低这里使用spin lock的性能损耗*/

		/*如果文件file_stat的file_area很多都是热的，判定file_stat是热文件，则把file_stat移动到global file_stat_hot_head链表，
		  global file_stat_hot_head链表上的file_stat不再扫描上边的file_area，有没有必要这样做??????????????????????*/
		if(file_stat_in_file_stat_temp_head_list(p_file_stat) && is_file_stat_hot_file(&hot_cold_file_global_info,p_file_stat)){
		  /*外层有spin_lock(&p_file_stat->file_stat_lock)，这里不应该再关中断，只能spin_lock加锁
			这个spin lock加锁可以移动到get_file_area_from_file_stat_list()函数开头遍历file_stat的for循环里，判断出热文件则把file_stat
			移动到hot_cold_file_global_info.file_stat_hot_head链表，否则在这个函数，可能频繁spin lock加锁而导致性能损失!!!!!!!!!!*/
			spin_lock(&hot_cold_file_global_info.global_lock);

		  /*加锁成功后要再判断一次file_stat是否还处于global temp_head链表。为什么?因为可能其他进程可能并发执行了该函数，先获取了
		   * global_lock锁，然后把file_stat移动到hot_head热文件链表。然后当前进程获取global_lock锁后，file_stat已经不再处于
		   * global temp_head链表了。并且，异步内存回收线程可能也会并发修改改file_stat的状态，因为凡是修改file_stat状态的地方，
		   * 再获取global_lock锁成功后，都要再判断一次file_stat的状态
		   * */
			if(file_stat_in_file_stat_temp_head_list(p_file_stat)){
				hot_cold_file_global_info.file_stat_hot_count ++;//热文件数加1
				clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
				//设置file_stat处于热文件链表
				set_file_stat_in_file_stat_hot_head_list(p_file_stat);
				//把file_stat移动到热文件链表
				list_move(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.file_stat_hot_head);
			}
			spin_unlock(&hot_cold_file_global_info.global_lock);
		}
		/*文件file_stat的file_area个数大于阀值则移动到global file_stat_hot_head_large_file_temp链表
		  file_stat必须处于global temp_head_list链表，不能处于其他链表，比如global file_stat_hot_head链表*/
		else if(file_stat_in_file_stat_temp_head_list(p_file_stat) && !file_stat_in_large_file(p_file_stat) && 
				is_file_stat_large_file(&hot_cold_file_global_info,p_file_stat)){

				spin_lock(&hot_cold_file_global_info.global_lock);
			  /*加锁成功后要再判断一次file_stat是否还处于global temp_head链表。为什么?因为可能其他进程可能并发执行了该函数，先获取了global_lock锁，
				然后把file_stat移动到hot_head热文件链表。然后当前进程获取global_lock锁后，file_stat已经不再处于global temp_head链表了。并且，异步内存
				回收线程可能也会并发修改改file_stat的状态，因为凡是修改file_stat状态的地方，再获取global_lock锁成功后，都要再判断一次file_stat的状态*/
				if(file_stat_in_file_stat_temp_head_list(p_file_stat)){
					//设置file_stat是大文件
					set_file_stat_in_large_file(p_file_stat);
					//file_stat移动到大文件链表
					list_move(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.file_stat_temp_large_file_head);
					hot_cold_file_global_info.file_stat_large_count ++;
				}
				spin_unlock(&hot_cold_file_global_info.global_lock);
		}


		if(p_file_area->file_area_age > hot_cold_file_global_info.global_age)
			panic("p_file_area->file_area_age:%ld > hot_cold_file_global_info.global_age:%ld\n",p_file_area->file_area_age,hot_cold_file_global_info.global_age);

out:
		//这个原子操作目前看没必要防止重排序
		atomic_dec(&hot_cold_file_global_info.ref_count);
		/*不能因为走了err分支，就释放p_file_stat和p_file_area结构。二者都已经添加到ot_file_global_info.file_stat_hot_head 或 
		 * p_file_stat->file_area_temp链表，不能释放二者的数据结构。是这样吗，得再考虑一下?????????????*/
		if(p_file_stat){
			//kmem_cache_free(hot_cold_file_global_info.file_stat_cachep,p_file_stat);
		}
		if(p_file_area){
			//kmem_cache_free(hot_cold_file_global_info.file_area_cachep,p_file_area);
		}
		return ret;
	}

    return 0;
}

static unsigned long cold_file_shrink_pages(struct hot_cold_file_global *p_hot_cold_file_global)
{
	int i;
	unsigned long nr_reclaimed = 0;
	struct reclaim_stat stat = {};

	struct scan_control_async sc = {
		.gfp_mask = GFP_KERNEL,
		.order = 1,
		.priority = DEF_PRIORITY,
		.may_writepage = 1,
		.may_unmap = 0,
		.may_swap = 0,
		.reclaim_idx = MAX_NR_ZONES - 1,
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,18,0)
		.no_demotion = 1,//高版本内核多了一个no_demotion
#endif
	};

	struct hot_cold_file_node_pgdat *p_hot_cold_file_node_pgdat = p_hot_cold_file_global->p_hot_cold_file_node_pgdat;
	//遍历每个内存节点上p_hot_cold_file_node_pgdat[i]->pgdat_page_list 上的page，释放它，
	for(i = 0;i < hot_cold_file_global_info.node_count;i ++){
		struct list_head *p_pgdat_page_list = &p_hot_cold_file_node_pgdat[i].pgdat_page_list;

		if(!list_empty(p_pgdat_page_list)){
			//开始释放p_hot_cold_file_node_pgdat[i]->pgdat_page_list链表上的page
			nr_reclaimed += async_shrink_free_page(p_hot_cold_file_node_pgdat[i].pgdat,NULL,p_pgdat_page_list,&sc,&stat);
			//把p_hot_cold_file_node_pgdat[i]->pgdat_page_list链表上未释放成功的page再移动到lru链表
			hot_cold_file_putback_inactive_pages(p_hot_cold_file_node_pgdat[i].pgdat,p_pgdat_page_list);

			//此时p_hot_cold_file_node_pgdat[pgdat->node_id]->pgdat_page_list链表上还残留的page没人再用了，引用计数是0，这里直接释放
			mem_cgroup_uncharge_list_async(p_pgdat_page_list);
			free_unref_page_list_async(p_pgdat_page_list);
		}
	}
	return nr_reclaimed;
}
static void get_file_name(char *file_name_path,struct file_stat * p_file_stat)
{
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;

	file_name_path[0] = '\0';

	/*必须 hlist_empty()判断文件inode是否有dentry，没有则返回true。这里通过inode和dentry获取文件名字，必须 inode->i_lock加锁 
	 *同时 增加inode和dentry的应用计数，否则可能正使用时inode和dentry被其他进程释放了*/
	if(p_file_stat->mapping && p_file_stat->mapping->host && !hlist_empty(&p_file_stat->mapping->host->i_dentry)){
		inode = p_file_stat->mapping->host;
        spin_lock(&inode->i_lock);
		//如果inode的引用计数是0，说明inode已经在释放环节了，不能再使用了
		if(atomic_read(&inode->i_count) > 0){
			dentry = hlist_entry(p_file_stat->mapping->host->i_dentry.first, struct dentry, d_u.d_alias);
			//__dget(dentry);------这里不再__dget,因为全程有spin_lock(&inode->i_lock)加锁
			if(dentry)
				snprintf(file_name_path,MAX_FILE_NAME_LEN - 2,"dentry:0x%llx %s",(u64)dentry,dentry->d_iname);
			//dput(dentry);
        }
		spin_unlock(&inode->i_lock);
	}
}
//遍历p_hot_cold_file_global各个链表上的file_stat的file_area个数及page个数
static int hot_cold_file_print_all_file_stat(struct hot_cold_file_global *p_hot_cold_file_global,struct seq_file *m,int is_proc_print)//is_proc_print:1 通过proc触发的打印
{
	struct file_stat * p_file_stat;
	unsigned int file_stat_one_file_area_count = 0,file_stat_many_file_area_count = 0;
	unsigned int file_stat_one_file_area_pages = 0,all_pages = 0;
	char file_name_path[MAX_FILE_NAME_LEN];

	//如果驱动在卸载，禁止再打印file_stat信息
	if(!test_bit(ASYNC_MEMORY_RECLAIM_ENABLE,&async_memory_reclaim_status)){
		printk("async_memory_reclaime ko is remove\n");
		return 0;
	}

	//hot_cold_file_global->file_stat_hot_head链表
	if(!list_empty(&p_hot_cold_file_global->file_stat_hot_head)){
		if(is_proc_print)
			seq_printf(m,"hot_cold_file_global->file_stat_hot_head list********\n");
		else	
		    printk("hot_cold_file_global->file_stat_hot_head list********\n");
    }
	list_for_each_entry_rcu(p_file_stat,&p_hot_cold_file_global->file_stat_hot_head,hot_cold_file_list){
		atomic_inc(&hot_cold_file_global_info.ref_count);
		lock_file_stat(p_file_stat,0);
		/*如果file_stat对应的文件inode释放了，file_stat被标记了delete，此时不能再使用p_file_stat->mapping，因为mapping已经释放了.
		  但执行这个函数时，必须禁止执行cold_file_stat_delete_all_file_area()释放掉file_stat!!!!!!!!!!!!!!!!!!!!*/
		smp_rmb();//内存屏障获取最新的file_stat状态
		if(0 == file_stat_in_delete(p_file_stat)){
			if(p_file_stat->file_area_count > 1){
				file_stat_many_file_area_count ++;
				get_file_name(file_name_path,p_file_stat);
				all_pages += p_file_stat->mapping->nrpages;
                
				if(is_proc_print)
					seq_printf(m,"file_stat:0x%llx max_age:%ld recent_access_age:%ld file_area_count:%d nrpages:%ld %s\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->recent_access_age,p_file_stat->file_area_count,p_file_stat->mapping->nrpages,file_name_path);
				else	
				    printk("file_stat:0x%llx max_age:%ld recent_access_age:%ld file_area_count:%d nrpages:%ld %s\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->recent_access_age,p_file_stat->file_area_count,p_file_stat->mapping->nrpages,file_name_path);
			}
			else{
				file_stat_one_file_area_count ++;
				file_stat_one_file_area_pages += p_file_stat->mapping->nrpages;
			}
		}
		else{
			if(p_file_stat->file_area_count > 1){
				file_stat_many_file_area_count ++;
				if(is_proc_print)
					seq_printf(m,"file_stat:0x%llx max_age:%ld file_area_count:%d delete\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->file_area_count);
				else	
				    printk("file_stat:0x%llx max_age:%ld file_area_count:%d delete\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->file_area_count);
			}
			else{
				file_stat_one_file_area_count ++;
			}
		}
		unlock_file_stat(p_file_stat);
		atomic_dec(&hot_cold_file_global_info.ref_count);
	}

	//hot_cold_file_global->file_stat_temp_head链表
	if(!list_empty(&p_hot_cold_file_global->file_stat_temp_head)){
		if(is_proc_print)
			seq_printf(m,"hot_cold_file_global->file_stat_temp_head list********\n");
		else	
		    printk("hot_cold_file_global->file_stat_temp_head list********\n");
	}
	list_for_each_entry_rcu(p_file_stat,&p_hot_cold_file_global->file_stat_temp_head,hot_cold_file_list){
		atomic_inc(&hot_cold_file_global_info.ref_count);
		lock_file_stat(p_file_stat,0);
		/*如果file_stat对应的文件inode释放了，file_stat被标记了delete，此时不能再使用p_file_stat->mapping，因为mapping已经释放了
		  但执行这个函数时，必须禁止执行cold_file_stat_delete_all_file_area()释放掉file_stat!!!!!!!!!!!!!!!!!!!!*/
		smp_rmb();//内存屏障获取最新的file_stat状态
		if(0 == file_stat_in_delete(p_file_stat)){
			if(p_file_stat->file_area_count > 1){
				file_stat_many_file_area_count ++;
				get_file_name(file_name_path,p_file_stat);
				all_pages += p_file_stat->mapping->nrpages;

				if(is_proc_print)
					seq_printf(m,"file_stat:0x%llx max_age:%ld recent_access_age:%ld file_area_count:%d nrpages:%ld %s\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->recent_access_age,p_file_stat->file_area_count,p_file_stat->mapping->nrpages,file_name_path);
				else	
				    printk("file_stat:0x%llx max_age:%ld recent_access_age:%ld file_area_count:%d nrpages:%ld %s\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->recent_access_age,p_file_stat->file_area_count,p_file_stat->mapping->nrpages,file_name_path);
			}
			else{
				file_stat_one_file_area_count ++;
				file_stat_one_file_area_pages += p_file_stat->mapping->nrpages;
			}
		}
		else{
			if(p_file_stat->file_area_count > 1){
				file_stat_many_file_area_count ++;
				if(is_proc_print)
					seq_printf(m,"file_stat:0x%llx max_age:%ld file_area_count:%d delete\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->file_area_count);
				else	
				    printk("file_stat:0x%llx max_age:%ld file_area_count:%d delete\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->file_area_count);
			}
			else{
				file_stat_one_file_area_count ++;
			}
		}
		unlock_file_stat(p_file_stat);
		atomic_dec(&hot_cold_file_global_info.ref_count);
	}

	//hot_cold_file_global->file_stat_temp_large_file_head链表
	if(!list_empty(&p_hot_cold_file_global->file_stat_temp_large_file_head)){
		if(is_proc_print)
			seq_printf(m,"hot_cold_file_global->file_stat_temp_large_file_head list********\n");
		else	
		    printk("hot_cold_file_global->file_stat_temp_large_file_head list********\n");
	}
	list_for_each_entry_rcu(p_file_stat,&p_hot_cold_file_global->file_stat_temp_large_file_head,hot_cold_file_list){
		atomic_inc(&hot_cold_file_global_info.ref_count);

		lock_file_stat(p_file_stat,0);
		/*如果file_stat对应的文件inode释放了，file_stat被标记了delete，此时不能再使用p_file_stat->mapping，因为mapping已经释放了
		  但执行这个函数时，必须禁止执行cold_file_stat_delete_all_file_area()释放掉file_stat!!!!!!!!!!!!!!!!!!!!*/
		smp_rmb();//内存屏障获取最新的file_stat状态
		if(0 == file_stat_in_delete(p_file_stat)){
			if(p_file_stat->file_area_count > 1){
				file_stat_many_file_area_count ++;
				get_file_name(file_name_path,p_file_stat);
				all_pages += p_file_stat->mapping->nrpages;

				if(is_proc_print)
					seq_printf(m,"file_stat:0x%llx max_age:%ld recent_access_age:%ld file_area_count:%d nrpages:%ld %s\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->recent_access_age,p_file_stat->file_area_count,p_file_stat->mapping->nrpages,file_name_path);
				else	
				    printk("file_stat:0x%llx max_age:%ld recent_access_age:%ld file_area_count:%d nrpages:%ld %s\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->recent_access_age,p_file_stat->file_area_count,p_file_stat->mapping->nrpages,file_name_path);
			}
			else{
				file_stat_one_file_area_count ++;
				file_stat_one_file_area_pages += p_file_stat->mapping->nrpages;
			}
		}
		else{
			if(p_file_stat->file_area_count > 1){
				file_stat_many_file_area_count ++;
				if(is_proc_print)
					seq_printf(m,"file_stat:0x%llx max_age:%ld file_area_count:%d delete\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->file_area_count);
				else	
				    printk("file_stat:0x%llx max_age:%ld file_area_count:%d delete\n",(u64)p_file_stat,p_file_stat->max_file_area_age,p_file_stat->file_area_count);
			}
			else{
				file_stat_one_file_area_count ++;
			}
		}
		unlock_file_stat(p_file_stat);
		atomic_dec(&hot_cold_file_global_info.ref_count);
	}
	all_pages += file_stat_one_file_area_pages;

	if(is_proc_print)
		seq_printf(m,"file_stat_one_file_area_count:%d pages:%d  file_stat_many_file_area_count:%d all_pages:%d\n",file_stat_one_file_area_count,file_stat_one_file_area_pages,file_stat_many_file_area_count,all_pages);
	else	
	    printk("file_stat_one_file_area_count:%d pages:%d  file_stat_many_file_area_count:%d all_pages:%d\n",file_stat_one_file_area_count,file_stat_one_file_area_pages,file_stat_many_file_area_count,all_pages);
	return 0;
}

/*遍历hot_cold_file_global->file_stat_temp_large_file_head或file_stat_temp_head链表尾巴上边的文件file_stat，然后遍历这些file_stat的
 *file_stat->file_area_temp链表尾巴上的file_area，被判定是冷的file_area则移动到file_stat->file_area_free_temp链表。把有冷file_area的
  file_stat移动到file_stat_free_list临时链表。返回值是遍历到的冷file_area个数*/
static unsigned int get_file_area_from_file_stat_list(struct hot_cold_file_global *p_hot_cold_file_global,unsigned int scan_file_area_max,unsigned int scan_file_stat_max,struct list_head *file_stat_temp_head,struct list_head *file_stat_free_list)
{
    //file_stat_temp_head来自 hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head 链表
	
	struct file_stat * p_file_stat,*p_file_stat_temp;
	struct file_area *p_file_area,*p_file_area_temp;
    int repeat_count = 0;

	unsigned int scan_file_area_count  = 0;
	unsigned int scan_file_stat_count  = 0;
	unsigned int real_scan_file_stat_count  = 0;
	unsigned int scan_delete_file_stat_count = 0;
	unsigned int scan_cold_file_area_count = 0;
	unsigned int scan_large_to_small_count = 0;
	unsigned int scan_fail_file_stat_count = 0;

	unsigned int cold_file_area_for_file_stat = 0;
	unsigned int file_stat_count_in_cold_list = 0;
	unsigned int serial_file_area = 0;
    LIST_HEAD(unused_file_stat_list);
	//暂存从hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head 链表链表尾扫描到的file_stat
	LIST_HEAD(global_file_stat_temp_head_list);

	/*必须要先从file_stat_temp_head或file_stat_temp_large_file_head隔离多个file_stat，然后去遍历这些file_stat上的file_area，这样只用开关
	 * 一次hot_cold_file_global->global_lock锁.否则每遍历一个file_stat，都开关一次hot_cold_file_global->global_lock锁，太损耗性能。*/
	spin_lock(&p_hot_cold_file_global->global_lock);
	//先从global file_stat_temp_head链表尾隔离scan_file_stat_max个file_stat到 global_file_stat_temp_head_list 临时链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,file_stat_temp_head,hot_cold_file_list){
		if(scan_file_stat_count ++ > scan_file_stat_max)
			break;
		/*这里把file_stat 移动到 global_file_stat_temp_head_list 临时链表，用不用清理的file_stat的 in_file_stat_temp_head 标记，需要的。
		 *因为hot_file_update_file_status()函数中会并发因为file_stat的 in_file_stat_temp_head 标记，而移动到file_stat的file_stat_hot_head
		  链表，不能有这种并发操作*/
		if(!file_stat_in_file_stat_temp_head_list(p_file_stat) || file_stat_in_file_stat_temp_head_list_error(p_file_stat)){
			/*正常情况file_stat肯定处于global temp_head_list链表，但是可能有进程在hot_file_update_file_status()函数并发把这个file_stat判断为
			  热文件并移动到global hot_head链表。这个不可能，因为这里先获取global_lock锁，然后再遍历file_stat*/
			panic("%s file_stat:0x%llx not int file_stat_temp_head status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
			//continue;
		}
		else if(file_stat_in_delete(p_file_stat)){
			scan_delete_file_stat_count ++;
			clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			//如果该文件inode被释放了，则把对应file_stat移动到hot_cold_file_global->file_stat_delete_head链表
			list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_delete_head);
			continue;
		}
		//如果file_stat的file_area全被释放了，则把file_stat移动到hot_cold_file_global->file_stat_zero_file_area_head链表
		if(p_file_stat->file_area_count == 0){
			clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			set_file_stat_in_zero_file_area_list(p_file_stat);
			p_hot_cold_file_global->file_stat_count_zero_file_area ++;
			//如果该文件inode被释放了，则把对应file_stat移动到hot_cold_file_global->file_stat_zero_file_area_head链表
			list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_zero_file_area_head);
			continue;
		}

		/*file_stat_temp_head来自 hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head 链表，当是
		 * hot_cold_file_global->file_stat_temp_large_file_head时，file_stat_in_large_file(p_file_stat)才会成立*/

		/*当file_stat上有些file_area长时间没有被访问则会释放掉file_are结构。此时原本在hot_cold_file_global->file_stat_temp_large_file_head 链表的
		 *大文件file_stat则会因file_area数量减少而需要降级移动到hot_cold_file_global->file_stat_temp_head链表.这个判断起始可以放到
		  hot_file_update_file_status()函数，算了降低损耗*/
		if(file_stat_in_large_file(p_file_stat) && !is_file_stat_large_file(&hot_cold_file_global_info,p_file_stat)){

			scan_large_to_small_count ++;
			/*不用现在把file_stat移动到global file_stat_temp_head链表。等该file_stat的file_area经过内存回收后，该file_stat会因为
			 *clear_file_stat_in_large_file而移动到file_stat_temp_head链表。想了想，还是现在就移动到file_stat->file_stat_temp_head链表尾，
			  否则内存回收再移动更麻烦。要移动到链表尾，这样紧接着就会从file_stat_temp_head链表链表尾扫描到该file_stat*/
			list_move_tail(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);
			p_hot_cold_file_global->file_stat_large_count --;
			continue;
		}
		if(p_file_stat->recent_access_age < p_hot_cold_file_global->global_age)
			p_file_stat->recent_access_age = p_hot_cold_file_global->global_age;

		//需要设置这些file_stat不再处于file_stat_temp_head链表，否则之后hot_file_update_file_status()会因该file_stat的热file_area很多而移动到global file_stat_temp_head链表
		clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
		//这里设置file_stat处于in_free_page，然后hot_file_update_file_status()中即便并发设置file_stat状态，也没事，因为都做好了并发防护
		set_file_stat_in_free_page(p_file_stat);
		//扫描到的file_stat先移动到global_file_stat_temp_head_list临时链表，下边就开始遍历这些file_stat上的file_area
		list_move(&p_file_stat->hot_cold_file_list,&global_file_stat_temp_head_list);
		real_scan_file_stat_count++;
	}
	spin_unlock(&p_hot_cold_file_global->global_lock);

	/*前边设置了参与内存回收的file_stat的in_free_page状态，但是有可能此时正好有进程hot_file_update_file_status()访问这些file_stat的file_area，
	  把file_area从file_stat->file_area_temp链表移动到file_stat->file_area_hot链表。该函数下边正好要遍历file_stat->file_area_temp链表上的file_area，
	  要避免此时hot_file_update_file_status()把正遍历的file_area从file_stat->file_area_temp链表移动到了file_stat->file_area_hot链表。否则会导致
	  边遍历file_stat->file_area_temp链表上的file_area陷入死循环。这就是"遍历的链表成员被移动到其他链表，因为链表头变了导致的遍历陷入死循环"。
	  而等这些进程都退出hot_file_update_file_status()函数，hot_cold_file_global_info.ref_count是0，这里才可以继续执行，遍历
	  file_stat->file_area_temp链表上的file_area。因为等新的进程再执行hot_file_update_file_status()，file_stat的in_free_page状态肯定已经
	  生效，hot_file_update_file_status()中就不会再把file_stat->file_area_temp链表上的file_area移动到file_stat->file_area_hot链表了
	*/
	while(atomic_read(&hot_cold_file_global_info.ref_count)){
		msleep(1);
	}

	/*在遍历hot_cold_file_global->file_stat_temp_head链表期间，可能创建了新文件并创建了file_stat并添加到hot_cold_file_global->file_stat_temp_head链表，
	  下边遍历hot_cold_file_global->file_stat_hot_head链表成员期间，是否用hot_cold_file_global_info.global_lock加锁？不用，因为遍历链表期间
	  向链表添加成员没事，只要不删除成员！想想我写的内存屏障那片文章讲解list_del_rcu的代码*/
	list_for_each_entry_safe(p_file_stat,p_file_stat_temp,&global_file_stat_temp_head_list,hot_cold_file_list)//本质就是遍历p_hot_cold_file_global->file_stat_temp_head链表尾的file_stat
	{

      repeat_count = 0;
		cold_file_area_for_file_stat = 0;
repeat:
		serial_file_area = 0;
		/*注意，这里扫描的global file_stat_temp_head上的file_stat肯定有冷file_area，因为file_stat只要50%的file_area是热的，file_stat就要移动到
		  global file_stat_hot_head 链表*/
		list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_temp,file_area_list)//从链表尾开始遍历，链表尾的成员更老，链表头的成员是最新添加的
		{
			if(!file_stat_in_free_page(p_file_stat) || file_stat_in_free_page_error(p_file_stat)){
			    panic("%s file_stat:0x%llx not int file_stat_in_free_page status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
		    }

			scan_file_area_count ++;

			//file_area经过FILE_AREA_TEMP_TO_COLD_AGE_DX个周期还没有被访问，则被判定是冷file_area，然后就释放该file_area的page
			if(p_hot_cold_file_global->global_age - p_file_area->file_area_age >  p_hot_cold_file_global->file_area_temp_to_cold_age_dx){
				//每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表???????
				spin_lock(&p_file_stat->file_stat_lock);
			  /*为什么file_stat_lock加锁后要再判断一次file_area是不是被访问了,因为可能有这种情况:上边的if成立,此时file_area还没被访问。但是此时有进程
				先执行hot_file_update_file_status()获取file_stat_lock锁,然后访问当前file_area,file_area不再冷了,当前进程此时获取file_stat_lock锁失败,
				等获取file_stat_lock锁成功后，file_area的file_area_age就和global_age相等了。变量加减后的判断，在spin_lock前后各判断一次有必要的!!!!!*/
				if(p_hot_cold_file_global->global_age - p_file_area->file_area_age <=  p_hot_cold_file_global->file_area_temp_to_cold_age_dx){
					spin_unlock(&p_file_stat->file_stat_lock);    
					continue;
				}
				serial_file_area = 0;
				//access_count清0，如果内存回收期间又被访问了，access_count将大于0，将被判断为refault page。
				file_area_access_count_clear(p_file_area);
				clear_file_area_in_temp_list(p_file_area);
				/*设置file_area处于file_stat的free_temp_list链表。这里设定，不管file_area处于file_stat->file_area_free_temp还是
				 *file_stat->file_area_free链表，都是file_area_in_free_list状态，没有必要再区分二者。主要设置file_area的状态需要
				  遍历每个file_area并file_stat_lock加锁，再多设置一次set_file_area_in_free_temp_list状态浪费性能。这点需注意!!!!!!!!!!!!!*/
				set_file_area_in_free_list(p_file_area);
				/*需要加锁，此时可能有进程执行hot_file_update_file_status()并发向该p_file_area前或者后插入新的file_area，这里是把该
				 * p_file_area从file_area_temp链表剔除，存在同时修改该p_file_area在file_area_temp链表前的file_area结构的next指针和在链表后的
				 * file_area结构的prev指针，并发修改同一个变量就需要加锁*/
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_free_temp);
				spin_unlock(&p_file_stat->file_stat_lock);

				cold_file_area_for_file_stat ++;
			}
			//else if(p_hot_cold_file_global->global_age == p_file_area->file_area_age)
			else 
			//否则就停止遍历file_stat->file_area_temp链表上的file_area，因为该链表上的file_area从左向右，访问频率由大向小递增，这个需要实际测试?????????
			{
				/*如果file_stat->file_area_temp链表尾连续扫到3个file_area都是热的，才停止扫描该file_stat上的file_area。因为此时
				 *file_stat->file_area_temp链表尾上的file_area可能正在被访问，file_area->file_area_age=hot_cold_file_global->global_age，
				  但是file_area还没被移动到file_stat->file_area_temp链表头。这个判断是为了过滤掉这种瞬时的热file_area干扰*/
				if(serial_file_area ++ > 1)
					break;
			}
		}
		/*第2遍遍历file_stat->file_area_temp链表尾的file_area，防止第1次遍历file_stat->file_area_temp链表尾的file_area时，该file_stat因为被访问
		  在hot_file_update_file_status()函数中被移动到file_stat->file_area_temp链表头，这样就会立即结束遍历。file_stat->file_area_temp链表尾的
		  冷file_area根本没有遍历完*/
        if(repeat_count == 0){
			repeat_count ++;
			goto repeat;
		}

	   /*1:cold_file_area_for_file_stat != 0表示把有冷file_area的file_stat移动到file_stat_free_list临时链表.此时的file_sata已经不在
		   file_stat_temp_head链表，不用clear_file_stat_in_file_stat_temp_head_list
		 2:如果file_stat->file_area_refault链表非空，说明也需要扫描这上边的file_area，要把上边冷的file_area移动回file_stat_temp_head_list
		    链表，参数内存回收扫描，结束保护期
		 3:如果file_stat->file_area_free 和 file_stat->file_area_hot链表上也非空，说明上边也有file_area需要遍历，file_area_hot链表上的冷
		    file_area需要移动回file_stat_temp_head_list链表，file_area_free链表上长时间没有被访问的file_area要释放掉file_area结构。

		 因此，file_stat->file_area_temp上有冷page，或者file_stat->file_area_refault、file_area_free、file_area_hot 链表只要非空，有file_area，
		 都要把file_stat结构添加到file_stat_free_list临时链表。然后free_page_from_file_area()中依次扫描这些file_stat的file_area_free_temp、
		 file_area_refault、file_area_free、file_area_hot链表上file_area，按照对应策略该干啥干啥。

		 这段代码是从上边的for循环移动过来的，放到这里是保证同一个file_stat只list_move到file_stat_free_list链表一次。并且，当
		 file_stat->file_area_temp链表没有冷file_area或者没有一个file_area时，但是file_stat的file_area_free_temp、file_area_refault、
		 file_area_free、file_area_hot链表上file_area要遍历，这样也要把该file_stat移动到file_stat_free_list链表，这样将来
		 free_page_from_file_area()函数中才能从file_stat_free_list链表扫描到该file_stat，否则会出现一些问题，比如file_stat的file_area_free链表上
		 长时间没访问的file_stat无法遍历到，无法释放这些file_stat结构；还有 file_stat的file_area_refault和file_area_hot链表上的冷file_area
		 无法降级移动到file_stat->file_area_temp链表，这些file_stat将无法扫描到参与内存回收
		 */
		if(cold_file_area_for_file_stat != 0 || !list_empty(&p_file_stat->file_area_refault) ||
				!list_empty(&p_file_stat->file_area_free) || !list_empty(&p_file_stat->file_area_hot)){
			list_move(&p_file_stat->hot_cold_file_list,file_stat_free_list);
			//移动到file_stat_free_list链表头的file_stat个数
			file_stat_count_in_cold_list ++;
		}
        else{
			/*把没有冷file_area、file_stat->file_area_refault、file_area_free、file_area_hot还是空的file_stat移动到unused_file_stat_list
			 *临时链表，最后再移动到global file_stat_temp_head链表头，这样下轮异步内存回收不会重复扫描这些file_stat*/
		    list_move(&p_file_stat->hot_cold_file_list,&unused_file_stat_list);
		}
		//累计遍历到的冷file_area个数
		scan_cold_file_area_count += cold_file_area_for_file_stat;

		/*防止在for循环耗时太长，限制遍历的文件file_stat数。这里两个问题 问题1:单个file_stat上的file_area太多了，只扫描一个file_stat这里就
		  break跳出循环了。这样下边就把global_file_stat_temp_head_list残留的file_stat移动到global file_stat_temp_head链表头了。下轮扫描从
		  global file_stat_temp_head尾就扫描不到该file_stat了。合理的做法是，把这些压根没扫描的file_stat再移动到global file_stat_temp_head尾。
		  问题2：还是 单个file_stat上的file_area太多了，没扫描完，下次再扫描该file_stat时，直接从上次结束的file_area位置处继续扫描，似乎更合理。
		  file_stat断点file_area继续扫描！但是实现起来似乎比较繁琐，算了*/
		if(scan_file_area_count > scan_file_area_max)
			break;
    }
	/*到这里还残留在global_file_stat_temp_head_list上的file_stat，是本轮就没有扫描到的。因为参与内存回收的扫描的file_area总数不能超过
	  scan_file_area_max，如果某个file_stat的file_area太多就会导致global_file_stat_temp_head_list链表上其他file_stat扫描不到。这里要把
	  这些file_stat移动到global file_stat_temp_head链表尾，下次异步内存回收继续扫描这些file_stat*/
	if(!list_empty(&global_file_stat_temp_head_list)){

		spin_lock(&p_hot_cold_file_global->global_lock);
		//设置file_stat状态要加锁
		list_for_each_entry(p_file_stat,&global_file_stat_temp_head_list,hot_cold_file_list){
			/*这里清理file_stat的in_free_page状态很重要，因为这些file_stat在该函数开头设置了in_free_page状态，这里要清理掉in_free_page状态，
			 * 否则后续扫描这些file_stat时，会出现file_stat状态错乱*/
		    clear_file_stat_in_free_page(p_file_stat);
			set_file_stat_in_file_stat_temp_head_list(p_file_stat);//设置file_stat状态为head_temp_list 
			scan_fail_file_stat_count ++;
		}

		//把未遍历的file_stat再移动回global file_stat_temp_head或global file_stat_temp_large_file_head 链表尾巴
		list_splice_tail(&global_file_stat_temp_head_list,file_stat_temp_head);

		/*list_splice把前者的链表成员a1...an移动到后者链表，并不会清空前者链表。必须INIT_LIST_HEAD清空前者链表，否则它一直指向之前的链表成员
		 *a1...an。后续再向该链表添加新成员b1...bn。这个链表就指向的成员就有a1...an + b1...+bn。而此时a1...an已经移动到了后者链表，
		 *相当于前者和后者链表都指向了a1...an成员，这样肯定会出问题.之前get_file_area_from_file_stat_list()函数报错
		 "list_add corruption. next->prev should be prev"而crash估计就是这个原因!!!!!!!!!!!!!!!!!!
		 */
		
		//INIT_LIST_HEAD(&global_file_stat_temp_head_list)//global_file_stat_temp_head_list是局部链表，不用清，只有全局变量才必须list_splice_tail后清空链表

		spin_unlock(&p_hot_cold_file_global->global_lock);
	}

	/*unused_file_stat_list链表上的file_stat，没有冷file_area、file_stat->file_area_refault、file_area_free、file_area_hot还是空的，这里把
	 *这些file_stat移动到global file_stat_temp_head链表头，这样下轮异步内存回收不会重复扫描这些file_stat*/
	if(!list_empty(&unused_file_stat_list)){

		spin_lock(&p_hot_cold_file_global->global_lock);
		//设置file_stat状态要加锁
		list_for_each_entry(p_file_stat,&unused_file_stat_list,hot_cold_file_list){
			/*这里清理file_stat的in_free_page状态很重要，因为这些file_stat在该函数开头设置了in_free_page状态，这里要清理掉in_free_page状态，
			 * 否则后续扫描这些file_stat时，会出现file_stat状态错乱*/
		    clear_file_stat_in_free_page(p_file_stat);
			set_file_stat_in_file_stat_temp_head_list(p_file_stat);//设置file_stat状态为head_temp_list 
			scan_fail_file_stat_count ++;
		}
        //移动到 global file_stat_temp_head 或 file_stat_temp_large_file_head 链表头，样下轮异步内存回收不会重复扫描这些file_stat
		list_splice(&unused_file_stat_list,file_stat_temp_head);
		spin_unlock(&p_hot_cold_file_global->global_lock);
	}

	if(shrink_page_printk_open)
		printk("3:%s %s %d p_hot_cold_file_global:0x%llx scan_file_stat_count:%d scan_file_area_count:%d scan_cold_file_area_count:%d file_stat_count_in_cold_list:%d  real_scan_file_stat_count:%d\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,scan_file_stat_count,scan_file_area_count,scan_cold_file_area_count,file_stat_count_in_cold_list,real_scan_file_stat_count);

	//扫描的file_area个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_file_area_count = scan_file_area_count;
	//扫描的file_stat个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_file_stat_count = real_scan_file_stat_count;
	//扫描到的处于delete状态的file_stat个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_delete_file_stat_count = scan_delete_file_stat_count;
	//扫描的冷file_stat个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_cold_file_area_count = scan_cold_file_area_count;
	//扫描到的大文件转小文件的个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_large_to_small_count = scan_large_to_small_count;
	//本次扫描到但没有冷file_area的file_stat个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_fail_file_stat_count = scan_fail_file_stat_count;

	return scan_cold_file_area_count;
}
/*该函数主要有3个作用
 * 1：释放file_stat_free_list链表上的file_stat的file_area_free_temp链表上冷file_area的page。释放这些page后，把这些file_area移动到
 *    file_stat->file_area_free链表头
 * 2：遍历file_stat_free_list链表上的file_stat的file_area_hot链表尾上的热file_area，如果长时间没有被访问，说明变成冷file_area了，
 *    则移动到file_stat->file_area_temp链表头
 * 3：遍历file_stat_free_list链表上的file_stat的file_area_free链表尾上的file_area，如果还是长时间没有被访问，则释放掉这些file_area结构
 * 4: 遍历file_stat_free_list链表上的file_stat的file_area_refault链表尾巴的file_area，如果长时间没有被访问，则移动到file_stat->file_area_temp链表头
 * 5: 把file_stat_free_list链表上的file_stat再移动回file_stat_temp_head链表(即global file_stat_temp_head或file_stat_temp_large_file_head)头，
 *    这样下轮walk_throuth_all_file_area()再扫描，从global file_stat_temp_head或file_stat_temp_large_file_head链表尾巴扫到的file_stat
 *    都是最近没有被扫描过的，避免重复扫描
 */

/*file_stat_free_list链表上的file_stat来自本轮扫描从global file_stat_temp_head或file_stat_temp_large_file_head链表尾获取到的
  file_stat_temp_head是global file_stat_temp_head或file_stat_temp_large_file_head*/
static unsigned long free_page_from_file_area(struct hot_cold_file_global *p_hot_cold_file_global,struct list_head * file_stat_free_list,struct list_head *file_stat_temp_head)
{
	struct file_stat *p_file_stat,*p_file_stat_temp;
	struct file_area *p_file_area,*p_file_area_temp;
	unsigned int cold_file_area_count;
	unsigned int free_pages = 0;
	unsigned int file_area_count;
	unsigned int isolate_lru_pages = 0;
	unsigned int file_area_refault_to_temp_list_count = 0;
	unsigned int file_area_free_count = 0;
	unsigned int file_area_hot_to_temp_list_count = 0;

	/*同一个文件file_stat的file_area对应的page，更大可能是属于同一个内存节点node，所以要基于一个个文件的file_stat来扫描file_area，
	 *避免频繁开关内存节点锁pgdat->lru_lock锁*/  

	//遍历file_stat_free_list临时链表上的file_stat，释放这些file_stat的file_stat->file_area_free_temp链表上的冷file_area的page
	list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list)
	{
		/*对file_area_free_temp上的file_stat上的file_area对应的page进行隔离，隔离成功的移动到
		 *p_hot_cold_file_global->hot_cold_file_node_pgdat->pgdat_page_list对应内存节点链表上*/
		isolate_lru_pages += cold_file_isolate_lru_pages(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_free_temp);
		//这里真正释放p_hot_cold_file_global->hot_cold_file_node_pgdat->pgdat_page_list链表上的内存page
		free_pages += cold_file_shrink_pages(p_hot_cold_file_global);


	    if(shrink_page_printk_open1)
		    printk("1:%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%lx free_pages:%d\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status,free_pages);

		/*注意，file_stat->file_area_free_temp 和 file_stat->file_area_free 各有用处。file_area_free_temp保存每次扫描释放的page的file_area。
		  释放后把这些file_area移动到file_area_free链表，file_area_free保存的是每轮扫描释放page的所有file_area，是所有的!!!!!!!!!!!!!!*/

		/*p_file_stat->file_area_free_temp上的file_area的冷内存page释放过后,下边需则把file_area_free_temp链表上的file_area结构再移动到
		 *file_area_free链表头，file_area_free链表上的file_area结构要长时间也没被访问就释放掉*/

		//if(!list_empty(&p_file_stat->file_area_free_temp)){//get_file_area_from_file_stat_list()函数中，有的file_stat没有冷file_area，但是有热file_area、refault file_area，也会移动到file_stat_free_list链表，但是file_stat->file_area_free_temp链表是空的，这里就if不成立了，因此要去掉

			/*hot_file_update_file_status()函数中会并发把file_area从file_stat->file_area_free_temp链表移动到file_stat->file_area_free_temp链表.
			  这里把file_stat->file_area_free_temp链表上的file_area移动到file_stat->file_area_free，需要加锁*/
			spin_lock(&p_file_stat->file_stat_lock);
			
			if(!file_stat_in_free_page(p_file_stat) || file_stat_in_free_page_error(p_file_stat)){
			    panic("%s file_stat:0x%llx not int file_stat_in_free_page status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
		    }

			//清理file_stat的in_free_page状态，并设置file_stat处于in_free_page_done状态
		    clear_file_stat_in_free_page(p_file_stat);
		    set_file_stat_in_free_page_done(p_file_stat);

			list_splice(&p_file_stat->file_area_free_temp,&p_file_stat->file_area_free);
			/*list_splice把前者的链表成员a1...an移动到后者链表，并不会清空前者链表。必须INIT_LIST_HEAD清空前者链表，否则它一直指向之前的
			 *链表成员a1...an。后续再向该链表添加新成员b1...bn。这个链表就指向的成员就有a1...an + b1...+bn。而此时a1...an已经移动到了后者
			 *链表，相当于前者和后者链表都指向了a1...an成员，这样肯定会出问题.之前get_file_area_from_file_stat_list()函数报错
			 *"list_add corruption. next->prev should be prev"而crash估计就是这个原因!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			 */
			INIT_LIST_HEAD(&p_file_stat->file_area_free_temp);

			spin_unlock(&p_file_stat->file_stat_lock);
		//}
	}
	//需要调度的话休眠一下
	cond_resched();

	/*遍历file_stat_free_list临时链表上的file_stat，然后遍历着这些file_stat->file_area_hot链表尾巴上热file_area。这些file_area之前
	 *被判定是热file_area而被移动到了file_stat->file_area_hot链表。之后，file_stat->file_area_hot链表头的file_area访问频繁，链表尾巴
	  的file_area就会变冷。则把这些file_stat->file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->file_area_temp链表头*/
	list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list){
		cold_file_area_count = 0;
		list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_hot,file_area_list){
			if(!file_area_in_hot_list(p_file_area) || file_area_in_hot_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_hot\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			//file_stat->file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->file_area_temp链表头
			if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > p_hot_cold_file_global->file_area_hot_to_temp_age_dx){
				cold_file_area_count = 0;
				file_area_hot_to_temp_list_count ++;
				//每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表?????
				spin_lock(&p_file_stat->file_stat_lock);
				clear_file_area_in_hot_list(p_file_area);
				//file_stat的热file_area个数减1
				p_file_stat->file_area_hot_count --;
				set_file_area_in_temp_list(p_file_area);
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				spin_unlock(&p_file_stat->file_stat_lock);	    
			}else{//到这里，file_area被判定还是热file_area，还是继续存在file_stat->file_area_hot链表

				/*如果file_stat->file_area_hot尾巴上连续出现2个file_area还是热file_area，则说明file_stat->file_area_hot链表尾巴上的冷
				 *file_area都遍历完了,遇到链表头的热file_area了，则停止遍历。file_stat->file_area_hot链表头到链表尾，file_area是由热到
				 *冷顺序排布的。之所以要限制连续碰到两个热file_area再break，是因为file_stat->file_area_hot尾巴上的冷file_area可能此时
				 *hot_file_update_file_status()中并发被频繁访问，变成热file_area，但还没来得及移动到file_stat->file_area_hot链表头
				 */
				if(cold_file_area_count ++ > 2)
					break;
			}
		}
	}

	//需要调度的话休眠一下
	cond_resched();

	/*遍历file_stat_free_list临时链表上的file_stat，然后看这些file_stat的file_area_free链表上的哪些file_area长时间未被访问，抓到的话就
	 *释放掉file_area结构如果file_stat->file_area_free链表上有很多file_area导致这里遍历时间很长怎么办？需要考虑一下????????*/
	list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list){
		file_area_count = 0;
		list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_free,file_area_list){
		    /*由于这个过程没有spin_lock(&p_file_stat->file_stat_lock)加锁，file_area可能正在被访问，清理的file_area_in_free_list标记，
			 *并设置了file_area_in_hot_list或file_area_in_temp_list标记，但是file_area还没移动到file_stat的file_area_temp或file_area_hot链表。
			 *此时if(!file_area_in_free_list(p_file_area))成立，但这是正常现象。如果file_area_free链表上file_stat又被访问了，则在
			 *hot_file_update_file_status()函数中再被移动到p_file_stat->file_area_temp链表
			 */
			if(!file_area_in_free_list(p_file_area)){
				printk("%s file_area:0x%llx status:0x%x not in file_area_free !!!!!!!!!!!!\n",__func__,(u64)p_file_area,p_file_area->file_area_state);
				continue;
			}
			//如果file_stat->file_area_free链表上的file_area长时间没有被访问则释放掉file_area结构
			if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > p_hot_cold_file_global->file_area_free_age_dx){
				file_area_free_count ++;
				file_area_count = 0;
				/*hot_file_update_file_status()函数中会并发把file_area从file_stat->file_area_free链表移动到file_stat->file_area_free_temp
				 *链表.这里把file_stat->file_area_free链表上的file_area剔除掉并释放掉，需要spin_lock(&p_file_stat->file_stat_lock)加锁，
				 *这个函数里有加锁*/
				cold_file_area_detele(p_hot_cold_file_global,p_file_stat,p_file_area);
			}else{
				/*如果file_stat->file_area_free链表尾连续出现3个file_area未达到释放标准,说明可能最近被访问过，则结束遍历该
				 *file_stat->file_area_free上的file_area这是防止遍历耗时太长，并且遍历到本轮扫描添加到file_stat->file_area_free上的file_area，浪费*/
				if(file_area_count ++ > 2)
					break;
			}
		}
	}

	/*遍历 file_stat_free_list临时链表上的file_stat，然后看这些file_stat的file_area_refault链表上的file_area，如果长时间没有被访问，
	  则要移动到file_stat->file_area_temp链表*/
	list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list){
		file_area_count = 0;
		list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_refault,file_area_list){
			if(!file_area_in_refault_list(p_file_area) || file_area_in_refault_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_refault\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			//file_stat->file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->file_area_temp链表头
			if(p_hot_cold_file_global->global_age - p_file_area->file_area_age >  p_hot_cold_file_global->file_area_refault_to_temp_age_dx){
				file_area_refault_to_temp_list_count ++;
				file_area_count = 0;
				//每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
				spin_lock(&p_file_stat->file_stat_lock);
				clear_file_area_in_refault_list(p_file_area);
				set_file_area_in_temp_list(p_file_area);
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				spin_unlock(&p_file_stat->file_stat_lock);	    
			}else{
				/*如果file_stat->file_area_refault尾巴上连续出现2个file_area还是热file_area，则说明file_stat->file_area_hot链表尾巴上的冷
				 *file_area都遍历完了,遇到链表头的热file_area了，则停止遍历。file_stat->file_area_refault链表头到链表尾，file_area是由热到
				  冷顺序排布的。之所以要限制连续碰到两个热file_area再break，是因为file_stat->file_area_refault尾巴上的冷file_area可能此时
				  hot_file_update_file_status()中并发被频繁访问，变成热file_area，但还没来得及移动到file_area_refault链表头*/
				if(file_area_count ++ >2)
					break;
			}
		}
	}

	//需要调度的话休眠一下
	cond_resched();
	/*在内存回收结束时，遍历参与内存回收的一个个文件file_stat的file_area_temp和file_area_free链表头的file_area，是否在内存回收期间被访问了，
	 *是的话就移动到对应链表*/
    list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list){
		/*如果内存回收期间file_stat->file_area_temp链表上的file_area被频繁访问，这种file_area只会移动到file_stat->file_area_temp链表头。
		  这里在内存回收结束时，检查file_stat->file_area_temp链表头是否有热file_area，有的话就释放则移动到file_stat->file_area_hot链表，
		  没有立即跳出循环*/
		list_for_each_entry_safe(p_file_area,p_file_area_temp,&p_file_stat->file_area_temp,file_area_list){
			if(!file_area_in_temp_list(p_file_area) || file_area_in_temp_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_temp\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			if(file_area_access_count_get(p_file_area) > FILE_AREA_HOT_LEVEL){
				spin_lock(&p_file_stat->file_stat_lock);
				clear_file_area_in_temp_list(p_file_area);
				set_file_area_in_hot_list(p_file_area);
				p_file_stat->file_area_hot_count ++;//热file_area个数加1
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_hot);
                //在内存回收期间产生的热file_area个数
				p_hot_cold_file_global->hot_cold_file_shrink_counter.hot_file_area_count_in_free_page ++;
				spin_unlock(&p_file_stat->file_stat_lock); 
			}
			else
				break;//用不用加个过滤条件，连续两个file_area的access_count小于FILE_AREA_HOT_LEVEL时再break????????
		}
		/*如果内存回收期间file_stat->file_area_free链表上的file_area被访问了，这种file_area只会移动到file_stat->file_area_free链表头。
		  这里在内存回收结束时，检查file_stat->file_area_free链表头的file_area是否内存回收过程或结束时被访问了，是则释放则移动到
		  file_stat->file_area_refault链表，无则立即跳出循环*/
		list_for_each_entry_safe(p_file_area,p_file_area_temp,&p_file_stat->file_area_free,file_area_list){
			if(!file_area_in_free_list(p_file_area) || file_area_in_free_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_free\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			if(file_area_access_count_get(p_file_area) > 0){
				spin_lock(&p_file_stat->file_stat_lock);
				clear_file_area_in_free_list(p_file_area);
				set_file_area_in_refault_list(p_file_area);
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
                //在内存回收期间产生的refault file_area个数
				p_hot_cold_file_global->hot_cold_file_shrink_counter.refault_file_area_count_in_free_page ++;
				spin_unlock(&p_file_stat->file_stat_lock);	    
			}
			else
				break;
		}
	}

	//把file_stat_free_list临时链表上释放过内存page的file_stat再移动回global file_stat_temp_head或file_stat_temp_large_file_head链表头
	if(!list_empty(file_stat_free_list)){
		spin_lock(&p_hot_cold_file_global->global_lock);
		/*突然想到，下边for循环正在进行时，要是hot_file_update_file_status()函数中把p_file_stat的下一个file_stat即p_file_stat_temp移动到
		 *其他链表了这个for循环岂不是又要发生file_stat跨链表导致死循环?不会，因为这个for循环全程 global_lock加锁，其他地方无法把
		 *file_stat移动到其他链表*/
		list_for_each_entry_safe(p_file_stat,p_file_stat_temp,file_stat_free_list,hot_cold_file_list){
			if(!file_stat_in_free_page_done(p_file_stat) || file_stat_in_free_page_done_error(p_file_stat)){
			    panic("%s file_stat:0x%llx not int file_stat_in_free_page_done status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
		    }
			//清理file_stat的in_free_page_done状态，结束内存回收
            clear_file_stat_in_free_page_done(p_file_stat);
			/*在前边遍历这些file_stat的file_area并回收内存page过程中，file_stat是无状态的。现在这些file_stat重新移动回global的各个链表过程，
			  重新判断一下这个文件是否是大文件或者热文件，是的话则移动到对应链表*/
			if(is_file_stat_hot_file(p_hot_cold_file_global,p_file_stat)){//热文件
			    set_file_stat_in_file_stat_hot_head_list(p_file_stat);
				p_hot_cold_file_global->file_stat_hot_count ++;//热文件数加1 
				list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_hot_head);
			}else{
			    set_file_stat_in_file_stat_temp_head_list(p_file_stat);

				if(is_file_stat_large_file(p_hot_cold_file_global,p_file_stat)){//大文件
					p_hot_cold_file_global->file_stat_large_count ++;//大文件数加1
					list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_large_file_head);
				}
				else//普通文件
				    list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);
			}
		}
		/*把这些遍历过的file_stat移动回global file_stat_temp_head或file_stat_temp_large_file_head链表头,注意是链表头。这是因为，把这些
		 *遍历过的file_stat移动到global file_stat_temp_head或file_stat_temp_large_file_head链表头，下轮扫描才能从global file_stat_temp_head
		  或file_stat_temp_large_file_head链表尾遍历没有遍历过的的file_stat*/
		//list_splice(file_stat_free_list,file_stat_temp_head);//把这段代码移动到上边了

		/*list_splice把前者的链表成员a1...an移动到后者链表，并不会清空前者链表。必须INIT_LIST_HEAD清空前者链表，否则它一直指向之前的链表
		 *成员a1...an。后续再向该链表添加新成员b1...bn。这个链表就指向的成员就有a1...an + b1...+bn。而此时a1...an已经移动到了后者链表，
		 *相当于前者和后者链表都指向了a1...an成员，这样肯定会出问题.之前get_file_area_from_file_stat_list()函数报错
		 *"list_add corruption. next->prev should be prev"而crash估计就是这个原因!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		 */
		INIT_LIST_HEAD(file_stat_free_list);
		spin_unlock(&p_hot_cold_file_global->global_lock);
	}

	//释放的page个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.free_pages = free_pages;
	//隔离的page个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.isolate_lru_pages = isolate_lru_pages;
	//file_stat的refault链表转移到temp链表的file_area个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.file_area_refault_to_temp_list_count = file_area_refault_to_temp_list_count;
	//释放的file_area结构个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.file_area_free_count = file_area_free_count;
	//file_stat的hot链表转移到temp链表的file_area个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.file_area_hot_to_temp_list_count = file_area_hot_to_temp_list_count;

	if(shrink_page_printk_open)
		printk("5:%s %s %d p_hot_cold_file_global:0x%llx free_pages:%d isolate_lru_pages:%d file_stat_temp_head:0x%llx file_area_free_count:%d file_area_refault_to_list_temp_count:%d file_area_hot_to_temp_list_count:%d\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,free_pages,isolate_lru_pages,(u64)file_stat_temp_head,file_area_free_count,file_area_refault_to_temp_list_count,file_area_hot_to_temp_list_count);
	return free_pages;
}
static void printk_shrink_param(struct hot_cold_file_global *p_hot_cold_file_global,struct seq_file *m,int is_proc_print)
{
	struct hot_cold_file_shrink_counter *p = &p_hot_cold_file_global->hot_cold_file_shrink_counter;

	if(is_proc_print){
	    seq_printf(m,"scan_file_area:%d scan_file_stat:%d scan_delete_file_stat:%d scan_cold_file_area:%d scan_large_to_small:%d scan_fail_file_stat:%d file_area_refault_to_temp:%d file_area_free:%d file_area_hot_to_temp:%d-%d\n",p->scan_file_area_count,p->scan_file_stat_count,p->scan_delete_file_stat_count,p->scan_cold_file_area_count,p->scan_large_to_small_count,p->scan_fail_file_stat_count,p->file_area_refault_to_temp_list_count,p->file_area_free_count,p->file_area_hot_to_temp_list_count,p->file_area_hot_to_temp_list_count2);

	    seq_printf(m,"isolate_pages:%d del_file_stat:%d del_file_area:%d lock_fail_count:%d writeback:%d dirty:%d page_has_private:%d mapping:%d free_pages:%d free_pages_fail:%d scan_zero_file_area_file_stat_count:%d unevictable:%d lru_lock_contended:%d\n",p->isolate_lru_pages,p->del_file_stat_count,p->del_file_area_count,p->lock_fail_count,p->writeback_count,p->dirty_count,p->page_has_private_count,p->mapping_count,p->free_pages_count,p->free_pages_fail_count,p->scan_zero_file_area_file_stat_count,p->page_unevictable_count,p->lru_lock_contended_count);

		seq_printf(m,"file_area_delete_in_cache:%d file_area_cache_hit:%d file_area_access_in_free_page:%d hot_file_area_in_free_page:%d refault_file_area_in_free_page:%d hot_file_area_one_period:%d refault_file_area_one_period:%d find_file_area_from_tree:%d all_file_area_access:%d\n",p->file_area_delete_in_cache_count,p->file_area_cache_hit_count,p->file_area_access_count_in_free_page,p->hot_file_area_count_in_free_page,p->refault_file_area_count_in_free_page,p->hot_file_area_count_one_period,p->refault_file_area_count_one_period,p->find_file_area_from_tree_not_lock_count,p->all_file_area_access_count);

	    seq_printf(m,"0x%llx age:%ld file_stat_count:%d file_stat_hot:%d file_stat_zero_file_area:%d file_stat_large_count:%d\n",(u64)p_hot_cold_file_global,p_hot_cold_file_global->global_age,p_hot_cold_file_global->file_stat_count,p_hot_cold_file_global->file_stat_hot_count,p_hot_cold_file_global->file_stat_count_zero_file_area,p_hot_cold_file_global->file_stat_large_count);
	}
	else
	{
	    printk("scan_file_area_count:%d scan_file_stat_count:%d scan_delete_file_stat_count:%d scan_cold_file_area_count:%d scan_large_to_small_count:%d scan_fail_file_stat_count:%d file_area_refault_to_temp_list_count:%d file_area_free_count:%d file_area_hot_to_temp_list_count:%d-%d\n",p->scan_file_area_count,p->scan_file_stat_count,p->scan_delete_file_stat_count,p->scan_cold_file_area_count,p->scan_large_to_small_count,p->scan_fail_file_stat_count,p->file_area_refault_to_temp_list_count,p->file_area_free_count,p->file_area_hot_to_temp_list_count,p->file_area_hot_to_temp_list_count2);

	    printk("isolate_lru_pages:%d del_file_stat_count:%d del_file_area_count:%d lock_fail_count:%d writeback_count:%d dirty_count:%d page_has_private_count:%d mapping_count:%d free_pages_count:%d free_pages_fail_count:%d scan_zero_file_area_file_stat_count:%d unevictable:%d lru_lock_contended:%d\n",p->isolate_lru_pages,p->del_file_stat_count,p->del_file_area_count,p->lock_fail_count,p->writeback_count,p->dirty_count,p->page_has_private_count,p->mapping_count,p->free_pages_count,p->free_pages_fail_count,p->scan_zero_file_area_file_stat_count,p->page_unevictable_count,p->lru_lock_contended_count);

		printk("file_area_delete_in_cache_count:%d file_area_cache_hit_count:%d file_area_access_count_in_free_page:%d hot_file_area_count_in_free_page:%d refault_file_area_count_in_free_page:%d hot_file_area_count_one_period:%d refault_file_area_count_one_period:%d find_file_area_from_tree_not_lock_count:%d all_file_area_access_count:%d\n",p->file_area_delete_in_cache_count,p->file_area_cache_hit_count,p->file_area_access_count_in_free_page,p->hot_file_area_count_in_free_page,p->refault_file_area_count_in_free_page,p->hot_file_area_count_one_period,p->refault_file_area_count_one_period,p->find_file_area_from_tree_not_lock_count,p->all_file_area_access_count);


	    printk(">>>>>0x%llx global_age:%ld file_stat_count:%d file_stat_hot_count:%d file_stat_count_zero_file_area:%d file_stat_large_count:%d<<<<<<\n",(u64)p_hot_cold_file_global,p_hot_cold_file_global->global_age,p_hot_cold_file_global->file_stat_count,p_hot_cold_file_global->file_stat_hot_count,p_hot_cold_file_global->file_stat_count_zero_file_area,p_hot_cold_file_global->file_stat_large_count);
	}
}


/*遍历global file_stat_zero_file_area_head链表上的file_stat，如果file_stat对应文件长时间不被访问杂释放掉file_stat。如果file_stat对应文件又被访问了，
  则把file_stat再移动回 gloabl file_stat_temp_head、file_stat_temp_large_file_head、file_stat_hot_head链表*/
static void file_stat_has_zero_file_area_manage(struct hot_cold_file_global *p_hot_cold_file_global)
{
	struct file_stat * p_file_stat,*p_file_stat_temp;
	unsigned int scan_file_stat_max = 128,scan_file_stat_count = 0;
	unsigned int del_file_stat_count = 0;
	/*由于get_file_area_from_file_stat_list()向global file_stat_zero_file_area_head链表添加成员，这里遍历file_stat_zero_file_area_head链表成员，
	 *都是在异步内存回收线程进行的，不用spin_lock(&p_hot_cold_file_global->global_lock)加锁。除非要把file_stat_zero_file_area_head链表上的file_stat
	 *移动到 gloabl file_stat_temp_head、file_stat_temp_large_file_head、file_stat_hot_head链表。*/

	//向global  file_stat_zero_file_area_head添加成员是向链表头添加的，遍历则从链表尾巴开始遍历
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_zero_file_area_head,hot_cold_file_list){
		if(!file_stat_in_zero_file_area_list(p_file_stat) || file_stat_in_zero_file_area_list_error(p_file_stat))
			panic("%s file_stat:0x%llx not in_zero_file_area_list status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

		if(scan_file_stat_count++ > scan_file_stat_max)
			break;

		//如果file_stat对应文件长时间不被访问杂释放掉file_stat结构，这个过程不用spin_lock(&p_hot_cold_file_global->global_lock)加锁
		if(p_file_stat->file_area_count == 0 && p_hot_cold_file_global->global_age - p_file_stat->max_file_area_age > p_hot_cold_file_global->file_stat_delete_age_dx){
			/*如果该文件有pagecache没有被file_area统计到，则释放释放文件的pagecache。放到这里有问题，如果文件inode此时被删除了怎么办???????
			  决定在里边lock_file_stat()加锁，防护inode被删除*/
			file_stat_free_leak_page(p_hot_cold_file_global,p_file_stat);

			cold_file_stat_delete(p_hot_cold_file_global,p_file_stat);
			del_file_stat_count ++;
			//0个file_area的file_stat个数减1
			p_hot_cold_file_global->file_stat_count_zero_file_area --;
		}
		/*如果p_file_stat->file_area_count大于0，说明最近被访问了，则把file_stat移动回 gloabl file_stat_temp_head、file_stat_temp_large_file_head、
		 *file_stat_hot_head链表*/
		else if (p_file_stat->file_area_count > 0)
		{
			//0个file_area的file_stat个数减1
			p_hot_cold_file_global->file_stat_count_zero_file_area --;

			spin_lock(&p_hot_cold_file_global->global_lock);
			//先清理掉file_stat的in_zero_file_area_list标记
			clear_file_stat_in_zero_file_area_list(p_file_stat);

			//file_stat是热文件则移动到global file_stat_hot_head链表                   
			if(is_file_stat_hot_file(&hot_cold_file_global_info,p_file_stat)){
				set_file_stat_in_file_stat_hot_head_list(p_file_stat);                          
				list_move(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.file_stat_hot_head);
				hot_cold_file_global_info.file_stat_hot_count ++;//热文件数加1
			}
			//file_stat是大文件则移动到global file_stat_temp_large_file_head链表
			else if(file_stat_in_large_file(p_file_stat)){
				set_file_stat_in_file_stat_temp_head_list(p_file_stat); 
				set_file_stat_in_large_file(p_file_stat);
				p_hot_cold_file_global->file_stat_large_count ++;
				list_move(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.file_stat_temp_large_file_head);
			} 
			//否则，file_stat移动到 global file_stat_temp_head 普通文件链表
			else{
				set_file_stat_in_file_stat_temp_head_list(p_file_stat); 
				list_move(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.file_stat_temp_head);
			}
			spin_unlock(&p_hot_cold_file_global->global_lock);
		}
	}

	p_hot_cold_file_global->hot_cold_file_shrink_counter.del_file_stat_count = del_file_stat_count;
	p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_zero_file_area_file_stat_count = scan_file_stat_count;
}
static int walk_throuth_all_file_area(struct hot_cold_file_global *p_hot_cold_file_global)
{
	struct file_stat * p_file_stat,*p_file_stat_temp;
	struct file_area *p_file_area,*p_file_area_temp;
	//LIST_HEAD(file_area_list);
	LIST_HEAD(file_stat_free_list_from_head_temp);
	LIST_HEAD(file_stat_free_list_from_head_temp_large);
	unsigned int scan_file_area_max,scan_file_stat_max;
	unsigned int scan_cold_file_area_count = 0;
	unsigned long nr_reclaimed = 0;
	unsigned int cold_file_area_count;
	unsigned int file_area_hot_to_temp_list_count = 0;
	unsigned int del_file_stat_count = 0,del_file_area_count = 0;
	//每个周期global_age加1
	hot_cold_file_global_info.global_age ++;


	scan_file_stat_max = 10;
	scan_file_area_max = 1024;
	/*遍历hot_cold_file_global->file_stat_temp_large_file_head链表尾巴上边的大文件file_stat，然后遍历这些大文件file_stat的file_stat->file_area_temp
	 *链表尾巴上的file_area，被判定是冷的file_area则移动到file_stat->file_area_free_temp链表。把有冷file_area的file_stat移动到
	  file_stat_free_list_from_head_temp_large临时链表。返回值是遍历到的冷file_area个数*/
	scan_cold_file_area_count += get_file_area_from_file_stat_list(p_hot_cold_file_global,scan_file_area_max,scan_file_stat_max, 
			&p_hot_cold_file_global->file_stat_temp_large_file_head,&file_stat_free_list_from_head_temp_large);
	//需要调度的话休眠一下
	cond_resched();
	scan_file_stat_max = 64;
	scan_file_area_max = 1024;
	/*遍历hot_cold_file_global->file_stat_temp_head链表尾巴上边的小文件file_stat，然后遍历这些小文件file_stat的file_stat->file_area_temp
	 *链表尾巴上的file_area，被判定是冷的file_area则移动到file_stat->file_area_free_temp链表。把有冷file_area的file_stat移动到
	 *file_stat_free_list_from_head_temp临时链表。返回值是遍历到的冷file_area个数*/
	scan_cold_file_area_count += get_file_area_from_file_stat_list(p_hot_cold_file_global,scan_file_area_max,scan_file_stat_max, 
			&p_hot_cold_file_global->file_stat_temp_head,&file_stat_free_list_from_head_temp);

	/*该函数主要有5个作用
	 * 1：释放file_stat_free_list_from_head_temp_large链表上的file_stat的file_area_free_temp链表上冷file_area的page。释放这些page后，把这些
	 *   file_area移动到file_stat->file_area_free链表头
	 * 2：遍历file_stat_free_list_from_head_temp_large的file_area_hot链表尾上的热file_area，如果长时间没有被访问，说明变成冷file_area了，
	 *   则移动到file_stat->file_area_temp链表头
	 * 3：遍历file_stat_free_list_from_head_temp_large链表上的file_stat的file_area_free链表尾上的file_area，如果还是长时间没有被访问，
	 *   则释放掉这些file_area结构
	 * 4: 遍历file_stat_free_list_from_head_temp_large链表上的file_stat的file_area_refault链表尾巴的file_area，如果长时间没有被访问，则移动
	 *   到file_stat->file_area_temp链表头
	 * 5: 把file_stat_free_list_from_head_temp_large链表上的file_stat再移动回file_stat_temp_head链表(即global file_stat_temp_head或
	 *   file_stat_temp_large_file_head)头，这样下轮walk_throuth_all_file_area()再扫描，从global file_stat_temp_head或
	 *   file_stat_temp_large_file_head链表尾巴扫到的file_stat都是最近没有被扫描过的，避免重复扫描
	 */
	nr_reclaimed =  free_page_from_file_area(p_hot_cold_file_global,&file_stat_free_list_from_head_temp_large,&p_hot_cold_file_global->file_stat_temp_large_file_head); 
	nr_reclaimed += free_page_from_file_area(p_hot_cold_file_global,&file_stat_free_list_from_head_temp,&p_hot_cold_file_global->file_stat_temp_head); 

	/*遍历hot_cold_file_global->file_stat_hot_head链表上的热文件file_stat，如果哪些file_stat不再是热文件，再要把file_stat移动回
	 *global->file_stat_temp_head或file_stat_temp_large_file_head链表*/
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_hot_head,hot_cold_file_list){
		if(!file_stat_in_file_stat_hot_head_list(p_file_stat) || file_stat_in_file_stat_hot_head_list_error(p_file_stat))
			panic("%s file_stat:0x%llx not int file_stat_hot_head_list status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

		cold_file_area_count = 0;
		/*遍历global->file_stat_hot_head上的热文件file_stat的file_area_hot链表上的热file_area，如果哪些file_area不再被访问了，则要把
		 *file_area移动回file_stat->file_area_temp链表。同时令改文件的热file_area个数file_stat->file_area_hot_count减1*/
		list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_hot,file_area_list){
			//file_stat->file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->file_area_temp链表头
			if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > p_hot_cold_file_global->file_area_hot_to_temp_age_dx){
				cold_file_area_count = 0;
				if(!file_area_in_hot_list(p_file_area) || file_area_in_hot_list_error(p_file_area))
					panic("%s file_area:0x%llx status:0x%x not in file_area_hot\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

				file_area_hot_to_temp_list_count ++;
				//每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
				spin_lock(&p_file_stat->file_stat_lock);
				p_file_stat->file_area_hot_count --;
				clear_file_area_in_hot_list(p_file_area);
				set_file_area_in_temp_list(p_file_area);
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				spin_unlock(&p_file_stat->file_stat_lock);	    
			}else{//到这里，file_area被判定还是热file_area，还是继续存在file_stat->file_area_hot链表

				/*如果file_stat->file_area_hot尾巴上连续出现2个file_area还是热file_area，则说明file_stat->file_area_hot链表尾巴上的冷
				 *file_area都遍历完了,遇到链表头的热file_area了，则停止遍历。file_stat->file_area_hot链表头到链表尾，file_area是
				 *由热到冷顺序排布的。之所以要限制连续碰到两个热file_area再break，是因为file_stat->file_area_hot尾巴上的冷file_area
				 *可能此时hot_file_update_file_status()中并发被频繁访问，变成热file_area，但还没来得及移动到file_stat->file_area_hot链表头
				 */
				if(cold_file_area_count ++ > 1)
					break;
			}
		}

		/*该文件file_stat的热file_area个数file_stat->file_area_hot_count小于阀值，则被判定不再是热文件
		  然后file_stat就要移动回hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head链表*/
		if(!is_file_stat_hot_file(p_hot_cold_file_global,p_file_stat)){

			spin_lock(&p_hot_cold_file_global->global_lock);
			hot_cold_file_global_info.file_stat_hot_count --;//热文件数减1
			clear_file_stat_in_file_stat_hot_head_list(p_file_stat);
			set_file_stat_in_file_stat_temp_head_list(p_file_stat);//设置file_stat状态为in_head_temp_list
			if(file_stat_in_large_file(p_file_stat)){
				p_hot_cold_file_global->file_stat_large_count ++;
				list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_large_file_head);
			}
			else
				list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);
			spin_unlock(&p_hot_cold_file_global->global_lock);
		}
	}

	/*遍历global file_stat_delete_head链表上已经被删除的文件的file_stat，
	  一次不能删除太多的file_stat对应的file_area，会长时间占有cpu，后期需要调优一下*/
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_delete_head,hot_cold_file_list){
		if(!file_stat_in_delete(p_file_stat) /*|| file_stat_in_delete_error(p_file_stat)*/)
			panic("%s file_stat:0x%llx not delete status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

		del_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_file_stat_count ++;
	}
	//file_stat的hot链表转移到temp链表的file_area个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.file_area_hot_to_temp_list_count2 = file_area_hot_to_temp_list_count;
	//释放的file_area个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.del_file_area_count = del_file_area_count;
	//释放的file_stat个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.del_file_stat_count = del_file_stat_count;

	//对没有file_area的file_stat的处理
	file_stat_has_zero_file_area_manage(p_hot_cold_file_global);

	//如果此时echo 触发了drop_cache，ASYNC_DROP_CACHES置1，则禁止异步内存回收线程处理global drop_cache_file_stat_head链表上的file_stat
	if(!test_bit(ASYNC_DROP_CACHES, &async_memory_reclaim_status))
	    //处理drop cache的文件的pagecache
	    drop_cache_truncate_inode_pages(p_hot_cold_file_global);

	//打印所有file_stat的file_area个数和page个数
	if(shrink_page_printk_open1)
	    hot_cold_file_print_all_file_stat(p_hot_cold_file_global,NULL,0);
	//打印内存回收时统计的各个参数
	if(shrink_page_printk_open1)
	    printk_shrink_param(p_hot_cold_file_global,NULL,0);

	//每个周期打印hot_cold_file_shrink_counter参数后清0
	memset(&p_hot_cold_file_global->hot_cold_file_shrink_counter,0,sizeof(struct hot_cold_file_shrink_counter));
	return 0;
}
/*卸载该驱动时，先async_memory_reclaim_status=0，确保所有的file_stat和file_area不再被进程访问后。就会执行该函数删除掉所有文件对应的
 *file_stat，同时要把file_stat->mapping->rh_reserved1清0，否则等下次加载驱动，因为mapping->rh_reserved1非0，则直接把file_area添加到
  这个file_stat，但这个file_stat已经delete了，将发生crash*/
static void cold_file_disable_file_stat_mapping(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat)
{
	/*这是驱动卸载过程，但是此时也会并发有进程删除inode而执行__destroy_inode_handler_post()函数。但是这种情况走的else分支，二者都有
	 * spin_lock(&p_hot_cold_file_global->global_lock)加锁防护，不用担心担心并发问题*/
	spin_lock(&p_hot_cold_file_global->global_lock);
	//if(p_file_stat->mapping->rh_reserved1) 不能通过p_file_stat->mapping->rh_reserved1是否0来判断file_stat的文件inode是否释放了，因为之后inode和mapping都是无效的
	if(p_file_stat->mapping){
		p_file_stat->mapping->rh_reserved1 = 0;
		/*此时会并发有进程执行__destroy_inode_handler_post()函数，但是二者都有global_lock加锁防护，以内不用再加内存屏障*/
		//smp_wmb();
	}
	spin_unlock(&p_hot_cold_file_global->global_lock);
}
//删除所有的file_stat和file_area，这个过程不加锁，因为提前保证了不再有进程访问file_stat和file_area
static int cold_file_delete_all_file_stat(struct hot_cold_file_global *p_hot_cold_file_global)
{
	unsigned int del_file_area_count = 0,del_file_stat_count = 0;
	struct file_stat * p_file_stat,*p_file_stat_temp;


	//hot_cold_file_global->file_stat_delete_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_delete_head,hot_cold_file_list){
		/*标记 p_file_stat->mapping->rh_reserved1=0，表示该文件的file_stat已经释放了。否则，mapping->rh_reserved1保存的file_stat指针一直存在，
		 *等下次该文件再被访问执行hot_file_update_file_status(),就会因为mapping->rh_reserved1非0，导致错误以为改文件的file_stat已经分配了，
		  然后使用这个file_stat无效的导致crash*/
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_file_stat_count ++;
	}
	if(shrink_page_printk_open1)
	    printk("hot_cold_file_global->file_stat_delete_head del_file_area_count:%d del_file_stat_count:%d\n",del_file_area_count,del_file_stat_count);
	del_file_area_count = 0;
	del_file_stat_count = 0;

	//hot_cold_file_global->file_stat_hot_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_hot_head,hot_cold_file_list){
		//标记 p_file_stat->mapping->rh_reserved1=0，表示该文件的file_stat已经释放了
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_file_stat_count ++;
	}
	if(shrink_page_printk_open1)
	    printk("hot_cold_file_global->file_stat_hot_head del_file_area_count:%d del_file_stat_count:%d\n",del_file_area_count,del_file_stat_count);
	del_file_area_count = 0;
	del_file_stat_count = 0;

	//hot_cold_file_global->file_stat_temp_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_temp_head,hot_cold_file_list){
		//标记 p_file_stat->mapping->rh_reserved1=0，表示该文件的file_stat已经释放了
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_file_stat_count ++;
	}
	if(shrink_page_printk_open1)
	    printk("hot_cold_file_global->file_stat_temp_head del_file_area_count:%d del_file_stat_count:%d\n",del_file_area_count,del_file_stat_count);
	del_file_area_count = 0;
	del_file_stat_count = 0;

	//hot_cold_file_global->file_stat_temp_large_file_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_temp_large_file_head,hot_cold_file_list){
		//标记 p_file_stat->mapping->rh_reserved1=0，表示该文件的file_stat已经释放了
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_file_stat_count ++;
	}
	if(shrink_page_printk_open1)
	    printk("hot_cold_file_global->file_stat_temp_large_file_head del_file_area_count:%d del_file_stat_count:%d\n",del_file_area_count,del_file_stat_count);
	del_file_area_count = 0;
	del_file_stat_count = 0;

	//hot_cold_file_global->cold_file_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->cold_file_head,hot_cold_file_list){
		//标记 p_file_stat->mapping->rh_reserved1=0，表示该文件的file_stat已经释放了
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_file_stat_count ++;
	}

	//hot_cold_file_global->file_stat_zero_file_area_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_zero_file_area_head,hot_cold_file_list){
		//标记 p_file_stat->mapping->rh_reserved1=0，表示该文件的file_stat已经释放了
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_file_stat_count ++;
	}
	if(shrink_page_printk_open1)
	    printk("hot_cold_file_global->file_stat_zero_file_area_head del_file_area_count:%d del_file_stat_count:%d\n",del_file_area_count,del_file_stat_count);
	del_file_area_count = 0;
	del_file_stat_count = 0;

	//hot_cold_file_global->drop_cache_file_stat_head链表
    list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->drop_cache_file_stat_head,hot_cold_file_list){
		//标记 p_file_stat->mapping->rh_reserved1=0，表示该文件的file_stat已经释放了
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_file_stat_count ++;
	}
	if(p_hot_cold_file_global->file_stat_count != 0){
		panic("cold_file_delete_all_file_stat: file_stat_count:%d !=0 !!!!!!!!\n",p_hot_cold_file_global->file_stat_count);
	}
	if(shrink_page_printk_open1)
	    printk("hot_cold_file_global->drop_cache_file_stat_head del_file_area_count:%d del_file_stat_count:%d\n",del_file_area_count,del_file_stat_count);

	if(shrink_page_printk_open1)
	    printk("hot_cold_file_global->cold_file_head del_file_area_count:%d del_file_stat_count:%d\n",del_file_area_count,del_file_stat_count);

	return 0;
}

static int hot_cold_file_thread(void *p){
	struct hot_cold_file_global *p_hot_cold_file_global = (struct hot_cold_file_global *)p;
	int sleep_count = 0;

	while(1){
		sleep_count = 0;
		while(sleep_count ++ < p_hot_cold_file_global->global_age_period){
			if (kthread_should_stop())
				return 0;
			msleep(1000);
		}

		walk_throuth_all_file_area(p_hot_cold_file_global);
	}
	return 0;
}

static int hot_cold_file_init(void)
{
	int node_count,i,ret;
	hot_cold_file_global_info.file_stat_cachep = kmem_cache_create("file_stat",sizeof(struct file_stat),0,0,NULL);
	hot_cold_file_global_info.file_area_cachep = kmem_cache_create("file_area",sizeof(struct file_area),0,0,NULL);
	hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep = kmem_cache_create("hot_cold_file_area_tree_node",sizeof(struct hot_cold_file_area_tree_node),0,0,NULL);

	if(!hot_cold_file_global_info.file_stat_cachep || !hot_cold_file_global_info.file_area_cachep || !hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep){
	    printk("%s slab 0x%llx 0x%llx 0x%llx error\n",__func__,(u64)hot_cold_file_global_info.file_stat_cachep,(u64)hot_cold_file_global_info.file_area_cachep,(u64)hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep);
		return -1;
	}
	
	INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_hot_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_temp_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_temp_large_file_head);

	INIT_LIST_HEAD(&hot_cold_file_global_info.cold_file_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_delete_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_zero_file_area_head);

	INIT_LIST_HEAD(&hot_cold_file_global_info.drop_cache_file_stat_head);
	spin_lock_init(&hot_cold_file_global_info.global_lock);

	atomic_set(&hot_cold_file_global_info.ref_count,0);
	atomic_set(&hot_cold_file_global_info.inode_del_count,0);

	hot_cold_file_global_info.file_area_hot_to_temp_age_dx = FILE_AREA_HOT_to_TEMP_AGE_DX;
	hot_cold_file_global_info.file_area_refault_to_temp_age_dx = FILE_AREA_REFAULT_TO_TEMP_AGE_DX;
	hot_cold_file_global_info.file_area_temp_to_cold_age_dx = FILE_AREA_TEMP_TO_COLD_AGE_DX;
	hot_cold_file_global_info.file_area_free_age_dx = FILE_AREA_FREE_AGE_DX;
	hot_cold_file_global_info.file_stat_delete_age_dx  = FILE_STAT_DELETE_AGE_DX;
	hot_cold_file_global_info.global_age_period = ASYNC_MEMORY_RECLIAIM_PERIOD;

	//1G的page cache对应多少个file_area
	hot_cold_file_global_info.file_area_count_for_large_file = (1024*1024*1024)/(4096 *PAGE_COUNT_IN_AREA);
	node_count = 0;
	for_each_node_state(i, N_MEMORY)
		node_count ++;

	hot_cold_file_global_info.node_count = node_count;
	//按照内存节点数node_count分配node_count个hot_cold_file_node_pgdat结构体，保存到数组
	hot_cold_file_global_info.p_hot_cold_file_node_pgdat = (struct hot_cold_file_node_pgdat *)kmalloc(node_count*sizeof(struct hot_cold_file_node_pgdat),GFP_KERNEL);
	for(i = 0;i < node_count;i++){
		//保存每个内存节点的pgdat指针
		hot_cold_file_global_info.p_hot_cold_file_node_pgdat[i].pgdat = NODE_DATA(i);
		//初始化每个内存节点的pgdat_page_list链表，将来内存回收时，把每个内存节点要回收的内存保存到pgdat_page_list链表上
		INIT_LIST_HEAD(&hot_cold_file_global_info.p_hot_cold_file_node_pgdat[i].pgdat_page_list);
	}

	hot_cold_file_global_info.hot_cold_file_thead = kthread_run(hot_cold_file_thread,&hot_cold_file_global_info, "hot_cold_file_thread");
	if (IS_ERR(hot_cold_file_global_info.hot_cold_file_thead)) {
		printk("Failed to start  hot_cold_file_thead\n");
		return -1;

	}
	//利用kprobe计数获取内核kallsyms_lookup_name()函数的指针并保存到kallsyms_lookup_name_async，将来用它替代内核原生kallsyms_lookup_name函数
	kp_kallsyms_lookup_name.post_handler = kallsyms_lookup_name_handler_post;
	ret = register_kprobe(&kp_kallsyms_lookup_name);
	if (ret < 0) {
		pr_err("kallsyms_lookup_name register_kprobe failed, returned %d\n", ret);
		return -1;
	}
	kallsyms_lookup_name_async = (void *)(kp_kallsyms_lookup_name.addr);
	unregister_kprobe(&kp_kallsyms_lookup_name);


	//获取用到的内核非export的函数指针
	if(look_up_not_export_function())
		return -1;

#ifdef CONFIG_X86
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	/*x86架构5.10内核后在触发int3 kprobe中断后，会令nmi中断计数加1。接着执行kprobe的函数hot_file_update_file_status,
	 * 执行里边的kmem_cache_alloc分配slab时，执行到allocate_slab->shuffle_freelist->get_random_int分配一个随机数。
	 * 最后有概率执行到__blake2s_final->blake2s_compress->kernel_fpu_begin->irq_fpu_usable函数，在irq_fpu_usable
	 * 函数中，因为nmi中断计数大于0，导致if (WARN_ON_ONCE(in_nmi()))成立，从而触发内核warn告警。为了解决这个问题，
	 * 令slab的random_seq置NULL，从而禁止掉分配slab在shuffle_freelist中执行get_random_int获取随机数。很不理解为什么
	 * x86结构5.10内核要在触发int3 kprobe中断后，要令NMI中断加1，有这个必要吗？NMI中断是mce、长时间关中断才会触发的呀!!!*/
#if 0
	/*编译不通过，一直打印"invalid use of undefined type ‘struct kmem_cache"。*/
	kfree(hot_cold_file_global_info.file_stat_cachep->random_seq);
	hot_cold_file_global_info.file_stat_cachep->random_seq = NULL;
	
	kfree(hot_cold_file_global_info.file_area_cachep->random_seq);
	hot_cold_file_global_info.file_area_cachep->random_seq = NULL;
	
	kfree(hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep->random_seq);
	hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep->random_seq = NULL;
#else
	cache_random_seq_destroy_async(hot_cold_file_global_info.file_stat_cachep);
	cache_random_seq_destroy_async(hot_cold_file_global_info.file_area_cachep);
	cache_random_seq_destroy_async(hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep);
#endif
    #endif
#endif	

	return 0;
}
/*****************************************************************************************/
static void mark_page_accessed_handler_post(struct kprobe *p, struct pt_regs *regs,
		unsigned long flags)
{
	struct page *page = (struct page *)(regs->di);
	if(page){
		hot_file_update_file_status(page);
	}
}
//在执行__destroy_inode_handler_post()能否休眠，万一上层调用者使用spin_lock锁咋办？得看看__destroy_inode()的上层调用者的代码
static void __destroy_inode_handler_post(struct kprobe *p, struct pt_regs *regs,
		unsigned long flags)
{
	struct inode *inode = (struct inode *)(regs->di);
	if(inode && inode->i_mapping && inode->i_mapping->rh_reserved1){
		struct file_stat *p_file_stat = NULL;

		//如果驱动没有卸载
		if(test_bit(ASYNC_MEMORY_RECLAIM_ENABLE,&async_memory_reclaim_status))
		{
			atomic_inc(&hot_cold_file_global_info.inode_del_count);
			/*1:获取最新的inode->i_mapping->rh_reserved1值，如果是0说明文件file_stat已经释放，直接return
			 *2:上边的inode_del_count原子变量加1可能不能禁止编译器重排序，因此这个内存屏障可以防止reorder*/
			smp_rmb();

			/*如果该inode被地方后，不用立即把inode->mapping对应的file_stat立即加锁释放掉。因为即便这个inode被释放后立即又被其他进程分配，
			  但分配后会先对inode清0，inode->mapping 和 inode->mapping->rh_reserved1 全是0，不会受inode->mapping->rh_reserved1指向的老file_stat
			  结构的影响。只用异步内存回收线程里这个file_stat对应的hot file tree中的节点hot_cold_file_area_tree_node结构和该文件的所有file_area
			  结构。同时，到这里时，可能cold_file_disable_file_stat_mapping()函数中已经把inode->i_mapping->rh_reserved1清0，因此需要
			  smp_rmb()后再获取最新的inode->i_mapping->rh_reserved1值，判断是不是0*/
			if(test_bit(ASYNC_MEMORY_RECLAIM_ENABLE,&async_memory_reclaim_status) && inode->i_mapping->rh_reserved1){
				//smp_rmb();这个内存屏障移动到了上边

				/*如果file_stat在cold_file_stat_delete()中被释放了，会把inode->i_mapping->rh_reserved1清0，这里不再使用file_stat。注意，这里不能再使用
				 * file_stat_in_delete(p_file_stat)判断file_stat已经被cold_file_stat_delete()标记delete，因为此时file_stat结构体已经被释放了，这里
				 * 就不能再操作file_stat。cold_file_stat_delete()中释放file_stat前，会先标记inode->i_mapping->rh_reserved1清0，然后等
				 * inode_del_count原子变量是0，即所有执行__destroy_inode_handler_post()的进程退出，然后再释放file_stat结构。此时新的进程再执行
				 * __destroy_inode_handler_post()，inode->i_mapping->rh_reserved1已经是0了，这里就直接return，不会再使用这个已经释放掉的file_stat结构*/
				if(0 == inode->i_mapping->rh_reserved1){
			        atomic_dec(&hot_cold_file_global_info.inode_del_count);
					return;
				}
				p_file_stat = (struct file_stat *)(inode->i_mapping->rh_reserved1);
				//如果
				if(inode->i_mapping != p_file_stat->mapping){
			        atomic_dec(&hot_cold_file_global_info.inode_del_count);
					//unlock_file_stat(p_file_stat);
					return;
				}

				/*对file_stat加锁，此时异步内存回收线程会执行cold_file_stat_delete()释放file_stat结构，然后这里再使用file_stat就会crash了。
				 *必须等cold_file_stat_delete()里释放完file_stat，然后把inode->i_mapping->rh_reserved1清0，释放file_stat锁后。这里才能继续运行，
				  然后因为inode->i_mapping->rh_reserved1是0直接return*/
				lock_file_stat(p_file_stat,1);

				/*xfs文件系统不会对新分配的inode清0，因此要主动对inode->i_mapping->rh_reserved1清0，防止该file_stat和inode被释放后。
				 *立即被其他进程分配了这个inode，但是没有对inode清0，导致inode->i_mapping->rh_reserved1还保存着老的已经释放的file_stat，
				  因为inode->i_mapping->rh_reserved1不是0，不对这个file_stat初始化，然后把file_area添加到这个无效file_stat，就要crash。*/
				inode->i_mapping->rh_reserved1 = 0;
				barrier();
				p_file_stat->mapping = NULL;
				smp_wmb();//在这个加个内存屏障，保证前后代码隔离开。即file_stat有delete标记后，inode->i_mapping->rh_reserved1一定是0，p_file_stat->mapping一定是NULL

				/*这里有个很大的隐患，此时file_stat可能处于global file_stat_hot_head、file_stat_temp_head、file_stat_temp_large_file_head 
				 *3个链表，这里突然设置set_file_stat_in_delete，将来这些global 链表遍历这个file_stat，发现没有 file_stat_in_file_stat_hot_head
				  等标记，会主动触发panic()。不对，set_file_stat_in_delete并不会清理原有的file_stat_in_file_stat_hot_head等标记，杞人忧天了。*/
				set_file_stat_in_delete(p_file_stat);
				//smp_wmb();----set_file_stat_in_delete()现在改成 test_and_set_bit_lock原子操作设置，并且有内促屏障，这个smp_wmb就不需要了

				unlock_file_stat(p_file_stat);
	            if(shrink_page_printk_open1)
				    printk("%s file_stat:0x%llx delete !!!!!!!!!!!!!!!!\n",__func__,(u64)p_file_stat);
			}
			else
			{
		   /*到这个分支说明async_memory_reclaim_status已经被驱动卸载并发清0了，那就goto file_stat_delete分支，择机把
	         inode->i_mapping->rh_reserved1清0，保证这个inode被新的进程读写文件分配后，因文件访问执行hot_file_update_file_status()时，
			 inode->i_mapping->rh_reserved1是0，则重新分配一个新的file_stat，否则会使用inode->i_mapping->rh_reserved1指向的老的已经释放的file_stat*/
				atomic_dec(&hot_cold_file_global_info.inode_del_count);
				goto file_stat_delete;
			}
			//inode_del_count减1的操作操作不能禁止reorder，这里加个内存屏障是确保与上边的unlock_file_stat(p_file_stat)操作隔开
			smp_mb__before_atomic();
			atomic_dec(&hot_cold_file_global_info.inode_del_count);
		}
		else
		{
			/*走这个分支，说明现在驱动在卸载。驱动卸载后时可能释放了file_stat结构，此时__destroy_inode_handler_post()就不能再使用了file_stat了，
            比如"set_file_stat_in_delete(p_file_stat)"执行时就会导致crash。于是两个流程都spin_lock加锁防护并发操作*/ 
file_stat_delete:

			/*这里不用再对file_stat加锁，因为 cold_file_stat_delete()里把inode->i_mapping->rh_reserved1清0放到了spin lock加锁了，已经可以防止并发释放/使用 file_stat*/
			//lock_file_stat(p_file_stat);
			
			/*在这个分支不用再 lock_file_stat加锁了，因为到这里，驱动开始卸载，异步内存回收线程不再运行，同时hot_cold_file_print_all_file_stat()
			 *禁止执行使用file_stat打印信息这个spin lock加锁是防止此时驱动卸载并发执行cold_file_stat_delete()释放file_stat结构，
			  此时这里再使用file_stat就会crash*/
			spin_lock(&hot_cold_file_global_info.global_lock);
			/*inode->i_mapping->rh_reserved1是0说明驱动卸载流程执行cold_file_stat_delete()释放了file_stat，把inode->i_mapping->rh_reserved1清0，
			 *这里不能再使用file_stat*/
			if(0 == inode->i_mapping->rh_reserved1){
				spin_unlock(&hot_cold_file_global_info.global_lock);
				return;
			}
			p_file_stat = (struct file_stat *)(inode->i_mapping->rh_reserved1);
			if(inode->i_mapping->rh_reserved1 && inode->i_mapping == p_file_stat->mapping){
				p_file_stat->mapping->rh_reserved1 = 0;
				barrier();
				//驱动卸载，释放file_stat时，遇到p_file_stat->mapping是NULL，就不再执行"p_file_stat->mapping->rh_reserved1 = 0"了，会crash
				p_file_stat->mapping = NULL;
				smp_wmb();
				/*正常情况，走到这个分支是驱动卸载流程，这里把file_stat标记delete后，异步内存回收线程可能不会把有delete标记的file_stat从
				 *global temp或hot或large_file链表移动到global delete链表。这样就有问题了，file_stat的状态跟它所在的链表不匹配，就会造成crash。
				  因此这里就不再使用set_file_stat_in_delete了，通过p_file_stat->mapping是NULL也能判断file_stat已经delete。这就要求判断
				  file_stat是否已经删除的代码里，要使用if(file_stat_in_delete(p_file_stat) || (NULL == p_file_stat->mapping))两个判断一起加上
				  ，不能单独只使用if(file_stat_in_delete(p_file_stat)判断file_stat是否已删除!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
				//set_file_stat_in_delete(p_file_stat);---关键代码，不要删
			}
			spin_unlock(&hot_cold_file_global_info.global_lock);
		}
	}
}
static int __init async_memory_reclaime_for_cold_file_area_init(void)
{
	int ret;
	//kp_mark_page_accessed.post_handler = mark_page_accessed_handler_post;
	kp_read_cache_func.post_handler = mark_page_accessed_handler_post;
	kp_write_cache_func.post_handler = mark_page_accessed_handler_post;
	kp__destroy_inode.post_handler = __destroy_inode_handler_post;


	/*ret = register_kprobe(&kp_mark_page_accessed);
	if (ret < 0) {
		pr_err("kp_mark_page_accessed register_kprobe failed, returned %d\n", ret);
		goto err;
	}*/
	ret = register_kprobe(&kp_read_cache_func);
	if (ret < 0) {
		pr_err("kp_read_cache_func register_kprobe failed, returned %d\n", ret);
		goto err;
	}
	ret = register_kprobe(&kp_write_cache_func);
	if (ret < 0) {
		pr_err("kp_write_cache_func register_kprobe failed, returned %d\n", ret);
		goto err;
	}

	ret = register_kprobe(&kp__destroy_inode); 
	if (ret < 0) {
		pr_err("kp__destroy_inode register_kprobe failed, returned %d\n", ret);
		goto err;
	}
	ret = hot_cold_file_init();
	if(ret < 0){
		goto err;
	}

	ret = hot_cold_file_proc_init(&hot_cold_file_global_info);
	if(ret < 0){
		goto err;
	}
	return 0;
err:
	/*if(kp_mark_page_accessed.post_handler)
		unregister_kprobe(&kp_mark_page_accessed);*/
	if(kp_read_cache_func.post_handler)
		unregister_kprobe(&kp_read_cache_func);
	if(kp_write_cache_func.post_handler)
		unregister_kprobe(&kp_write_cache_func);


	if(kp__destroy_inode.post_handler)
		unregister_kprobe(&kp__destroy_inode);

	if(hot_cold_file_global_info.hot_cold_file_thead)
		kthread_stop(hot_cold_file_global_info.hot_cold_file_thead);

	hot_cold_file_proc_exit(&hot_cold_file_global_info);
	return ret;
}
static void __exit async_memory_reclaime_for_cold_file_area_exit(void)
{ 
	//这里是重点，先等异步内存回收线程结束运行，就不会再使用任何的file_stat了，此时可以放心执行下边的cold_file_delete_all_file_stat()释放所有文件的file_stat
	kthread_stop(hot_cold_file_global_info.hot_cold_file_thead);

	//为使用 clear_bit_unlock()把async_memory_reclaim_status清0，这样使用async_memory_reclaim_status的地方不用再smp_rmb获取最的async_memory_reclaim_status值0
	//async_memory_reclaim_status = 0;
	//smp_wmb();
	clear_bit_unlock(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status);//驱动卸载，把async_memory_reclaim_status清0

	//如果还有进程在访问file_stat和file_area，p_hot_cold_file_global->ref_count大于0，则先休眠
	while(atomic_read(&hot_cold_file_global_info.ref_count)){
		msleep(1);
	}
	/*如果有进程正在因inode删除而执行__destroy_inode_handler_post()里"set_file_stat_in_delete(p_file_stat)"的操作file_stat的代码，
	 *导致inode_del_count大于0，则等待退出*/
	while(atomic_read(&hot_cold_file_global_info.inode_del_count)){
		msleep(1);
	}

	cold_file_delete_all_file_stat(&hot_cold_file_global_info);
	//unregister_kprobe(&kp_mark_page_accessed);
	unregister_kprobe(&kp_read_cache_func);
	unregister_kprobe(&kp_write_cache_func);
	unregister_kprobe(&kp__destroy_inode);
	kmem_cache_destroy(hot_cold_file_global_info.file_stat_cachep);
	kmem_cache_destroy(hot_cold_file_global_info.file_area_cachep);
	kmem_cache_destroy(hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep);
	hot_cold_file_proc_exit(&hot_cold_file_global_info);
}
module_init(async_memory_reclaime_for_cold_file_area_init);
module_exit(async_memory_reclaime_for_cold_file_area_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hujunpeng : dongzhiyan_linux@163.com");
