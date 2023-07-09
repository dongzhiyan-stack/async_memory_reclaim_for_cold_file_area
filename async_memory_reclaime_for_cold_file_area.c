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

int open_shrink_printk = 1;
int open_shrink_printk1 = 0;
int hot_file_shrink_enable = 8388624;
void inline update_async_shrink_page(struct page *page);
int hot_file_init(void);
/***************************************************************/
//一个 hot_file_area 包含的page数，默认6个
#define PAGE_COUNT_IN_AREA_SHIFT 3
#define PAGE_COUNT_IN_AREA (1UL << PAGE_COUNT_IN_AREA_SHIFT)

#define TREE_MAP_SHIFT	6
#define TREE_MAP_SIZE	(1UL << TREE_MAP_SHIFT)
#define TREE_MAP_MASK (TREE_MAP_SIZE - 1)

#define TREE_ENTRY_MASK 3
#define TREE_INTERNAL_NODE 1

//file_area在 GOLD_FILE_AREA_LEVAL 个周期内没有被访问则被判定是冷file_area，然后释放这个file_area的page
#define GOLD_FILE_AREA_LEVAL  5

#define FILE_AREA_HOT_BIT (1 << 0)//hot_file_area的bit0是1表示是热的file_area_hot,是0则是冷的。bit1是1表示是热的大文件，是0则是小文件
//一个冷hot_file_area，如果经过HOT_FILE_AREA_FREE_LEVEL个周期，仍然没有被访问，则释放掉hot_file_area结构
#define HOT_FILE_AREA_FREE_LEVEL  6
//当一个hot_file_area在一个周期内访问超过FILE_AREA_HOT_LEVEL次数，则判定是热的hot_file_area
#define FILE_AREA_HOT_LEVEL 3
//一个hot_file_area表示了一片page范围(默认6个page)的冷热情况，比如page索引是0~5、6~11、12~17各用一个hot_file_area来表示
struct hot_file_area
{
    //每次hot_file_stat的hot_file_area_free链表上的hot_file_area，每次遍历cold_time加1，如果cold_time达到阀值就释放掉hot_file_area结构。
    //如果在这个过程中hot_file_area又被访问了，则cold_time清0，并且把hot_file_area移动到hot_file_area_temp链表。
    //unsigned char cold_time;
    //不同取值表示hot_file_area当前处于哪种链表，hot_file_area_temp:0 hot_file_area_hot:1 hot_file_area_cold:2 hot_file_area_free_temp:3 hot_file_area_free:4 hot_file_area_refault:5
    unsigned char file_area_state;
    //该hot_file_area 上轮被访问的次数
    //unsigned int last_access_count;
    //该file_area最新依次被访问时的global_age，global_age - file_area_age差值大于 GOLD_FILE_AREA_LEVAL，则判定file_area是冷file_area，然后释放该file_area的page
    unsigned long file_area_age;
    //该hot_file_area当前周期被访问的次数
    unsigned int area_access_count;
    //该hot_file_area里的某个page最近一次被回收的时间点，单位秒
    unsigned int shrink_time;
    //hot_file_area通过hot_file_area_list添加hot_file_stat的各种链表
    struct list_head hot_file_area_list;
    //指向父hot_file_area_tree_node节点，作用是在hot_file_area_detele()函数把file_area从hot file tree剔除时，顺便剔除没有成员的父节点，并且逐级向上剔除
    //父节点，最终删除整个hot file tree。其实这个parent可以没有，因为可以根据file_area的start_index从hot file tree找到它的父节点，也能实现同样效果呢。
    //但是这样耗时比较多，并且根据file_area的start_index从hot file tree找到它的父节点需要hot_file_stat_lock加锁，稍微耗时，影响hot_file_update_file_status()获取hot_file_stat_lock锁
    struct hot_file_area_tree_node *parent;
    //该hot_file_area代表的N个连续page的起始page索引
    pgoff_t start_index;
};
struct hot_file_area_tree_node
{
    //与该节点树下最多能保存多少个page指针有关
    unsigned char   shift;
    //在节点在父节点中的偏移
    unsigned char   offset;
    //指向父节点
    struct hot_file_area_tree_node *parent;
    //该节点下有多少个成员
    unsigned int    count;
    //是叶子节点时保存hot_file_area结构，是索引节点时保存子节点指针
    void    *slots[TREE_MAP_SIZE];
};
struct hot_file_area_tree_root
{
    unsigned int  height;//树高度
    struct hot_file_area_tree_node __rcu *root_node;
};
//热点文件统计信息，一个文件一个
struct hot_file_stat
{
    struct address_space *mapping;
    //hot_file_stat通过hot_file_list添加到hot_file_global的hot_file_head链表
    struct list_head hot_file_list;
    unsigned char file_stat_status;//bit0表示冷文件还是热文件，bit1表示大文件还是小文件
    unsigned int file_area_count;//总hot_file_area结构个数
    unsigned int file_area_hot_count;//热hot_file_area结构个数
//  unsigned char *hot_file_area_cache;
    struct hot_file_area_tree_root hot_file_area_tree_root_node;
    spinlock_t hot_file_stat_lock;
    //频繁被访问的文件page对应的hot_file_area存入这个头结点
    struct list_head hot_file_area_hot;
    //不冷不热处于中间状态的hot_file_area结构添加到这个链表，新分配的hot_file_area就添加到这里
    struct list_head hot_file_area_temp;
    //访问很少的文件page对应的hot_file_area，移动到该链表
    struct list_head hot_file_area_cold;
    //每轮扫描被释放内存page的hot_file_area结构临时先添加到这个链表。hot_file_area_free_temp有存在的必要
    struct list_head hot_file_area_free_temp;
    //所有被释放内存page的hot_file_area结构最后添加到这个链表，如果长时间还没被访问，就释放hot_file_area结构。
    struct list_head hot_file_area_free;
    //hot_file_area的page被释放后，但很快又被访问，发生了refault，于是要把这种page添加到hot_file_area_refault链表，短时间内不再考虑扫描和释放
    struct list_head hot_file_area_refault;
    //本轮扫描移动到hot_file_area_cold链表的file_area个数
    //unsigned int file_area_count_in_cold_list;
    //上一轮扫描移动到hot_file_area_cold链表的file_area个数
    //unsigned int old_file_area_count_in_cold_list;
};
struct hot_file_node_pgdat
{
    pg_data_t *pgdat;
    struct list_head pgdat_page_list;
};
//热点文件统计信息全局结构体
struct hot_file_global
{
    //被判定是热文本的hot_file_stat添加到hot_file_head链表,超过50%或者80%的file_area都是热的，则该文件就是热文件，文件的file_stat要移动到global的hot_file_head链表
    struct list_head hot_file_head;
    //新分配的文件hot_file_stat默认添加到hot_file_head_temp链表
    struct list_head hot_file_head_temp;
    //如果文件file_stat上的page cache数超过1G，则把file_stat移动到这个链表。将来内存回收时，优先遍历这种file_stat，因为file_area足够多，能遍历到更多的冷file_area，回收到内存page
    struct list_head hot_file_head_temp_large;
    //当file_stat的file_area个数达到file_area_count_for_large_file时，表示该文件的page cache数达到1G。因为一个file_area包含了多个page，一个file_area并不能填满page，
    //因此实际file_stat的file_area个数达到file_area_count_for_large_file时，实际该文件的的page cache数应该小于1G
    int file_area_count_for_large_file;

    struct list_head cold_file_head;
    struct list_head hot_file_head_delete;
    //在cold_fiLe_head链表的file_stat个数
    //unsigned int file_stat_count_in_cold_list;
    unsigned int hot_file_stat_count;
    unsigned long file_stat_count ;
    unsigned long global_age;//每个周期加1
    struct kmem_cache *hot_file_stat_cachep;
    struct kmem_cache *hot_file_area_cachep;
    struct kmem_cache *hot_file_area_tree_node_cachep;
    spinlock_t hot_file_lock;
    struct hot_file_node_pgdat *p_hot_file_node_pgdat;
    struct task_struct *hot_file_thead;
    int node_count;
};
static struct kprobe kp_kallsyms_lookup_name = {
    .symbol_name    = "kallsyms_lookup_name",
};
static void kallsyms_lookup_name_handler_post(struct kprobe *p, struct pt_regs *regs,
	                unsigned long flags)
{
}

#if 0
//返回1说明hot_file_area结构处于hot_file_area_temp链表，不冷不热
static inline int file_area_in_temp_list(struct hot_file_area *p_hot_file_area)
{
    return (0 == p_hot_file_area->file_area_state);
}
//设置 p_hot_file_area->file_area_state = 0表示该 hot_file_area处于hot_file_area_temp链表
static inline void set_file_area_in_temp_list(struct hot_file_area *p_hot_file_area)
{
    p_hot_file_area->file_area_state  = 0;
    smp_wmb();
}

//返回1说明hot_file_area结构处于hot_file_area_cold链表，冷file_file_area
static inline int file_area_in_cold_list(struct hot_file_area *p_hot_file_area)
{
    return (1 == p_hot_file_area->file_area_state);
}
//设置 p_hot_file_area->file_area_state = 1表示该 hot_file_area处于hot_file_area_cold链表
static inline void set_file_area_in_cold_list(struct hot_file_area *p_hot_file_area)
{
    p_hot_file_area->file_area_state  = 1;
    smp_wmb();
}

//返回1说明hot_file_area结构处于hot_file_area_hot链表，是热hot_file_area
static inline int file_area_in_hot_list(struct hot_file_area *p_hot_file_area)
{
    return (2 == p_hot_file_area->file_area_state);
}
//设置 p_hot_file_area->file_area_state = 2表示该 hot_file_area处于hot_file_area_hot链表
static inline void set_file_area_in_hot_list(struct hot_file_area *p_hot_file_area)
{
    p_hot_file_area->file_area_state  = 2;
    smp_wmb();
}

//返回1说明hot_file_area结构处于hot_file_area_refault链表
static inline int file_area_in_refault_list(struct hot_file_area *p_hot_file_area)
{
    return (5 == p_hot_file_area->file_area_state);
}
//设置 p_hot_file_area->file_area_state = 5 表示该 hot_file_area处于hot_file_area_refault链表
static inline void set_file_area_in_refault_list(struct hot_file_area *p_hot_file_area)
{
    p_hot_file_area->file_area_state  = 5;
    smp_wmb();
}

//返回1说明hot_file_area结构处于hot_file_area_free_temp链表
static inline int file_area_in_free_temp_list(struct hot_file_area *p_hot_file_area)
{
    return (3 == p_hot_file_area->file_area_state);
}
//设置 p_hot_file_area->file_area_state = 3 表示该 hot_file_area处于hot_file_area_free_temp链表
static inline void set_file_area_in_free_temp_list(struct hot_file_area *p_hot_file_area)
{
    p_hot_file_area->file_area_state  = 3;
    smp_wmb();
}

//返回1说明hot_file_area结构处于hot_file_area_free链表，不冷不热
static inline int file_area_in_free_list(struct hot_file_area *p_hot_file_area)
{
    return (4 == p_hot_file_area->file_area_state);
}
//设置 p_hot_file_area->file_area_state = 4 表示该 hot_file_area处于hot_file_area_free链表
static inline void set_file_area_in_free_list(struct hot_file_area *p_hot_file_area)
{
    p_hot_file_area->file_area_state  = 4;
    smp_wmb();
}
#else
enum file_area_status{
    F_file_area_in_temp_list,
    F_file_area_in_cold_list,
    F_file_area_in_hot_list,
    F_file_area_in_free_temp_list,
    F_file_area_in_free_list,
    F_file_area_in_refault_list
};
//不能使用 clear_bit、set_bit、test_bit，因为要求p_hot_file_area->file_area_state是64位数据，但实际只是u8型数据

//设置file_area的状态，在哪个链表
#define CLEAR_FILE_AREA_STATUS(list_name) \
static inline void clear_file_area_in_##list_name(struct hot_file_area *p_hot_file_area)\
      { p_hot_file_area->file_area_state &= ~(1 << F_file_area_in_##list_name);}
//    {clear_bit(file_area_in_##list_name,p_hot_file_area->file_area_state);}
//清理file_area在哪个链表的状态
#define SET_FILE_AREA_STATUS(list_name) \
static inline void set_file_area_in_##list_name(struct hot_file_area *p_hot_file_area)\
    { p_hot_file_area->file_area_state |= (1 << F_file_area_in_##list_name);}
    //{set_bit(file_area_in_##list_name,p_hot_file_area->file_area_state);}
//测试file_area在哪个链表
#define TEST_FILE_AREA_STATUS(list_name) \
static inline int file_area_in_##list_name(struct hot_file_area *p_hot_file_area)\
    {return p_hot_file_area->file_area_state & (1 << F_file_area_in_##list_name);}
    //{return test_bit(file_area_in_##list_name,p_hot_file_area->file_area_state);}

#define FILE_AREA_STATUS(list_name)     \
        CLEAR_FILE_AREA_STATUS(list_name) \
        SET_FILE_AREA_STATUS(list_name)  \
        TEST_FILE_AREA_STATUS(list_name)

FILE_AREA_STATUS(temp_list)
FILE_AREA_STATUS(cold_list)
FILE_AREA_STATUS(hot_list)
FILE_AREA_STATUS(free_temp_list)
FILE_AREA_STATUS(free_list)
FILE_AREA_STATUS(refault_list)
#endif

#if 0
//返回1说明hot_file_stat处于walk_throuth_all_hot_file_area()函数中的临时链表
static inline int file_stat_in_hot_file_other_list(struct hot_file_stat *p_hot_file_stat)
{
   return (0 == p_hot_file_stat->file_stat_status);
}
//设置hot_file_stat处于walk_throuth_all_hot_file_area()函数中的临时链表
static inline void set_file_stat_in_other_list(struct hot_file_stat *p_hot_file_stat)
{
    p_hot_file_stat->file_stat_status = 0;
    smp_wmb();
}

//返回1说明hot_file_stat处于global hot_file_head_temp链表
static inline int file_stat_in_hot_file_head_temp(struct hot_file_stat *p_hot_file_stat)
{
   return (1 == p_hot_file_stat->file_stat_status);
}
//设置hot_file_stat处于global hot_file_head_temp链表
static inline void set_file_stat_in_head_temp_list(struct hot_file_stat *p_hot_file_stat)
{
    p_hot_file_stat->file_stat_status = 1;
    smp_wmb();
}

//返回1说明hot_file_stat处于global hot_file_head链表
static inline int file_stat_in_hot_file_head(struct hot_file_stat *p_hot_file_stat)
{
   return (2 == p_hot_file_stat->file_stat_status);
}
//设置hot_file_stat处于global hot_file_head链表
static inline void set_file_stat_in_hot_file_head(struct hot_file_stat *p_hot_file_stat)
{
    p_hot_file_stat->file_stat_status = 2;
    smp_wmb();
}

//设置hot_file_stat是大文件
static inline void set_file_stat_in_hot_file_head_temp_large(struct hot_file_stat *p_hot_file_stat)
{
    p_hot_file_stat->file_stat_status = 3;
    smp_wmb();
}
//返回1说明是large file
static inline int file_stat_in_hot_file_head_temp_large(struct hot_file_stat *p_hot_file_stat)
{
   return (3 == p_hot_file_stat->file_stat_status);
}
#else
enum file_stat_status{
    F_file_stat_in_hot_file_head_list,
    F_file_stat_in_hot_file_head_temp_list,
    F_file_stat_in_large_file,
    F_file_stat_in_delete,
};
//不能使用 clear_bit、set_bit、test_bit，因为要求p_hot_file_stat->file_stat_status是64位数据，但这里只是u8型数据

//设置file_stat的状态，在哪个链表
#define CLEAR_FILE_STAT_STATUS(name)\
static inline void clear_file_stat_in_##name##_list(struct hot_file_stat *p_hot_file_stat)\
    {p_hot_file_stat->file_stat_status &= ~(1 << F_file_stat_in_##name##_list);}
//    {clear_bit(file_stat_in_##list_name,p_hot_file_stat->file_stat_status);}
//清理file_stat在哪个链表的状态
#define SET_FILE_STAT_STATUS(name)\
static inline void set_file_stat_in_##name##_list(struct hot_file_stat *p_hot_file_stat)\
    {p_hot_file_stat->file_stat_status |= (1 << F_file_stat_in_##name##_list);}
//    {set_bit(file_stat_in_##list_name,p_hot_file_stat->file_stat_status);}
//测试file_stat在哪个链表
#define TEST_FILE_STAT_STATUS(name)\
static inline int file_stat_in_##name##_list(struct hot_file_stat *p_hot_file_stat)\
    {return (p_hot_file_stat->file_stat_status & (1 << F_file_stat_in_##name##_list));}
//    {return test_bit(file_stat_in_##list_name,p_hot_file_stat->file_stat_status);}

#define FILE_STAT_STATUS(name) \
    CLEAR_FILE_STAT_STATUS(name) \
    SET_FILE_STAT_STATUS(name) \
    TEST_FILE_STAT_STATUS(name)

FILE_STAT_STATUS(hot_file_head)
FILE_STAT_STATUS(hot_file_head_temp)
//FILE_STAT_STATUS(large_file)
    
//设置文件的状态，大小文件等
#define CLEAR_FILE_STATUS(name)\
static inline void clear_file_stat_in_##name(struct hot_file_stat *p_hot_file_stat)\
    {p_hot_file_stat->file_stat_status &= ~(1 << F_file_stat_in_##name);}
//清理文件的状态，大小文件等
#define SET_FILE_STATUS(name)\
static inline void set_file_stat_in_##name(struct hot_file_stat *p_hot_file_stat)\
    {p_hot_file_stat->file_stat_status |= (1 << F_file_stat_in_##name);}
//测试文件的状态，大小文件等
#define TEST_FILE_STATUS(name)\
static inline int file_stat_in_##name(struct hot_file_stat *p_hot_file_stat)\
    {return (p_hot_file_stat->file_stat_status & (1 << F_file_stat_in_##name));}

#define FILE_STATUS(name) \
    CLEAR_FILE_STATUS(name) \
    SET_FILE_STATUS(name) \
    TEST_FILE_STATUS(name)

FILE_STATUS(large_file)
FILE_STATUS(delete)
#endif



struct hot_file_global hot_file_global_info;

/*************以下代码不同内核版本可能有差异******************************************************************************************/
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
void (*mem_cgroup_uncharge_async)(struct page *page);
compound_page_dtor * (*compound_page_dtors_async)[NR_COMPOUND_DTORS];

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
	//__count_memcg_events(memcg, idx, count);
	__count_memcg_events_async(memcg, idx, count);
	local_irq_restore(flags);
}
//源码跟内核count_memcg_page_event()一样，只是改了名字
//static inline void count_memcg_page(struct page *page,
static inline void count_memcg_page_event_async(struct page *page,
		       enum vm_event_item idx)
{
    	if (page->mem_cgroup)
            //count_memcg_events(page->mem_cgroup, idx, 1);
            count_memcg_events_async(page->mem_cgroup, idx, 1);
}


//static __always_inline void __update_lru_size(struct lruvec *lruvec,
static __always_inline void __update_lru_size_async(struct lruvec *lruvec,
					enum lru_list lru, enum zone_type zid,
									int nr_pages)
{
    struct pglist_data *pgdat = lruvec_pgdat(lruvec);

    //__mod_lruvec_state(lruvec, NR_LRU_BASE + lru, nr_pages);
    __mod_lruvec_state_async(lruvec, NR_LRU_BASE + lru, nr_pages);
    __mod_zone_page_state(&pgdat->node_zones[zid],
		NR_ZONE_LRU_BASE + lru, nr_pages);
}
//static __always_inline void update_lru_size(struct lruvec *lruvec,
static __always_inline void update_lru_size_async(struct lruvec *lruvec,
					enum lru_list lru, enum zone_type zid,
					int nr_pages)
{
    //__update_lru_size(lruvec, lru, zid, nr_pages);
    __update_lru_size_async(lruvec, lru, zid, nr_pages);
#ifdef CONFIG_MEMCG
    //mem_cgroup_update_lru_size(lruvec, lru, zid, nr_pages);
    mem_cgroup_update_lru_size_async(lruvec, lru, zid, nr_pages);
#endif
}
//static __always_inline void del_page_from_lru_list(struct page *page,
static __always_inline void del_page_from_lru_list_async(struct page *page,
					struct lruvec *lruvec, enum lru_list lru)
{
    list_del(&page->lru);
    //update_lru_size(lruvec, lru, page_zonenum(page), -hpage_nr_pages(page));
    update_lru_size_async(lruvec, lru, page_zonenum(page), -hpage_nr_pages(page));
}


//static __always_inline void add_page_to_lru_list(struct page *page,
static __always_inline void add_page_to_lru_list_async(struct page *page,
					struct lruvec *lruvec, enum lru_list lru)
{
    //update_lru_size(lruvec, lru, page_zonenum(page), hpage_nr_pages(page));
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

    while (!list_empty(page_list)) {
        struct address_space *mapping;
        struct page *page;
	int may_enter_fs;

        cond_resched();

	page = lru_to_page(page_list);
	list_del(&page->lru);

	if (!trylock_page(page))
	    goto keep;

        mapping = page_mapping(page);
        may_enter_fs = (sc->gfp_mask & __GFP_FS);

	/****page是witeback页*********************/
	if (PageWriteback(page)) {
    	    if(!PageReclaim(page)){
	        SetPageReclaim(page);
		nr_writeback += 1;
	    }else if (PageReclaim(page) &&test_bit(PGDAT_WRITEBACK, &pgdat->flags)){
	        nr_immediate += 1;
	    }
	}

	/****page是脏页*********************/
	if (PageDirty(page)) {
                nr_dirty++;
                goto activate_locked;	       
		//这里goto keep 分支，忘了unlock_page()了，导致其他进程访问到该page时因为page lock就休眠了
		//goto keep;
	}

	/*******释放page的bh******************/
	if (page_has_private(page)) {
		if(open_shrink_printk)
		    printk("17:%s %s %d page:0x%llx page->flags:0x%lx mapping:0x%llx page_has_private\n",__func__,current->comm,current->pid,(u64)page,page->flags,(u64)mapping);

		if (!try_to_release_page(page,sc->gfp_mask)){
			if(open_shrink_printk)
			    printk("18:%s %s %d page:0x%llx page->flags:0x%lx activate_locked\n",__func__,current->comm,current->pid,(u64)page,page->flags);
			goto activate_locked;
		}
		if (!mapping && page_count(page) == 1) {
			unlock_page(page);
			if (put_page_testzero(page)){
				if(open_shrink_printk)
				    printk("18_1:%s %s %d page:0x%llx page->flags:0x%lx put_page_testzero\n",__func__,current->comm,current->pid,(u64)page,page->flags);
				goto free_it;
			}
			else {
				if(open_shrink_printk)
				    printk("18_2:%s %s %d page:0x%llx page->flags:0x%lx page_has_private\n",__func__,current->comm,current->pid,(u64)page,page->flags);

				nr_reclaimed++;
				continue;
			}
		}
	}
        /********把page从radix tree剔除************************/
        if (!mapping || !__remove_mapping_async(mapping, page, true)){
            if(open_shrink_printk)
            printk("19:%s %s %d page:0x%llx page->flags:0x%lx mapping:0x%llx keep_locked\n",__func__,current->comm,current->pid,(u64)page,page->flags,(u64)mapping);
	    goto keep_locked;
        }


	unlock_page(page);
free_it:
	nr_reclaimed++;
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
    return nr_reclaimed;
}
/*
//把hot_file_area对应的page从lru链表剔除，然后添加到链表dst,这个过程需要
inline int get_page_from_hot_file_area(struct hot_file_stat * p_hot_file_stat,struct hot_file_area *p_hot_file_area,struct list_head *dst)
{
    int i;
    struct address_space *mapping = p_hot_file_stat->mapping;
    //得到hot_file_area对应的page
    for(i = 0;i < PAGE_COUNT_IN_AREA;i ++){
        page = xa_load(&mapping->i_pages, hot_file_area->start_index + i)
	if (page && !xa_is_value(page)) {
            list_move(&page->lru,dst);
	}
    }
}*/
static int __hot_file_isolate_lru_pages(pg_data_t *pgdat,struct page * page,struct list_head *dst,isolate_mode_t mode)
{
    struct lruvec *lruvec;
    int lru;
    
    //prefetchw_prev_lru_page(page, src, flags);
    lruvec = mem_cgroup_lruvec(page->mem_cgroup, pgdat);
    lru = page_lru_base_type(page);

    /*__isolate_lru_page里清除page的PageLRU属性，因为要把page从lru链表剔除了，并且令page的引用计数加1*/
    //switch (__isolate_lru_page(page, mode)) {
    switch (__isolate_lru_page_async(page, mode)) {
    case 0:
	    //nr_pages = hpage_nr_pages(page);
	    //nr_taken += nr_pages;
	    //nr_zone_taken[page_zonenum(page)] += nr_pages;
	    //page原本在lru链表，现在要移动到其他链表，要把page在链表的上一个page保存到async_shrink_page
	    //update_async_shrink_page(page);
	    //list_move(&page->lru, dst);

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
	    if(open_shrink_printk)
		printk("2:%s %s %d page:0x%llx page->flags:0x%lx EBUSY\n",__func__,current->comm,current->pid,(u64)page,page->flags);
	    break;

    default:
	//实际测试发现，这个会成立，这个正常，因为该page可能被内核内存回收线程隔离成功，就没有lru属性，但是这里不再触发bug，仅仅一个告警打印
	if(open_shrink_printk)
	    printk("3:%s %s %d page:0x%llx PageUnevictable:%d PageLRU:%d !!!!!!!!!!!!!\n",__func__,current->comm,current->pid,(u64)page,PageUnevictable(page),PageLRU(page));
        #if 0
	    BUG();
	#endif
    }
    
    /*更新 acitve/inactive file 链入链表的page数，减少nr_taken个，因为page将要从lru链表移除*/
    //update_lru_sizes(lruvec, lru, nr_zone_taken);------
    return -1;
}
//static void putback_inactive_pages(struct lruvec *lruvec, struct list_head *page_list)
static unsigned int hot_file_putback_inactive_pages(struct pglist_data *pgdat, struct list_head *page_list)
{
	//struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	unsigned int move = 0;
	LIST_HEAD(pages_to_free);
        struct lruvec *lruvec;
        
	spin_lock_irq(&pgdat->lru_lock);
	/*
	 * Put back any unfreeable pages.
	 */
	while (!list_empty(page_list)) {
		struct page *page = lru_to_page(page_list);
		int lru;

                if(open_shrink_printk)
		    printk("1:%s %s %d page:0x%llx page->flags:0x%lx\n",__func__,current->comm,current->pid,(u64)page,page->flags);

		VM_BUG_ON_PAGE(PageLRU(page), page);
		list_del(&page->lru);
	   	if (unlikely(!page_evictable_async(page))) {
			spin_unlock_irq(&pgdat->lru_lock);
			putback_lru_page_async(page);
			spin_lock_irq(&pgdat->lru_lock);
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
                        if(open_shrink_printk)
		            printk("2:%s %s %d put_page_testzero page:0x%llx page->flags:0x%lx PageCompound:%d\n",__func__,current->comm,current->pid,(u64)page,page->flags,PageCompound(page));
			__ClearPageLRU(page);
			__ClearPageActive(page);
			//里边调用了__mod_lruvec_state、mem_cgroup_update_lru_size函数，导致“undefined!”
			//del_page_from_lru_list(page, lruvec, lru);
			del_page_from_lru_list_async(page, lruvec, lru);

			if (unlikely(PageCompound(page))) {
				spin_unlock_irq(&pgdat->lru_lock);
				mem_cgroup_uncharge_async(page);
				(*get_compound_page_dtor_async(page))(page);
				spin_lock_irq(&pgdat->lru_lock);
			} else
				list_add(&page->lru, &pages_to_free);
		}
	}
        spin_unlock_irq(&pgdat->lru_lock);
	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	list_splice(&pages_to_free, page_list);
	return move;
}

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

//static int (*__isolate_lru_page_async)(struct page *page, isolate_mode_t mode);
//static int (*page_evictable_async)(struct page *page);
static int(* __remove_mapping_async)(struct address_space *mapping, struct folio *folio,bool reclaimed, struct mem_cgroup *target_memcg);
static void (*mem_cgroup_update_lru_size_async)(struct lruvec *lruvec, enum lru_list lru,int zid, int nr_pages);
//static struct lruvec *(*mem_cgroup_page_lruvec_async)(struct page *page, struct pglist_data *pgdat);
//static void (*__mod_lruvec_state_async)(struct lruvec *lruvec, enum node_stat_item idx,int val);
static void (*free_unref_page_list_async)(struct list_head *list);
static void (*__mem_cgroup_uncharge_list_async)(struct list_head *page_list);
static void (*__count_memcg_events_async)(struct mem_cgroup *memcg, enum vm_event_item idx,unsigned long count);

static unsigned long (*kallsyms_lookup_name_async)(const char *name);
//static bool (*can_demote_async)(int nid, struct scan_control_async *sc);-----编译成inline类型了
void (*putback_lru_page_async)(struct page *page);
//static unsigned int (*demote_page_list_async)(struct list_head *demote_pages,struct pglist_data *pgdat);-----编译成inline类型了
static struct mem_cgroup *root_mem_cgroup_async;
//static void (*folio_check_dirty_writeback_async)(struct folio *folio,bool *dirty, bool *writeback);-----编译成inline类型了
static void (*try_to_unmap_flush_async)(void);
void (*__mod_memcg_lruvec_state_async)(struct lruvec *lruvec, enum node_stat_item idx,int val);
static  bool (*mem_cgroup_disabled_async)(void);
extern void __mod_lruvec_page_state(struct page *page, enum node_stat_item idx,int val);

compound_page_dtor * const (*compound_page_dtors_async)[NR_COMPOUND_DTORS];

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
void __mod_lruvec_state_async(struct lruvec *lruvec, enum node_stat_item idx,
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

static __always_inline
void lruvec_add_folio_async(struct lruvec *lruvec, struct folio *folio)
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

static __always_inline
void lruvec_del_folio_async(struct lruvec *lruvec, struct folio *folio)
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
    #if 1
	LIST_HEAD(demote_pages);
	bool do_demote_pass;
    #endif
	unsigned int nr_reclaimed = 0;
	unsigned int pgactivate = 0;

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
                    if(open_shrink_printk)
		        printk("1:%s %s %d page:0x%llx page->flags:0x%lx trylock_page(page)\n",__func__,current->comm,current->pid,(u64)page,page->flags);
		    goto keep;
                }
                //这个判断要注释掉，异步内存回收的page可能处于active lru链表
		//VM_BUG_ON_PAGE(PageActive(page), page);

		nr_pages = compound_nr(page);

		/* Account the number of base pages even though THP */
		sc->nr_scanned += nr_pages;

		if (unlikely(!page_evictable_async(page)))
			goto activate_locked;

		if (!sc->may_unmap && page_mapped(page))
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
                        if(open_shrink_printk)
		            printk("2:%s %s %d page:0x%llx page->flags:0x%lx PageWriteback\n",__func__,current->comm,current->pid,(u64)page,page->flags);
			if(PageReclaim(page)){
			    SetPageReclaim(page);
			    stat->nr_writeback += nr_pages;
			}else if (PageReclaim(page) &&test_bit(PGDAT_WRITEBACK, &pgdat->flags)){
			   stat->nr_immediate += nr_pages;
			}

		    goto activate_locked; 
		}
 
                /*****demote_pages 是什么鬼??????????????????????????????**************/
		/*
		 * Before reclaiming the page, try to relocate
		 * its contents to another node.
		 */
	    #if 1
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
                    if(open_shrink_printk)
		        printk("3:%s %s %d page:0x%llx page->flags:0x%lx PageDirtyn",__func__,current->comm,current->pid,(u64)page,page->flags);
		    goto activate_locked;
		    //这里goto keep 分支，忘了unlock_page()了，导致其他进程访问到该page时因为page lock就休眠了!!!!!!!!!!!!!!!!
		    //goto keep;
		}

		if (page_has_private(page)) {
			if (!try_to_release_page(page, sc->gfp_mask)){
                               if(open_shrink_printk)
		                   printk("4:%s %s %d page:0x%llx page->flags:0x%lx try_to_release_page\n",__func__,current->comm,current->pid,(u64)page,page->flags);
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
                    if(open_shrink_printk)
		        printk("5:%s %s %d page:0x%llx page->flags:0x%lx __remove_mapping\n",__func__,current->comm,current->pid,(u64)page,page->flags);

		    goto keep_locked;
                }
		unlock_page(page);
free_it:
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

	return nr_reclaimed;
}
//static unsigned int move_pages_to_lru(struct lruvec *lruvec,struct list_head *list)
static unsigned int hot_file_putback_inactive_pages(struct pglist_data *pgdat, struct list_head *page_list)
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
                        spin_unlock_irq(&lruvec->lru_lock);
		    }
		    lruvec = lruvec_new;
		    //对新的page所属的pgdat进行spin lock
		    spin_lock_irq(&lruvec->lru_lock);
		}

		VM_BUG_ON_PAGE(PageLRU(page), page);
		list_del(&page->lru);
		if (unlikely(!page_evictable_async(page))) {
			spin_unlock_irq(&lruvec->lru_lock);
			putback_lru_page_async(page);
			spin_lock_irq(&lruvec->lru_lock);
			continue;
		}
		/*
		 * The SetPageLRU needs to be kept here for list integrity.
		 * Otherwise:
		 *   #0 move_pages_to_lru             #1 release_pages
		 *   if !put_page_testzero
		 *				      if (put_page_testzero())
		 *				        !PageLRU //skip lru_lock
		 *     SetPageLRU()
		 *     list_add(&page->lru,)
		 *                                        list_add(&page->lru,)
		 */
		SetPageLRU(page);

		if (unlikely(put_page_testzero(page))) {
			__clear_page_lru_flags(page);

			if (unlikely(PageCompound(page))) {
				spin_unlock_irq(&lruvec->lru_lock);
				destroy_compound_page_async(page);
				spin_lock_irq(&lruvec->lru_lock);
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
            spin_unlock_irq(&lruvec->lru_lock);
	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	list_splice(&pages_to_free, page_list);

        return nr_moved;
}
static int  __hot_file_isolate_lru_pages(pg_data_t *pgdat,struct page * page,struct list_head *dst,isolate_mode_t mode)
{
    struct lruvec *lruvec;
    //int lru;

    //prefetchw_prev_lru_page(page, src, flags); 不需要

    if (!PageLRU(page))
        return -1;

#if 0//在源头已经确保page不是mmap的，这里不用重复判断
    if (!sc->may_unmap && page_mapped(page))
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
# error Need LINUX_VERSION_CODE
#endif

int look_up_not_export_function(void)
{
//由于5.1*内核kallsyms_lookup_name函数不再export了，无法再ko使用。没办法只能利用kprobe计数获取内核kallsyms_lookup_name()函数的指针并保存到kallsyms_lookup_name_async。
    //用它替代内核原生kallsyms_lookup_name函数。低版本的内核不用这么操作，但为了保持兼容只能用kallsyms_lookup_name_async替代kallsyms_lookup_name。
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
	printk("__isolate_lru_page_async:0x%llx page_evictable_async:0x%llx __remove_mapping_async:0x%llx mem_cgroup_update_lru_size:0x%llx mem_cgroup_page_lruvec:0x%llx __mod_lruvec_state:0x%llx free_unref_page_list:0x%llx mem_cgroup_uncharge_list:0x%llx __count_memcg_events:0x%llx putback_lru_page_async:0x%llx try_to_unmap_flush_async:0x%llx compound_page_dtors_async:0x%llx mem_cgroup_uncharge_async:0x%llx\n",(u64)__isolate_lru_page_async,(u64)page_evictable_async,(u64)__remove_mapping_async,(u64)mem_cgroup_update_lru_size_async,(u64)mem_cgroup_page_lruvec_async,(u64)__mod_lruvec_state_async,(u64)free_unref_page_list_async,(u64)mem_cgroup_uncharge_list_async,(u64)__count_memcg_events_async,(u64)putback_lru_page_async,(u64)try_to_unmap_flush_async,(u64)compound_page_dtors_async,(u64)mem_cgroup_uncharge_async);
        return -1;
    }
#else
    //__isolate_lru_page_async = (void*)kallsyms_lookup_name_async("__isolate_lru_page");
    //page_evictable_async = (void*)kallsyms_lookup_name_async("page_evictable");
    __remove_mapping_async = (void*)kallsyms_lookup_name_async("__remove_mapping");
    mem_cgroup_update_lru_size_async = (void*)kallsyms_lookup_name_async("mem_cgroup_update_lru_size");
    //mem_cgroup_page_lruvec_async = (void*)kallsyms_lookup_name_async("mem_cgroup_page_lruvec");
    //__mod_lruvec_state_async = (void*)kallsyms_lookup_name_async("__mod_lruvec_state");
    free_unref_page_list_async = (void*)kallsyms_lookup_name_async("free_unref_page_list");
    //mem_cgroup_uncharge_list_async = (void*)kallsyms_lookup_name_async("mem_cgroup_uncharge_list");
    __count_memcg_events_async = (void*)kallsyms_lookup_name_async("__count_memcg_events");

    //新加的
    mem_cgroup_disabled_async = (void *)kallsyms_lookup_name_async("mem_cgroup_disabled");
    __mod_memcg_lruvec_state_async = (void *)kallsyms_lookup_name_async("__mod_memcg_lruvec_state");
    //folio_check_dirty_writeback_async = (void *)kallsyms_lookup_name_async("folio_check_dirty_writeback");
    putback_lru_page_async = (void *)kallsyms_lookup_name_async("putback_lru_page");
    //can_demote_async = (void *)kallsyms_lookup_name_async("can_demote");
    //demote_page_list_async = (void*)kallsyms_lookup_name_async("demote_page_list");
    try_to_unmap_flush_async = (void*)kallsyms_lookup_name_async("try_to_unmap_flush");
    __mem_cgroup_uncharge_list_async = (void*)kallsyms_lookup_name_async("__mem_cgroup_uncharge_list");
    root_mem_cgroup_async = (struct mem_cgroup *)kallsyms_lookup_name_async("root_mem_cgroup");
    compound_page_dtors_async= (compound_page_dtor *  (*)[NR_COMPOUND_DTORS])kallsyms_lookup_name_async("compound_page_dtors");
    if(!__remove_mapping_async || !mem_cgroup_update_lru_size_async  || !free_unref_page_list_async || !__count_memcg_events_async  || !mem_cgroup_disabled_async  || !__mod_memcg_lruvec_state_async  || !putback_lru_page_async  || !try_to_unmap_flush_async  || !root_mem_cgroup_async || !compound_page_dtors_async || !__mem_cgroup_uncharge_list_async){
	printk("__remove_mapping_async:0x%llx mem_cgroup_update_lru_size_async:0x%llx free_unref_page_list_async:0x%llx __count_memcg_events_async:0x%llx mem_cgroup_disabled_async:0x%llx __mod_memcg_lruvec_state_async:0x%llx putback_lru_page_async:0x%llx try_to_unmap_flush_async:0x%llx root_mem_cgroup_async:0x%llx compound_page_dtors_async:0x%llx __mem_cgroup_uncharge_list_async:0x%llx",(u64)__remove_mapping_async,(u64)mem_cgroup_update_lru_size_async,(u64)free_unref_page_list_async ,(u64)__count_memcg_events_async ,(u64)mem_cgroup_disabled_async ,(u64)__mod_memcg_lruvec_state_async,(u64)putback_lru_page_async,(u64)try_to_unmap_flush_async ,(u64)root_mem_cgroup_async,(u64)compound_page_dtors_async,(u64)__mem_cgroup_uncharge_list_async);
        return -1;
    }

    /*mem_cgroup_disabled明明是inline类型，但是cat /proc/kallsyms却可以看到它的函数指针。并且还可以在ko里直接用mem_cgroup_disabled()函数。但是测试表明，cat /proc/kallsyms看到的mem_cgroup_disabled()函数指针  和 在驱动里直接打印mem_cgroup_disabled()函数指针，竟然不一样，奇葩了，神奇了!!为了安全还是用cat /proc/kallsyms看到的函数指针吧!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
    if((u64)mem_cgroup_disabled_async != (u64)mem_cgroup_disabled){
        printk("mem_cgroup_disabled_async:0x%llx != mem_cgroup_disabled:0x%llx\n",(u64)mem_cgroup_disabled_async,(u64)mem_cgroup_disabled);
        //return -1;
    }
#endif

    printk("kallsyms_lookup_name:0x%llx root_mem_cgroup:0x%llx\n",(u64)(kp_kallsyms_lookup_name.addr),(u64)root_mem_cgroup_async);
   return 0;
}


//遍历p_hot_file_stat对应文件的hot_file_area_free链表上的hot_file_area结构，找到这些hot_file_area结构对应的page，这些page被判定是冷页，可以回收
static unsigned long hot_file_isolate_lru_pages(struct hot_file_global *p_hot_file_global,struct hot_file_stat * p_hot_file_stat,
	                               struct list_head *hot_file_area_free)
{
    struct hot_file_area *p_hot_file_area,*tmp_hot_file_area;
    int i;
    struct address_space *mapping = p_hot_file_stat->mapping;
    //unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
    isolate_mode_t mode = ISOLATE_UNMAPPED;
    pg_data_t *pgdat = NULL;
    struct page *page;
    unsigned int isolate_pages = 0;
    struct list_head *dst;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
    //struct folio *folio = NULL;
    struct lruvec *lruvec = NULL,*lruvec_new = NULL;
#endif 
    //!!!!!!!!!!!!!!隐藏非常深的地方，这里遍历hot_file_area_free(即)链表上的file_area时，可能该file_area在hot_file_update_file_status()中被访问而移动到了temp链表
    //这里要用list_for_each_entry_safe()，不能用list_for_each_entry!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    list_for_each_entry_safe(p_hot_file_area,tmp_hot_file_area,hot_file_area_free,hot_file_area_list){
        //if(open_shrink_printk)
	//    printk("%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

#if 0 
	//--------这段注释不要删除-------------------很重要

	/*这里要对p_hot_file_area->shrink_time的赋值需要加锁。
	  情况1：这里先加锁。对p_hot_file_area->shrink_time赋值，然后1s内执行hot_file_update_file_status()获取锁，访问到该file_area，则判定该file_area是refault file_area。
	  情况2:hot_file_update_file_status()先加锁，访问该file_area，令p_hot_file_global->global_age和p_hot_file_area->file_area_age相等，则
	        这里直接continue，不再释放hot_file_area的page。

	  有了hot_file_stat_lock加锁，完美解决p_hot_file_area->shrink_time在这里的赋值 和 在hot_file_update_file_status()函数的访问 时，数据不同步的问题，但是
	  这个加锁真的有必要吗????????要多次加锁,太浪费性能了，影响hot_file_update_file_status()函数的spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock)加锁
	 */
	spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
	//如果此时hot_file_area又被访问了，则不再释放，并移动回hot_file_area_temp链表
	//if(p_hot_file_area->area_access_count - p_hot_file_area->last_access_count  0){
	if(p_hot_file_global->global_age == p_hot_file_area->file_area_age){
            list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
	    set_file_area_in_temp_list(p_hot_file_area);
	    spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
	    continue;
	}
        //获取hot_file_area内存回收的时间，ktime_to_ms获取的时间是ms，右移10近似除以1000，变成单位秒
	p_hot_file_area->shrink_time = ktime_to_ms(ktime_get()) >> 10;
	spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
#else
	/*对p_hot_file_area->shrink_time的赋值不再加锁，
	 *情况1:如果这里先对p_hot_file_area->shrink_time赋值，然后1s内hot_file_update_file_status()函数访问该file_area，则file_area被判定是refault file_area。
	 *情况2:先有hot_file_update_file_status()函数访问该file_area,但p_hot_file_area->shrink_time还是0，则file_area无法被判定是refault file_area.
          但因为file_area处于file_stat->hot_file_area_free_temp链表上，故把file_area移动到file_stat->hot_file_area_temp链表。然后这里执行到
	  if(!file_area_in_free_list(p_hot_file_area))，if成立，则不再不再回收该file_area的page。这种情况也没事

	 *情况3:如果这里快要对p_hot_file_area->shrink_time赋值，但是先有hot_file_update_file_status()函数访问该file_area，但p_hot_file_area->shrink_time还是0，
	        则file_area无法被判定是refault file_area.但因为file_area处于file_stat->hot_file_area_free_temp链表上，故把file_area移动到file_stat->hot_file_area_temp链表。
		但是，在把file_area移动到file_stat->hot_file_area_free_temp链表上前，这里并发先执行了对p_hot_file_area->shrink_time赋值当前时间和
		if(!file_area_in_free_list(p_hot_file_area))，但if不成立。然后该file_area的page还要继续走内存回收流程。相当于刚访问过的file_area却被回收内存page了.
		这种情况没有办法。只有在hot_file_update_file_status()函数中，再次访问该file_area时，发现p_hot_file_area->shrink_time不是0，说明刚该file_area经历过一次
		重度refault现象，于是也要把file_area移动到refault链表。注意，此时file_area处于file_stat->hot_file_area_free_temp链表。
	 * */

    	//获取hot_file_area内存回收的时间，ktime_to_ms获取的时间是ms，右移10近似除以1000，变成单位秒
	p_hot_file_area->shrink_time = ktime_to_ms(ktime_get()) >> 10;
	smp_mb();
	//正常此时file_area处于file_stat->hot_file_area_free_temp链表，但如果正好此时该file_area被访问了，则就要移动到file_stat->hot_file_area_temp链表。
	//这种情况file_area的page就不能被释放了
	if(!file_area_in_free_list(p_hot_file_area)){
	    p_hot_file_area->shrink_time = 0;
	    continue;
	}
#endif
	//设置 hot_file_area的状态为 in_free_list
	//set_file_area_in_free_list(p_hot_file_area);------这里不再设置set_file_area_in_free_list的状态，因为设置需要hot_file_stat_lock加锁，浪费性能
	
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
	//得到hot_file_area对应的page
	for(i = 0;i < PAGE_COUNT_IN_AREA;i ++){
	    page = xa_load(&mapping->i_pages, p_hot_file_area->start_index + i);
	    if (page && !xa_is_value(page)) {
		//正常情况每个文件的page cache的page都应该属于同一个node，进行一次spin_lock_irq(&pgdat->lru_lock)就行，但是也有可能属于不同的内存节点node，
		//那就需要每次出现新的page所属的内存节点node的pgdat=page_pgdat(page)时，那就把老的pgdat=page_pgdat(page)解锁，对新的pgdat=page_pgdat(page)加锁
		//pgdat != page_pgdat(page)成立说明前后两个page所属node不一样，那就要把前一个page所属pgdat spin unlock，然后对新的page所属pgdat spin lock
                if(unlikely(pgdat != page_pgdat(page)))
		{
		    //第一次进入这个if，pgdat是NULL，此时不用spin unlock，只有后续的page才需要
		    if(pgdat){
			//对之前page所属pgdat进行spin unlock
                        spin_unlock_irq(&pgdat->lru_lock);
		    }
		    //pgdat最新的page所属node节点对应的pgdat
		    pgdat = page_pgdat(page);
		    if(pgdat != p_hot_file_global->p_hot_file_node_pgdat[pgdat->node_id].pgdat)
	                panic("pgdat not equal\n");
		    //对新的page所属的pgdat进行spin lock
		    spin_lock_irq(&pgdat->lru_lock);
		}
		//在把page从lru链表移动到dst临时链表时，必须spin_lock_irq(&pgdat->lru_lock)加锁
		//list_move(&page->lru,dst);-----在下边的hot_file_area_isolate_lru_pages实现
		
                /*这里又是另外一个核心点。由于现在前后两次的page不能保证处于同一个内存node、同一个memory、同一个lruvec，因此
		 * 只能每来一个page，都执行类似原版内存回收的isolate_lru_pages，判断能否隔离，可以隔离的话。再计算当前page所属的
		 * pgdat、lruvec、active/inacitve lru编号，然后把page从lru链表剔除，再令lru链表的page数减1。而原来内存回收的isolate_lru_pages函数，进行隔离的
		 * 多个page一定来自同一个pgdat、lruvec、active/inacitve lru编号，就不用针对隔离的每个page再计算这些参数了。并且把所有page
		 * 都隔离后，同一执行update_lru_sizes()令lru链表的page数减去隔离成功的page数。显然，这样更节省cpu，我的方法稍微有点耗cpu，尤其是隔离page多的情况下*/
		dst = &p_hot_file_global->p_hot_file_node_pgdat[pgdat->node_id].pgdat_page_list;//把page保存到对应node的hot_file_node_pgdat链表上
		if(__hot_file_isolate_lru_pages(pgdat,page,dst,mode) != 0){
		    //goto err; 到这里说明page busy，不能直接goto err返回错误，继续遍历page，否则就中断了整个内存回收流程，完全没必要
		    continue;
		}
		isolate_pages ++;
	    }
	}
    #else
	//得到hot_file_area对应的page
	for(i = 0;i < PAGE_COUNT_IN_AREA;i ++){
	    //folio = xa_load(&mapping->i_pages, p_hot_file_area->start_index + i);
	    //if (folio && !xa_is_value(folio)) {
	    page = xa_load(&mapping->i_pages, p_hot_file_area->start_index + i);
	    if (page && !xa_is_value(page)) {
		//为了保持兼容，还是把每个内存节点的page都移动到对应hot_file_global->p_hot_file_node_pgdat[pgdat->node_id].pgdat_page_list链表上
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

		dst = &p_hot_file_global->p_hot_file_node_pgdat[pgdat->node_id].pgdat_page_list;//把page保存到对应node的hot_file_node_pgdat链表上
		if(__hot_file_isolate_lru_pages(pgdat,page,dst,mode) != 0){
		    //goto err; 到这里说明page busy，不能直接goto err返回错误，继续遍历page，否则就中断了整个内存回收流程，完全没必要
		    continue;
		}
		isolate_pages ++;
	    }
	}
    #endif	
    }
//err:   
 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
    if(pgdat)
	spin_unlock_irq(&pgdat->lru_lock);
#else
    if(lruvec)
	spin_unlock_irq(&lruvec->lru_lock);
#endif
    return isolate_pages;
}

/*************以上代码不同内核版本可能有差异******************************************************************************************/

#if 0 //------------------------------这些是早期编写的代码，虽然没用的，但是有价值
#define HOT_FILE_AREA_CACHE_COUNT 6
#define HOT_FILE_AARE_RANGE 3
//文件热点区域信息头结点，每片热点区域的头结点
-struct hot_file_area_hot
{
    //1:hot_file_area_hot后边的区域是hot_file_area结构体
    //0:保存的是分配的4k内存page指针，这些page内存保存的是hot_file_area。此时说明hot_file_stat->hot_file_area_cache指向内存的hot_file_area全用完了。只能分配新的内存page了，用来保存
    //后续更多的hot_file_area结构，用来保存这些文件热点区域数据
    int file_area_magic;
    //文件热点区域个数
    unsigned int file_area_count;
    //最小起始文件page索引
    pgoff_t min_start_index;
    //最大起始文件page索引
    pgoff_t max_end_index;
}
//文件每个热点区域信息结构体，一个热点区域一个该结构体
-struct hot_file_area
{
    pgoff_t start_index;
    pgoff_t end_index;
    unsigned int area_access_count;
}
//热点文件统计信息，一个文件一个
-struct hot_file_stat
{
    struct address_space *mapping;
    struct list_head hot_file_list;
    struct async_shrink_file 
    unsigned int file_access_count;
    unsigned char *hot_file_area_cache;
}
//热点文件统计信息全局结构体
-struct hot_file_global
{
    struct list_head hot_file_head;
    struct list_head cold_file_head_temp;
    unsigned long hot_file_count;
    unsigned long cold_file_count;
    struct kmem_cache *hot_file_cachep;
    struct kmem_cache *hot_file_area_cachep;
    spinlock_t hot_file_lock;
}
-struct hot_file_global hot_file_global_info;
int async_shrink_file_init()
{
    unsigned int hot_file_area_cache_size = sizeof(struct hot_file_area)*HOT_FILE_AREA_CACHE_COUNT + sizeof(struct hot_file_area_hot);
    hot_file_global_info.hot_file_stat_cachep = KMEM_CACHE(hot_file_stat,0);
    hot_file_global_info.hot_file_area_cachep = kmem_cache_create("hot_file_area",hot_file_area_cache_size,0,0,NULL);
    INIT_LIST_HEAD(&hot_file_global_info.hot_file_head);
    INIT_LIST_HEAD(&hot_file_global_info.cold_file_head_temp);
    spin_lock_init(&hot_file_global_info.hot_file_lock);
}
//hot_file_area_start是保存文件热点区域结构体hot_file_area的首地址，vaild_hot_file_area_count是这片内存有效文件热点区域个数，all_hot_file_area_count是总热点区域个数
//page_index是本次要匹配查找的文件page索引。
//利用二分法查找包含索引index的hot_file_area
struct hot_file_area *find_match_hot_file_area(struct hot_file_area *hot_file_area_start,unsigned int vaild_hot_file_area_count,unsigned int all_hot_file_area_count
	                                      pgoff_t page_index,int *new_hot_file_area_index)
{
    int left,middle,right;
    struct hot_file_area *hot_file_area_middle;
    int search_count;
    /*举例
     0   1     2     3     4      5
     0-5 10-15 20-30 35-40 50-60 70-80

case1: page_index=16
step 1:left=0 right=6 middle=left + (right - 1)/2=2 则hot_file_area="20-30"
       page_index < hot_file_area.start_index(20)，则right = middle - 1=1

step 2:left=0 right=1 middle=left + (right - 1)/2=0 则hot_file_area="0-5"
       page_index > hot_file_area.end_index(5)，则left = middle + 1=1

step 3:left=1 right=1 middle=left + (right - 1)/2=1 则hot_file_area="10-15"
       page_index > hot_file_area.end_index(15)，则left = middle + 1=2
       因为left>right导致while(left <= right) 不成立退出循环,middle此时是1，指向hot_file_area="10-15",
       middle+1=2指向的hot_file_area="20-30",因为page_index=16与hot_file_area.start_index(20)相差大于HOT_FILE_AARE_RANGE(3),
       则本次的page_index不能合并到hot_file_area="20-30"

case2: page_index=51
step 1:left=0 right=6 middle=left + (right - 1)/2=2 则hot_file_area="20-30"
       page_index > hot_file_area.end_index(30)，则left = middle + 1=3

step 2:left=3 right=6 middle=left + (right - 1)/2=5 则hot_file_area="70-80"
       page_index < hot_file_area.start_index(70)，则right = middle - 1=4

case 3:left=3 right=4 middle=left + (right - 1)/2=4 则hot_file_area="50-60"
     page_index 在 则hot_file_area="50-60"范围内找到匹配的,成功返回

case3: page_index=69
step 1:left=0 right=6 middle=left + (right - 1)/2=2 则hot_file_area="20-30"
       page_index > hot_file_area.end_index(30)，则left = middle + 1=3

step 2:left=3 right=6 middle=left + (right - 1)/2=5 则hot_file_area="70-80"
       page_index < hot_file_area.start_index(70)，则right = middle - 1=4

case 3:left=3 right=4 middle=left + (right - 1)/2=4 则hot_file_area="50-60"
     page_index >hot_file_area.end_index(60),则 left = middle + 1=5
     因为left>right导致while(left <= right) 不成立退出循环,middle此时是4，指向hot_file_area="50-60",
     middle+1=5指向的hot_file_area="70-80",因为page_index=69与hot_file_area.start_index(70)相差小于HOT_FILE_AARE_RANGE(3),
     则本次的page_index=69可以合并到hot_file_area="20-30"!!!!!!!!!!!!!
     */
    *new_hot_file_area_index = -1; 
    right = vaild_hot_file_area_count;
    search_count = 0;
    while(left <= right){
        middle = left + (right - 1)/2;
        search_count ++;
	//得到中间的hot_file_area
        hot_file_area_middle = hot_file_area_start + middle;
	//待查找的索引index 小于中间区域hot_file_area的起始索引，要去文件热点区域更左半部分搜索，于是right = m - 1令右边界减少一半
        if(index < hot_file_area_middle->start_index)
	    right = middle - 1;
	//待查找的索引index 大于中间区域hot_file_area的结束索引，要去文件热点区域更右半部分搜索，于是left = m + 1令左边界增大一半
	else if(index > hot_file_area_middle->end_index)
	    left = middle + 1;
	else{//到这里肯定待查找的索引在当前hot_file_area包含的索引范围内
	    break;
	}
    }
    //middle不可能大于
    if(middle >= vaild_hot_file_area_count){
        panic("middle:%d %d error\n",vaild_hot_file_area_count,all_hot_file_area_count)
    }
    if(open_shrink_printk)
        printk("%s %s %d hot_file_area_count:%d index:%d search_count:%d\n",__func__,current->comm,current->pid,hot_file_area_count,index,search_count);
    
    //找到包含page_index索引的的hot_file_area则返回它
    if(page_index >= hot_file_area_middle->start_index && page_index <= hot_file_area_middle->end_index){
	return hot_file_area_middle;
    }
    else{
        /*case1 ****************************************************/
	/*
         0   1     2     3     4      5-----------原始文件hot_file_stat的hot_file_area_cache指向的内存只能容纳下6个hot_file_area。
         0-5 10-15 20-30 35-40 50-60 70-80
	 举例，vaild_hot_file_area_count=6，当page_index=69，经历上边的循环后middle=4，middle+1=5指向的hot_file_area="70-80"的start_index(70)与page_index=69差距
	 小于HOT_FILE_AARE_RANGE(3)，则本次的索引page_index=69就可以合并到hot_file_area="70-80"。因为本次访问的索引是69，按照经验下次访问的page索引
	 很有可能是70，这符合文件访问经验，依次向后访问。下边这个if做的就是这件事，
	 当前middle必须小于vaild_hot_file_area_count - 1，这样才能保证至少
	 有一个空闲的hot_file_area槽位。比如hot_file_area_count=6，当前内存区只有6个hot_file_area结构。走到这个分支，说明找不到
	 */
        //if(vaild_hot_file_area_count <= all_hot_file_area_count){
	    //比如 middle=4 vaild_hot_file_area_count=6，看middle+1=5指向的hot_file_area.start_index是否与page_index很接近。
	    //middle指向倒数第2个有效的hot_file_area，middle+1=5指向的 hot_file_area是最后一个有效的hot_file_area，看page_index能否合并到middle+1=5指向的 hot_file_area
	    if(middle < vaild_hot_file_area_count -1){//比如 middle=4 vaild_hot_file_area_count=6，看middle+5指向的hot_file_area.start_index是否与page_index很接近
		//middle指向middle后边那个的hot_file_area，看page_index与这个hot_file_area.start_index是否很接近，很接近就可以合并
		hot_file_area_middle = hot_file_area_start + middle + 1;
		if(hot_file_area_middle->start_index - page_index <= HOT_FILE_AARE_RANGE){
		    //更新hot_file_area的start_index 为 page_index，相当于把page_index何必到了当前的hot_file_area
		    hot_file_area_middle->start_index = page_index;
		    return hot_file_area_middle;
		}
	    }
	
        /*case2 ****************************************************/
        //执行到这里，说明没有找到没有找到匹配page_index的hot_file_area。但是还有剩余的空间，可以分配一个hot_file_area，保存本次的page->index
	if(vaild_hot_file_area_count < all_hot_file_area_count){
	    //分配一个新的hot_file_area，存本次的page->index
	    hot_file_area_middle = hot_file_area_start + vaild_hot_file_area_count;
	    hot_file_area_middle->start_index = page_index;
	    hot_file_area_middle->end_index = page_index + HOT_FILE_AARE_RANGE;
	    return hot_file_area_middle;
	}

        /*case3 ****************************************************/
	//执行到这里，说明 说明没有找到没有找到匹配page_index的hot_file_area，但是没有剩余的空间可以分配一个hot_file_area保存本次的page->index了。
	//那只能分配一个新的4K page内存，分配新的hot_file_area，保存本次的page->index
	if(vaild_hot_file_area_count >= all_hot_file_area_count){
	    return NULL;
	}

	/*以上是能想到的几种情况，但是还有隐藏很深的问题，看如下来自
	 
	 0   1     2     3     4      5-------------------索引地址必须由左向右依次增大
         0-5 10-15 20-30 35-40 50-60 75-80

	 vaild_hot_file_area_count=6，当page_index=65，经历上边的循环后middle=4，middle+1=5指向的hot_file_area="75-80"的start_index(75)与page_index=65
	 差距大于HOT_FILE_AARE_RANGE(3)，则本次的索引page_index=65 无法合并到hot_file_area="75-80"。怎么办？
	 要把弄一个新的hot_file_area ，保存page_index=65，然后把它插入到 hot_file_area="50-60"和hot_file_area="75-80"之间，
         具体操作起来非常麻烦，要先做成这样
	 0   1     2     3     4      5
         0-5 10-15 20-30 35-40 50-60 65-68
	 hot_file_area="75-80"就被挤走了，只能分配一个新的4K page内存，然后把hot_file_area="75-80"移动到这个4K内存page。
 	 是吗，并不是，按照预期算法，实际要把原有的在hot_file_area_cache指向的内存的6个hot_file_area也移动到这个4K内存page，如下
	 0   1     2     3     4      5     6
         0-5 10-15 20-30 35-40 50-60 65-68  75-80

	 然后 hot_file_area_cache指向的内存不再保存hot_file_area，而是变成索引，比如第一片内存指向前边分配的4K内存page，索引范围是0-80
	 0     1   2   3   4  5
	 0-80

         
	 还有一种情况,如下6片hot_file_area保存在4K page内存
	 0   1     2     3     4      6      7 
         0-5 10-15 20-30 35-40 50-60  75-80  90-100-------------------索引地址必须由左向右依次增大
         假设此时 page_index=69 要插入这里，最后m=4，则要分配一个新的 hot_file_area，保存page_index=69，然后把插入到里边如下
	 0   1     2     3     4      6      
         0-5 10-15 20-30 35-40 50-60  69-72
         然后把原有的 hot_file_area="75-80"和hot_file_area="90-100"复制，向后移动一个hot_file_area位置，整体变成如下:
	 0   1     2     3     4      6     6      7  
         0-5 10-15 20-30 35-40 50-60  69-72 75-80  90-100
         

	 还有一种情况
	 0   1     2     3     4      6      7 
         0-5 10-15 20-30 35-40 50-60  63-80  90-100-------------------索引地址必须由左向右依次增大
         此时 page_index=61要插入到里边
	 0   1     2     3     4      6      7 
         0-5 10-15 20-30 35-40 50-60  61-80  90-100
	 然后是否要把hot_file_area="61-80"合并到 hot_file_area="50-60 "，并且把 hot_file_area="90-100"向前移动一个 hot_file_area位置
	 0   1     2     3     4      7 
         0-5 10-15 20-30 35-40 50-80  90-100

    方案2	 
         这样的算法太复杂了！会因为发生插入新的hot_file_area或者老的hot_file_area合并到其他hot_file_area，导致频繁向前或者向
	 后复制移动N个 hot_file_area结构数据，浪费cpu！并且可能令 hot_file_area的索引范围无限扩大，比如的hot_file_area索引范围达到100，
	 这样就不太合适了，这种page索引范围太大了。粒度太大了！可以发现，原有的算法会遇到各种ext4 extent麻烦，比较浪费cpu。并且
	 hot_file_area的索引范围不受控制，大是很大，小时很小(将导致分配很多hot_file_area结构)。没办法，只能改进算法。
	 令每个hot_file_area的索引范围固定，比如每个hot_file_area的索引范围固定是5，也是从左向右排列，禁止hot_file_area向前或向后复制
	 数据结构，不再令相邻hot_file_area合并。
	 0   1    2     3     4     5    
         1-5 6-10 11-15 16-20 21-25 26-30-------------------索引地址必须由左向右依次增大
	 现在一个 hot_file_area索引范围是5，当文件很大时，弹性令hot_file_area索引范围增大到10,甚至20。总体觉得，这种算法更优，
	 更简单，避免繁琐的ext4 extent的合并、分割、赋值 操作。

	 当hot_file_area很多时，就分配4K的page内存，保存更多的hot_file_area

	 0-30 31-60 61-90 91-120 121-150  151-180--------原始文件hot_file_stat的hot_file_area_cache指向的内存只能容纳下6个hot_file_area空间，现在变成索引
         |
	 |
	 0   1    2     3     4     5     6     7     ........
         1-5 6-10 11-15 16-20 21-25 26-30 31-35 36-40 ........ -------------------4k page内存能容纳很多个hot_file_area

        这个方案看着貌似合理，但其实也有很大问题：一个全新的文件，10G，现在开始访问文件，但是直接访问文件索引 10000，这种情况线上是有的
	，并不是所有文件都是从文件0地址开始访问！

	这种情况要分配很多无效的中间索引page
	
	0-10000 10001-20000 *-* *-* *-*  50001-60000--------原始文件hot_file_stat的hot_file_area_cache指向的内存只能容纳下6个hot_file_area空间，现在变成索引
        
	0--5000  5001-10000   ------这里的两个page内存，都是索引，每个page的所有包含的索引总范围是5000
                  |
	          |
                  10000-10003 10004-10006 10007-10009 10011-10013  ----这个page内存才是有效的hot_file_area，包含了本次的文件索引10000

        看到没，为了找到第一次访问的page索引10000，就要无端分配3个page，浪费了内存。极端情况，分配的无效的page只会更多，这个方案也不行

    方案3	
        radix tree +ext4 extent

	把中间索引节点"0--5000"和 "5001-10000" 两个4K内存page，换成类似radix tree的radix_tree_node节点就行，一个节点消耗不了多少内存。
        而radix_tree_node的成员void *slots[64]保存一个个hot_file_area结构指针，保存热点索引区域
        */

	//否则就要把page_index插入到 middle指向的热点区域hot_file_area，原来位置的向后移动
        //new_hot_file_area_index = middle;
        if(open_shrink_printk)
	    printk("%s %s %d find error\n",__func__,current->comm,current->pid);
	return NULL;
    }
}
-int async_shirnk_update_file_status(struct *page){
    struct address_space *mapping;
    int ret = 0;
    struct hot_file_stat * p_hot_file_stat = NULL;
    unsigned char *hot_file_area_cache = NULL;

    mapping = page_mapping(page);
    if(mapping){
        struct hot_file_area_hot *p_hot_file_area_hot;
	struct hot_file_area *p_hot_file_area; 

	if(!mapping->hot_file_stat){
            unsigned int hot_file_area_cache_size = sizeof(struct hot_file_area)*HOT_FILE_AREA_CACHE_COUNT + sizeof(struct hot_file_area_hot);

	    if(!hot_file_global_info.hot_file_stat_cachep || !hot_file_global_info.hot_file_area_cachep){
	        ret =  -ENOMEM;
		goto err;
	    }
		
	    //新的文件分配hot_file_stat,一个文件一个，保存文件热点区域访问数据
	    p_hot_file_stat = kmem_cache_alloc(hot_file_global_info.hot_file_stat_cachep,GFP_KERNE);
            if (!p_hot_file_stat) {
	        printk("%s hot_file_stat alloc fail\n",__func__);
	        ret =  -ENOMEM;
		goto err;
	    }
	    memset(p_hot_file_stat,sizeof(struct hot_file_stat),0);
            //新的文件，先分配hot_file_area_cache,这片区域是1个hot_file_head结构 + 6个hot_file_area结构
	    hot_file_area_cache = kmem_cache_alloc(hot_file_global_info.hot_file_area_cachep,GFP_KERNE);
            if (!p_hot_file_area) {
	        printk("%s hot_file_area alloc fail\n",__func__);
	        ret =  -ENOMEM;
		goto err;
            }
	    memset(hot_file_area_cache,hot_file_area_cache_size,0);
	    //mapping->hot_file_stat记录该文件绑定的hot_file_stat结构，将来判定是否对该文件分配了hot_file_stat
	    mapping->hot_file_stat = p_hot_file_stat;
	    //hot_file_stat记录mapping结构
	    p_hot_file_stat->mapping = mapping;
	    //文件访问次数加1
	    p_hot_file_stat->file_access_count++;
            //p_hot_file_area_hot指向hot_file_area_cache第一片区域，即hot_file_area_hot。往后还有6片hot_file_area结构
            p_hot_file_area_hot = (struct hot_file_area_hot*)hot_file_area_cache;
	    //p_hot_file_area_hot指向的区域内文件热点区域加1
            p_hot_file_area_hot->file_area_count ++;
	    p_hot_file_area_hot->file_area_magic = 0;
            //hot_file_stat->hot_file_area_cache指向头结点区域
	    p_hot_file_stat->hot_file_area_cache = p_hot_file_area_hot;

	    //p_hot_file_area指向hot_file_area_cache第一个hot_file_area结构，为新文件分配的hot_file_stat，肯定要在第一片hot_file_area结构记录第一个该文件的热点区域
	    p_hot_file_area = (struct hot_file_area*)(p_hot_file_area_hot + sizeof(struct hot_file_area_hot));
	    //p_hot_file_area记录文件热点区域的起始、结束文件索引，默认page->index后的5个page都是热点区域
	    p_hot_file_area->start_index = page->index;
	    p_hot_file_area->end_index = page->index + HOT_FILE_AARE_RANGE;
	    //p_hot_file_area热点区域访问数加1
	    p_hot_file_area->area_access_count ++;

            p_hot_file_area_hot->min_start_index = p_hot_file_area->start_index;
            p_hot_file_area_hot->max_start_index = p_hot_file_area->end_index;
	    
            spin_lock(&hot_file_global_info.hot_file_lock);
	    list_add_rcu(p_hot_file_stat->hot_file_list,hot_file_global_info.hot_file_head);
	    spin_unlock(&hot_file_global_info.hot_file_lock);
	}
	else//走到这个分支，说明之前为当前访问的文件分配了hot_file_stat结构
	{
	    //从mapping得到该文件绑定的hot_file_stat结构
	    p_hot_file_stat = mapping->hot_file_stat;
	    //从文件绑定的hot_file_stat结构的成员hot_file_area_cache得到保存文件热点区域的内存地址，保存到p_hot_file_area_hot。该内存的数据是
	    //1个hot_file_area_hot结构+6个hot_file_area结构。但是如果文件热点区域hot_file_area大于6个，则这片内存的数据调整为是
	    //1个hot_file_area_hot结构+N个page指针，这些page的内存保存文件热点区域hot_file_area结构
            p_hot_file_area_hot = (struct hot_file_area_hot *)p_hot_file_stat->hot_file_area_cache;
	    //令p_hot_file_area第一个hot_file_area结构
	    p_hot_file_area = (struct hot_file_area *)(p_hot_file_area_hot + sizeof(struct hot_file_area_hot));

            //文件的ot_file_stat的hot_file_area_cache指向的内存保存的是文件热点区域结构hot_file_area
	    if(p_hot_file_area_hot->file_area_magic == 0)
	    {
                //本次的文件页page索引在hot_file_area_hot指向的热点区域范围内
	        //if(page->index > p_hot_file_area_hot->min_start_index && page->index < p_hot_file_area_hot->max_start_index)
		
		//找到包含page->index的文件热点区域hot_file_area则返回它，否则返回NULL。
		p_hot_file_area = find_match_hot_file_area(p_hot_file_area,hot_file_area_count,page->index);
                if(p_hot_file_area){
		    //该文件热点区域访问次数加1
		    p_hot_file_area->area_access_count ++;
		}
		else{
		    //文件绑定的hot_file_stat结构的成员hot_file_area_cache还有空闲的hot_file_area保存本次文件的热点区域
		    if(p_hot_file_area_hot->file_area_count < HOT_FILE_AREA_CACHE_COUNT){
			//令p_hot_file_are指向hot_file_area_cache空闲的hot_file_area，由于hot_file_area_cache里的6个hot_file_area，从左到右保存的文件索引
			//
		        p_hot_file_area = p_hot_file_area_hot + sizeof(struct hot_file_area)*(p_hot_file_area_hot->file_area_count;
			p_hot_file_area_hot->file_area_count ++;

		    }else{
		        /*到这里，说明hot_file_area_cache里的6个hot_file_area用完了，要分配内存page保存新的hot_file_area结构了*/

			
		    }

		}
	    }else
	    {
	    
	    }

	    //该文件的访问次数加1
	    p_hot_file_stat->file_access_count++;
            
        }
    }

    return 0;

err:
    if(p_hot_file_stat)
	kmem_cache_free(hot_file_global_info.hot_file_stat_cachep,p_hot_file_stat);
    if(p_hot_file_area)
	kmem_cache_free(hot_file_global_info.hot_file_area_cachep,p_hot_file_area);
    return ret;
}
#endif


static inline unsigned long hot_file_area_tree_shift_maxindex(unsigned int shift)
{
    return (TREE_MAP_SIZE << shift) - 1;
}
//计算以当前节点node为基准，它下边的子树能容纳多少个page有关的hot_file_area。如果是跟节点，则表示整个tree最多容纳多少个hot_file_area
static inline unsigned long hot_file_area_tree_node_maxindex(struct hot_file_area_tree_node *node)
{
    return  hot_file_area_tree_shift_maxindex(node->shift);
}
static inline bool hot_file_area_tree_is_internal_node(void *ptr)
{
    return ((unsigned long)ptr & TREE_ENTRY_MASK) == TREE_INTERNAL_NODE;
}
static inline struct hot_file_area_tree_node *entry_to_node(void *ptr)
{
    return (void *)((unsigned long)ptr & ~TREE_INTERNAL_NODE);
}
static inline void *node_to_entry(void *ptr)
{
    return (void *)((unsigned long)ptr | TREE_INTERNAL_NODE);
}
int hot_file_area_tree_extend(struct hot_file_area_tree_root *root,unsigned long area_index,unsigned int shift)
{
    struct hot_file_area_tree_node *slot;
    unsigned int maxshift;
    
    maxshift = shift;
    //hot_file_area_tree要扩增1层时，这个循环不成立.扩增2层时循环成立1次，其他类推
    while (area_index > hot_file_area_tree_shift_maxindex(maxshift))
	maxshift += TREE_MAP_SHIFT;
    
    slot = root->root_node;
    if (!slot)
        goto out;

    do {
	//在分配radix tree node前，是spin lock加了hot_file_stat->hot_file_stat_lock锁的，故这里分配内存禁止休眠，否则低内存场景就会占着spin锁休眠，然后导致其他进程获取spin lock失败而soft lockup
        //struct hot_file_area_tree_node* node = kmem_cache_alloc(hot_file_global_info.hot_file_area_tree_node_cachep,GFP_KERNEL);
        struct hot_file_area_tree_node* node = kmem_cache_alloc(hot_file_global_info.hot_file_area_tree_node_cachep,GFP_ATOMIC);
	if (!node)
	    return -ENOMEM;
	memset(node,0,sizeof(struct hot_file_area_tree_node));
        node->shift = shift;
	node->offset = 0;
	node->count = 1;
	node->parent = NULL;
	if (hot_file_area_tree_is_internal_node(slot))
	    entry_to_node(slot)->parent = node;
	//当hot_file_area tree只保存索引是0的hot_file_area时，hot_file_area指针是保存在root->root_node指针里。后续hot_file_area tree添加其他成员时，就需要增加tree层数，就在这个循环完成。
	//可能hot_file_area tree一次只增加一层，或者增加多层。这行代码是限制，当第一层增加tree层数时，slot是root->root_node，并且slot保存的是索引是0的hot_file_area指针，不是节点。
	//则hot_file_area_tree_is_internal_node(slot)返回flase，然后执行slot->parent = node令索引是0的hot_file_area的parent指向父节点。没有这样代码，该hot_file_area就成没有父亲的孤儿了，后续释放tree就会有问题
        else if(slot == root->root_node && !hot_file_area_tree_is_internal_node(slot))
	    /*此时根节点root->root_node保存的是hot_file_area指针，并不是hot_file_area_tree_node指针，要强制转换成hot_file_area指针并令其parent成员指向父节点。否则还是以
	     * hot_file_area_tree_node->parent=node形式赋值，实际赋值到了hot_file_area->file_area_age成员那里，内存越界了,导致它很大!!这个else if只在tree由0层向1层增加时才成立，
	     * 只会成立这一次，后续tree再增长高度，这里都不成立。此时slot=root->root_node保存的hot_file_area指针,bit1是0，不是internal_node.后续到这里slot都是internal_node，bit0是1.*/
	      //slot->parent = node; 此时根节点root->root_node保存的是hot_file_area指针，并不是hot_file_area_tree_node指针，要强制转换成hot_file_area指针并
	    ((struct hot_file_area *)slot)->parent = node;

	node->slots[0] = slot;
	slot = node_to_entry(node);
	rcu_assign_pointer(root->root_node, slot);
	shift += TREE_MAP_SHIFT;
        //printk("%s %s %d node:0x%llx slot:0x%llx shift:%d\n",__func__,current->comm,current->pid,(u64)node,(u64)slot,shift);
    }while (shift <= maxshift);
out:
    return maxshift + RADIX_TREE_MAP_SHIFT;    
}
struct hot_file_area_tree_node *hot_file_area_tree_lookup_and_create(struct hot_file_area_tree_root *root,
	                                                 unsigned long area_index,void ***page_slot_in_tree)
{
    unsigned int shift, offset = 0;
    unsigned long max_area_index;
    struct hot_file_area_tree_node *node = NULL, *child;
    void **slot = (void **)&root->root_node;
    int ret;
    //hot_file_area_tree根节点，radix tree原本用的是rcu_dereference_raw，为什么?????????????需要研究下
    node = rcu_dereference_raw(root->root_node);

    //hot_file_area_tree至少有一层，不是空的树
    if (likely(hot_file_area_tree_is_internal_node(node))){
	//此时的根节点node指针的bit0是1，表示是个节点，并不是真正的hot_file_area_tree_node指针，此时node->shift永远错误是0。下边每次就有很大概率执行hot_file_area_tree_extend()
	//反复创建tree新的层数，即便对应的层数之前已经创建过了
        node = entry_to_node(node);
        //hot_file_area_tree根节点的的shift+6
        shift = node->shift + TREE_MAP_SHIFT;
        max_area_index = hot_file_area_tree_shift_maxindex(node->shift);
	//这里要把node的bit0置1，否则下边child = node后，child的bit0是0，不再表示根节点，导致下边的while循环中直接走else if (!hot_file_area_tree_is_internal_node(child))分支,
	//这样每次都无法遍历tree，返回的
	node = node_to_entry(node);
    }
    else//到这里说明hot_file_area_tree 是空的，没有根节点
    {
	shift = 0;
	max_area_index = 0;
    }
    //此时child指向根节点
    child = node;
    //这里再赋值NULL是为了保证shift=0的场景，就是tree没有一个节点，只有索引是0的成员保存在root->root_node根节点，此时到这里shift是0，下边的while (shift > 0)不成立。
    //此时该函数返回的父节点node应是NULL，因为返回的slot就指向根节点的root->root_node，它的父节点是NULL
    node = NULL;

    //当本次查找的hot_file_area索引太大，hot_file_area_tree树能容纳的最大hot_file_area索引不能容纳本次要查找的hot_file_area索引
    if(area_index > max_area_index){//hot_file_area_tree 是空树时，这里不成立，二者都是0
        ret = hot_file_area_tree_extend(root,area_index,shift);
	if (ret < 0)
	    return ERR_PTR(ret);
	shift = ret;
	child = root->root_node;
    }
    
    //node是父节点，slot指向父节点node的某个槽位，这个槽位保存child这个节点指针 或者hot_file_area_tree树最下层节点的file_area_tree指针
    while (shift > 0) {
        shift -= TREE_MAP_SHIFT;

	//当前遍历指向radix tree层数的节点是NULL则分配一个新的节点，这里的child肯定是hot_file_area_tree的节点
	if (child == NULL) {
	    //在分配radix tree node前，是spin lock加了hot_file_stat->hot_file_stat_lock锁的，故这里分配内存禁止休眠，否则低内存场景就会占着spin锁休眠，然后导致其他进程获取spin lock失败而soft lockup
            //child = kmem_cache_alloc(hot_file_global_info.hot_file_area_tree_node_cachep,GFP_KERNEL);
            child = kmem_cache_alloc(hot_file_global_info.hot_file_area_tree_node_cachep,GFP_ATOMIC);
	    if (!child)
	        return ERR_PTR(-ENOMEM);
	    memset(child,0,sizeof(struct hot_file_area_tree_node));

	    child->shift = shift;
	    child->offset = offset;
	    child->parent = node;
	    //slot指向child所在父节点的槽位，这里是把新分配的节点hot_file_area_tree_node指针保存到父节点的槽位
	    rcu_assign_pointer(*slot, node_to_entry(child));
	    if (node)
		node->count++;//父节点的子成员树加1
	}
	//这里成立说明child不是hot_file_area_tree的节点，而是树最下层的节点保存的数据
	else if (!hot_file_area_tree_is_internal_node(child))
	    break;

	node = entry_to_node(child);
	//根据area_index索引计算在父节点的槽位索引offset
	offset = (area_index >> node->shift) & TREE_MAP_MASK;
        //根据area_index索引计算在父节点的槽位索引offset，找到在父节点的槽位保存的数据，可能是子节点 或者 保存在hot_file_area_tree树最下层节点的hot_file_area指针
	child = rcu_dereference_raw(node->slots[offset]);
        //根据area_index索引计算在父节点的槽位索引offset，令slot指向在父节点的槽位
	slot = &node->slots[offset];
        /*下轮循环，node= child 成为新的父节点。slot指向父节点node的某个槽位，这个槽位保存child这个节点指针 或者hot_file_area_tree树最下层节点的file_area_tree指针*/
        //printk("%s %s %d node:0x%llx child:0x%llx slot:0x%llx offset:%d max_area_index:%ld shift:%d\n",__func__,current->comm,current->pid,(u64)node,(u64)child,(u64)slot,offset,max_area_index,shift);
    }
    //page_slot_in_tree是3重指针，*page_slot_in_tree 和 slot 是2重指针，*page_slot_in_tree和slot才能彼此赋值。赋值后*page_slot_in_tree保存的是槽位的地址
    *page_slot_in_tree = slot;
    return node;
}
//释放hot_file_area结构，返回0说明释放成功，返回1说明hot_file_area此时又被访问了，没有释放
int hot_file_area_detele(struct hot_file_global *p_hot_file_global,struct hot_file_stat * p_hot_file_stat,struct hot_file_area *p_hot_file_area)
{
    struct hot_file_area_tree_node *p_hot_file_area_tree_node = p_hot_file_area->parent;
    struct hot_file_area_tree_node * p_hot_file_area_tree_node_tmp;
    int file_area_index = p_hot_file_area->start_index >>PAGE_COUNT_IN_AREA_SHIFT;
    //取出hot_file_area在父节点的槽位号，这个计算方法是错误的，p_hot_file_area->start_index是起始page的索引，不是file_area索引，这样会导致计算出的
    //槽位号slot_number是错误的，这样会导致错剔除其他的file_area
    //int slot_number = p_hot_file_area->start_index & TREE_MAP_MASK;
    int slot_number = file_area_index & TREE_MAP_MASK;

    //在释放hot_file_area时，可能正有进程执行hot_file_update_file_status()遍历hot_file_area_tree树中p_hot_file_area指向的hot_file_area结构，
    //这里又在释放hot_file_area结构，因此需要加锁。
    spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
    //如果近期file_area被访问了
    if(hot_file_global_info.global_age - p_hot_file_area->file_area_age < 2 ){
	//那就把它再移动回hot_file_stat->hot_file_area_temp链表头。有这个必要吗？没有必要的!因为该file_area是在hot_file_stat->hot_file_area_free链表上，如果
	//被访问了而执行hot_file_update_file_status()函数，会把这个file_area立即移动到hot_file_stat->hot_file_area_temp链表，这里就没有必要做了!!!!!!!!!!!!!!!
	
        //set_file_area_in_temp_list(p_hot_file_area);
	//list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
        spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
	return 1;
    }
    //该文件file_stat的file_area个数减1，这个过程已经加了锁。这个减1要放到这里，保证"仅有一个索引是0的file_area指针保存在根节点hot_file_stat->hot_file_area_tree_root_node.root_node"的
    //file_area结构释放时，也能令file_stat总file_area个数减1
    p_hot_file_stat->file_area_count --;

    //这个if成立，说明当前hot file tree是空树，仅有一个索引是0的file_area指针保存在根节点hot_file_stat->hot_file_area_tree_root_node.root_node，
    //现在这个file_area被剔除了，仅仅把hot_file_stat->hot_file_area_tree_root_node.root_node设置成NULL即可，表示之后该hot file tree一个file_area都没保存
    if(p_hot_file_area_tree_node == NULL){
        list_del(&p_hot_file_area->hot_file_area_list);
	//此时也要把"仅有一个索引是0的file_area"结构体释放掉，否则就内存泄漏了
        kmem_cache_free(p_hot_file_global->hot_file_area_cachep,p_hot_file_area);
	p_hot_file_stat->hot_file_area_tree_root_node.root_node = NULL;
        spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
	return 1;
    }
     
    if(p_hot_file_area_tree_node->slots[slot_number] != p_hot_file_area)
        panic("%s p_hot_file_area_tree_node->slots[%d]:0x%llx != p_hot_file_area:0x%llx\n",__func__,slot_number,(u64)p_hot_file_area_tree_node->slots[slot_number],(u64)p_hot_file_area);
    //从hot_file_area tree释放hot_file_area结构，同时也要从hot_file_area_list链表剔除，这个过程还要p_hot_file_stat->hot_file_stat_lock加锁
    list_del(&p_hot_file_area->hot_file_area_list);
    //该文件file_stat的file_area个数减1，这个过程已经加了锁
    //p_hot_file_stat->file_area_count --;
    kmem_cache_free(p_hot_file_global->hot_file_area_cachep,p_hot_file_area);

    p_hot_file_area_tree_node->slots[slot_number] = NULL;
    p_hot_file_area_tree_node->count --;//父节点的子成员数减1

    //如果 p_hot_file_area_tree_node没有成员了，则释放p_hot_file_area_tree_node节点，并且向上逐层没有成员的hot_file_area_tree_node父节点
    while(p_hot_file_area_tree_node->count == 0){
	//当前节点在父节点的槽位号
	slot_number = p_hot_file_area_tree_node->offset;
	p_hot_file_area_tree_node_tmp = p_hot_file_area_tree_node;
	//获取父节点
        p_hot_file_area_tree_node = p_hot_file_area_tree_node->parent;
        kmem_cache_free(p_hot_file_global->hot_file_area_tree_node_cachep,p_hot_file_area_tree_node_tmp);
	//如果此时p_hot_file_area_tree_node是NULL，说明上一部hot file tree只有一层，p_hot_file_area_tree_node指向第一层的节点，而它的父节点即p_hot_file_area_tree_node->parent
	//就是NULL。此时if成立，并且hot file tree此时唯一的节点也释放了，是空树，则要设置hot_file_stat->hot_file_area_tree_root_node.root_node=NULL，表示一个成员都没有了。
	if(p_hot_file_area_tree_node == NULL){
            p_hot_file_stat->hot_file_area_tree_root_node.root_node = NULL;
            break;	    
	}
	//子节点在父节点对应槽位设置NULL
        p_hot_file_area_tree_node->slots[slot_number] = NULL;
	//父节点的子成员数减1
        p_hot_file_area_tree_node->count --;
    }
    spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);

    return 0;
}
//文件被释放后，强制释放该文件file_stat的hot_file_area结构，是hot_file_area_detele()函数的快速版本
unsigned int hot_file_area_detele_quick(struct hot_file_global *p_hot_file_global,struct hot_file_stat * p_hot_file_stat,struct hot_file_area *p_hot_file_area)
{
    struct hot_file_area_tree_node *p_hot_file_area_tree_node = p_hot_file_area->parent;
    struct hot_file_area_tree_node * p_hot_file_area_tree_node_tmp;

    int file_area_index = p_hot_file_area->start_index >>PAGE_COUNT_IN_AREA_SHIFT;
    int slot_number = file_area_index & TREE_MAP_MASK;
    
    //该文件file_stat的file_area个数减1，这个过程已经加了锁。这个减1要放到这里，保证"仅有一个索引是0的file_area指针保存在根节点hot_file_stat->hot_file_area_tree_root_node.root_node"的
    //file_area结构释放时，也能令file_stat总file_area个数减1
    p_hot_file_stat->file_area_count --;

    //这个if成立，说明当前hot file tree是空树，仅有一个索引是0的file_area指针保存在根节点hot_file_stat->hot_file_area_tree_root_node.root_node，
    //现在这个file_area被剔除了，仅仅把hot_file_stat->hot_file_area_tree_root_node.root_node设置成NULL即可，表示之后该hot file tree一个file_area都没保存
    if(p_hot_file_area_tree_node == NULL){
        list_del(&p_hot_file_area->hot_file_area_list);
	//此时也要把"仅有一个索引是0的file_area"结构体释放掉，否则就内存泄漏了
        kmem_cache_free(p_hot_file_global->hot_file_area_cachep,p_hot_file_area);
	p_hot_file_stat->hot_file_area_tree_root_node.root_node = NULL;
	return 1;
    }
    
    if(p_hot_file_area_tree_node->slots[slot_number] != p_hot_file_area)
        panic("%s p_hot_file_area_tree_node->slots[%d]:0x%llx != p_hot_file_area:0x%llx\n",__func__,slot_number,(u64)p_hot_file_area_tree_node->slots[slot_number],(u64)p_hot_file_area);
    //从hot_file_area tree释放hot_file_area结构，同时也要从hot_file_area_list链表剔除，这个过程还要p_hot_file_stat->hot_file_stat_lock加锁
    list_del(&p_hot_file_area->hot_file_area_list);
    //该文件file_stat的file_area个数减1
    //p_hot_file_stat->file_area_count --;
    kmem_cache_free(p_hot_file_global->hot_file_area_cachep,p_hot_file_area);

    p_hot_file_area_tree_node->slots[slot_number] = NULL;
    p_hot_file_area_tree_node->count --;//父节点的子成员数减1

    //如果 p_hot_file_area_tree_node没有成员了，则释放p_hot_file_area_tree_node节点，并且向上逐层没有成员的hot_file_area_tree_node父节点
    while(p_hot_file_area_tree_node->count == 0){
	//当前节点在父节点的槽位号
	slot_number = p_hot_file_area_tree_node->offset;
	p_hot_file_area_tree_node_tmp = p_hot_file_area_tree_node;
	//获取父节点
        p_hot_file_area_tree_node = p_hot_file_area_tree_node->parent;
        kmem_cache_free(p_hot_file_global->hot_file_area_tree_node_cachep,p_hot_file_area_tree_node_tmp);
	//如果此时p_hot_file_area_tree_node是NULL，说明上一部hot file tree只有一层，p_hot_file_area_tree_node指向第一层的节点，而它的父节点即p_hot_file_area_tree_node->parent
	//就是NULL。此时if成立，并且hot file tree此时唯一的节点也释放了，是空树，则要设置hot_file_stat->hot_file_area_tree_root_node.root_node=NULL，表示一个成员都没有了。
	if(p_hot_file_area_tree_node == NULL){
            p_hot_file_stat->hot_file_area_tree_root_node.root_node = NULL;
            break;	    
	}
	//子节点在父节点对应槽位设置NULL
        p_hot_file_area_tree_node->slots[slot_number] = NULL;
	//父节点的子成员数减1
        p_hot_file_area_tree_node->count --;
    }

    return 0;
}
//删除p_hot_file_stat_del对应文件的file_stat上所有的file_area，已经对应hot file tree的所有节点hot_file_area_tree_node结构。最后释放掉p_hot_file_stat_del这个hot_file_stat数据结构
unsigned int hot_file_tree_delete_all(struct hot_file_global *p_hot_file_global,struct hot_file_stat * p_hot_file_stat_del)
{
    //struct hot_file_stat * p_hot_file_stat,*p_hot_file_stat_temp;
    struct hot_file_area *p_hot_file_area,*p_hot_file_area_temp;
    unsigned int del_file_area_count = 0;
    //refault链表
    list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat_del->hot_file_area_refault,hot_file_area_list){
        if(!file_area_in_refault_list(p_hot_file_area))
	    panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_refault\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

        hot_file_area_detele_quick(p_hot_file_global,p_hot_file_stat_del,p_hot_file_area);
	del_file_area_count ++;
    }
    //hot链表
    list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat_del->hot_file_area_hot,hot_file_area_list){
        if(!file_area_in_hot_list(p_hot_file_area))
	    panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_hot\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

        hot_file_area_detele_quick(p_hot_file_global,p_hot_file_stat_del,p_hot_file_area);
	del_file_area_count ++;
    }
    //temp链表
    list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat_del->hot_file_area_temp,hot_file_area_list){
        if(!file_area_in_temp_list(p_hot_file_area))
	    panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_temp\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

        hot_file_area_detele_quick(p_hot_file_global,p_hot_file_stat_del,p_hot_file_area);
	del_file_area_count ++;
    }
    //free链表
    list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat_del->hot_file_area_free,hot_file_area_list){
        if(!file_area_in_free_list(p_hot_file_area))
	    panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_free\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

        hot_file_area_detele_quick(p_hot_file_global,p_hot_file_stat_del,p_hot_file_area);
	del_file_area_count ++;
    }
    //free_temp链表
    list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat_del->hot_file_area_free_temp,hot_file_area_list){
        if(!file_area_in_free_list(p_hot_file_area))
	    panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_free_temp\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

        hot_file_area_detele_quick(p_hot_file_global,p_hot_file_stat_del,p_hot_file_area);
	del_file_area_count ++;
    }

    if(p_hot_file_stat_del->file_area_count != 0){
        panic("hot_file_stat_del:0x%llx file_area_count:%d !=0 !!!!!!!!\n",(u64)p_hot_file_stat_del,p_hot_file_stat_del->file_area_count);
    }

    spin_lock(&p_hot_file_global->hot_file_lock);
    //从global的链表中剔除该file_stat，这个过程需要加锁，因为同时其他进程会执行hot_file_update_file_status()向global的链表添加新的文件file_stat
    list_del(&p_hot_file_stat_del->hot_file_list);
    //释放该file_stat结构
    kmem_cache_free(p_hot_file_global->hot_file_stat_cachep,p_hot_file_stat_del);
    //file_stat个数减1
    hot_file_global_info.file_stat_count--;
    spin_unlock(&p_hot_file_global->hot_file_lock);

    return del_file_area_count;
}

//如果一个文件file_stat超过一定比例(比如50%)的file_area都是热的，则判定该文件file_stat是热文件，file_stat要移动到global hot_file_head链表。返回1是热文件
int is_file_stat_hot_file(struct hot_file_global *p_hot_file_global,struct hot_file_stat * p_hot_file_stat){
    int ret;

    //如果文件file_stat的file_area个数比较少，则比例按照50%计算
    if(p_hot_file_stat->file_area_count < p_hot_file_global->file_area_count_for_large_file){
        //超过50%的file_area是热的，则判定文件file_stat是热文件
        //if(div64_u64((u64)p_hot_file_stat->file_area_count*100,(u64)p_hot_file_stat->file_area_hot_count) > 50)
	if(p_hot_file_stat->file_area_hot_count > p_hot_file_stat->file_area_count>>1)
	    ret = 1;
        else
	    ret = 0;
    }else{
	//否则，文件很大，则必须热file_area超过文件总file_area数的很多很多，才能判定是热文件。因为此时file_area很多，冷file_area的数目有很多，应该遍历回收这种file_area的page
        if(p_hot_file_stat->file_area_hot_count > (p_hot_file_stat->file_area_count - (p_hot_file_stat->file_area_count >>2)))
	   ret  = 1;
	else
	   ret =  0;
    }
    return ret;
}
//当文件file_stat的file_area个数超过阀值则判定是大文件
int inline is_file_stat_large_file(struct hot_file_global *p_hot_file_global,struct hot_file_stat * p_hot_file_stat)
{
    if(p_hot_file_stat->file_area_count > hot_file_global_info.file_area_count_for_large_file)
	return 1;
    else
	return 0;
}
//模仿page_mapping()判断是否是page cache
inline struct address_space * hot_file_page_mapping(struct page *page)
{
    struct address_space *mapping;
    if (unlikely(PageSlab(page)) || unlikely(PageSwapCache(page)) || PageAnon(page) || page_mapped(page) || PageCompound(page))
        return NULL;

    mapping = page->mapping;
    if ((unsigned long)mapping & PAGE_MAPPING_ANON)
        return NULL;

    return (void *)((unsigned long)mapping & ~PAGE_MAPPING_FLAGS);
}
int hot_file_update_file_status(struct page *page)
{
    struct address_space *mapping;

    //mapping = page_mapping(page);-----这个针对swapcache也是返回非NULL，不能用
    mapping = hot_file_page_mapping(page);
    /*注意，遇到一个奇葩现象，因mapping->host->i_sb不合法而导致 mapping->host->i_sb->s_dev 非法内存访问而crash，竟然直接重启了，没有生成vmcore。难道是因为
     * 现在hot_file_update_file_status()是在kprobe里调用，kprobe里非法内存访问导致系统crash，不会生成vmcore?这对调试太不利了!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
    if(hot_file_shrink_enable && mapping && mapping->host && mapping->host->i_sb/* && (hot_file_shrink_enable == mapping->host->i_sb->s_dev || hot_file_shrink_enable == mapping->host->i_sb->s_dev >> 20)*/){
        void **page_slot_in_tree = NULL;
	//page所在的hot_file_area的索引
	unsigned int area_index_for_page;
        struct hot_file_area_tree_node *parent_node;
        int ret = 0;
        struct hot_file_stat * p_hot_file_stat = NULL;
        struct hot_file_area *p_hot_file_area = NULL; 

	//与 __destroy_inode_handler_post()函数删除file_stat的smp_wmb()成对，详细看注释
	smp_rmb();
	//如果两个进程同时访问同一个文件的page0和page1，这就就有问题了，因为这个if会同时成立。然后下边针对
	if(mapping->rh_reserved1 == 0 ){

	    if(!hot_file_global_info.hot_file_stat_cachep || !hot_file_global_info.hot_file_area_cachep){
	        ret =  -ENOMEM;
		goto err;
	    }
            
	    //这里有个问题，hot_file_global_info.hot_file_lock有个全局大锁，每个进程执行到这里就会获取到。合理的是
	    //应该用每个文件自己的spin lock锁!比如hot_file_stat里的spin lock锁，但是在这里，每个文件的hot_file_stat结构还没分配!!!!!!!!!!!!
            spin_lock(&hot_file_global_info.hot_file_lock);
	    //如果两个进程同时访问一个文件，同时执行到这里，需要加锁。第1个进程加锁成功后，分配hot_file_stat并赋值给
	    //mapping->hot_file_stat，第2个进程获取锁后执行到这里mapping->hot_file_stat就会成立
	    if(mapping->rh_reserved1){
	        spin_unlock(&hot_file_global_info.hot_file_lock);
	        goto already_alloc;  
	    }
	    //新的文件分配hot_file_stat,一个文件一个，保存文件热点区域访问数据
	    p_hot_file_stat = kmem_cache_alloc(hot_file_global_info.hot_file_stat_cachep,GFP_ATOMIC);
            if (!p_hot_file_stat) {
	        spin_unlock(&hot_file_global_info.hot_file_lock);
	        printk("%s hot_file_stat alloc fail\n",__func__);
	        ret =  -ENOMEM;
		goto err;
	    }
	    //file_stat个数加1
	    hot_file_global_info.file_stat_count++;

	    memset(p_hot_file_stat,0,sizeof(struct hot_file_stat));
	    //初始化hot_file_area_hot头结点
	    INIT_LIST_HEAD(&p_hot_file_stat->hot_file_area_hot);
	    INIT_LIST_HEAD(&p_hot_file_stat->hot_file_area_temp);
	    INIT_LIST_HEAD(&p_hot_file_stat->hot_file_area_cold);
	    INIT_LIST_HEAD(&p_hot_file_stat->hot_file_area_free_temp);
	    INIT_LIST_HEAD(&p_hot_file_stat->hot_file_area_free);
	    INIT_LIST_HEAD(&p_hot_file_stat->hot_file_area_refault);

	    //mapping->hot_file_stat记录该文件绑定的hot_file_stat结构，将来判定是否对该文件分配了hot_file_stat
	    mapping->rh_reserved1 = (unsigned long)p_hot_file_stat;
	    //hot_file_stat记录mapping结构
	    p_hot_file_stat->mapping = mapping;
	    //把针对该文件分配的hot_file_stat结构添加到hot_file_global_info的hot_file_head_temp链表
	    list_add(&p_hot_file_stat->hot_file_list,&hot_file_global_info.hot_file_head_temp);
	    //新分配的file_stat必须设置in_hot_file_head_temp_list链表
	    set_file_stat_in_hot_file_head_temp_list(p_hot_file_stat);
            spin_lock_init(&p_hot_file_stat->hot_file_stat_lock);

	    spin_unlock(&hot_file_global_info.hot_file_lock);
	}

already_alloc:	    
	    //根据page索引找到所在的hot_file_area的索引，二者关系默认是 hot_file_area的索引 = page索引/6
            area_index_for_page =  page->index >> PAGE_COUNT_IN_AREA_SHIFT;

	    p_hot_file_stat = (struct hot_file_stat *)mapping->rh_reserved1;
	    //如果mapping->rh_reserved1被其他代码使用，直接返回错误
	    if(p_hot_file_stat == NULL || p_hot_file_stat->mapping != mapping){
	        printk("%s p_hot_file_stat:0x%llx error or p_hot_file_stat->mapping != mapping\n",__func__,(u64)p_hot_file_stat);
		goto err;
	    }

            spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
	    //根据page索引的hot_file_area的索引，找到对应在file area tree树的槽位，page_slot_in_tree双重指针指向这个槽位。
	    //下边分配真正的hot_file_area结构，把hot_file_area指针保存到这个操作
	    parent_node = hot_file_area_tree_lookup_and_create(&p_hot_file_stat->hot_file_area_tree_root_node,area_index_for_page,&page_slot_in_tree);
            if(IS_ERR(parent_node)){
	        spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
	        printk("%s hot_file_area_tree_insert fail\n",__func__);
		goto err;
	    }
	    //两个进程并发执行该函数时，进程1获取hot_file_stat_lock锁成功，执行hot_file_area_tree_insert()查找page绑定的hot_file_area的
	    //在file_area_tree的槽位，*page_slot_in_tree 是NULL，然后对它赋值。进程2获取hot_file_stat_lock锁后，*page_slot_in_tree就不是NULL了
	    if(*page_slot_in_tree == NULL){//针对当前page索引的hot_file_area结构还没有分配,page_slot_in_tree是槽位地址，*page_slot_in_tree是槽位里的数据，就是hot_file_area指针
		//针对本次page索引，分配hot_file_area一个结构，于是该hot_file_area就代表了page
		p_hot_file_area = kmem_cache_alloc(hot_file_global_info.hot_file_area_cachep,GFP_ATOMIC);
		if (!p_hot_file_area) {
	            spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
		    printk("%s hot_file_area alloc fail\n",__func__);
		    ret =  -ENOMEM;
		    goto err;
		}
		memset(p_hot_file_area,0,sizeof(struct hot_file_area));
	        //把根据page索引分配的hot_file_area结构指针保存到file area tree指定的槽位
	        rcu_assign_pointer(*page_slot_in_tree,p_hot_file_area);

		//set_file_area_in_temp_list(p_hot_file_area);
	        //把新分配的hot_file_area添加到hot_file_area_temp链表
	        list_add(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
		//保存该hot_file_area对应的起始page索引，一个hot_file_area默认包含8个索引挨着依次增大page，start_index保存其中第一个page的索引
		p_hot_file_area->start_index = area_index_for_page * PAGE_COUNT_IN_AREA;
		//新分配的hot_file_area指向其在hot_file_area_tree的父节点node
		p_hot_file_area->parent = parent_node;
		//如果第一次把索引是0的hot_file_area插入hot_file_area tree，是把该hot_file_area指针保存到hot_file_area tree的根节点，此时parent_node是NULL
		if(parent_node)
		    parent_node->count ++;//父节点下的hot_file_area个数加1
		//令新创建的hot_file_area的last_access_count为1，跟area_access_count相等。如果将来walk_throuth_all_hot_file_area()扫描到hot_file_area
		//的last_access_count和area_access_count都是1，说明后续该hot_file_area就没被访问过。
		//p_hot_file_area->last_access_count = 1;
		
		p_hot_file_stat->file_area_count ++;//文件file_stat的file_area个数加1
		set_file_area_in_temp_list(p_hot_file_area);//新分配的file_area必须设置in_temp_list链表
            }
	    p_hot_file_area = *page_slot_in_tree;
	    //hot_file_global_info.global_age更新了，把最新的global age更新到本次访问的hot_file_area->file_area_age。并对hot_file_area->area_access_count清0，本周期被访问1次则加1
	    if(p_hot_file_area->file_area_age < hot_file_global_info.global_age){
		p_hot_file_area->file_area_age = hot_file_global_info.global_age;
	        p_hot_file_area->area_access_count = 0;
	    }
	    //file_area区域的page被访问的次数加1
	    p_hot_file_area->area_access_count ++;
#if 0
	    //如果p_hot_file_area在当前周期第1次被访问，则把移动到hot_file_area_temp链表头，该链表头的hot_file_area访问比较频繁，链表尾的hot_file_area很少访问。
	    //将来扫描释放page时，也是从hot_file_area_temp链表尾扫描hot_file_area看哪些可以释放
            if(file_area_in_temp_list(p_hot_file_area) && 
		    //p_hot_file_area->area_access_count - p_hot_file_area->last_access_count == 1)
		p_hot_file_area->area_access_count == 1)
	    {
		//如果p_hot_file_area不在hot_file_area_temp链表头，才把它添加到hot_file_area_temp链表头
	        if(p_hot_file_area->hot_file_area_list.prev != &p_hot_file_stat->hot_file_area_temp){
		    list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
		}
	    }
#endif
	    //如果p_hot_file_area在当前周期第1次被访问，则把移动到hot_file_area_hot链表头，该链表头的hot_file_area访问比较频繁，链表尾的hot_file_area很少访问。
	    //将来walk_throuth_all_hot_file_area()函数扫描释放page时过程，遍历到file_area所处的file_stat并释放内存page时，遍历这些file_stat的hot_file_area_hot
	    //链表尾巴的file_area，如果这些file_area在移动到hot_file_area_hot链表后,很少访问了，则把把这些file_area再降级移动回hot_file_area_temp链表头
            if(p_hot_file_area->area_access_count == 1)
	    {
		//如果p_hot_file_area不在hot_file_area_hot或hot_file_area_temp链表头，才把它添加到hot_file_area_hot或hot_file_area_temp链表头
		//file_stat的hot_file_area_hot或hot_file_area_temp链表头的file_area是最频繁访问的，链表尾的file_area访问频次低，内存回收光顾这些链表尾的file_area
                
		if(file_area_in_temp_list(p_hot_file_area)){
		    if(!list_is_first(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp))
		        list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
		}else if(file_area_in_hot_list(p_hot_file_area)){
		    if(!list_is_first(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_hot))
		        list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_hot);
		}else if(file_area_in_refault_list(p_hot_file_area)){//在refault链表的file_area如果被访问了也移动到链表头
		        list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_refault);
		}
	    }

            //如果p_hot_file_area是冷热不定的，并且hot_file_area的本轮访问次数大于阀值，则设置hot_file_area热，并且把该hot_file_area移动到hot_file_area_hot链表
	    if(file_area_in_temp_list(p_hot_file_area) &&  
		    //p_hot_file_area->area_access_count - p_hot_file_area->last_access_count >= FILE_AREA_HOT_LEVEL){
		p_hot_file_area->area_access_count > FILE_AREA_HOT_LEVEL){

		clear_file_area_in_temp_list(p_hot_file_area);
                //设置hot_file_area 处于 hot_file_area_hot链表
	        set_file_area_in_hot_list(p_hot_file_area);
	        list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_hot);
		/*//hot_file_area->last_access_count保存当前的hot_file_area->area_access_count值。如果hot_file_area移动到hot_file_area_hot链表后
		//hot_file_area还是经常被访问，area_access_count还会一直增加，则这种hot_file_area一直停留在ot_file_area_hot链表。否则area_access_count不再增加，
		//后续扫描到 hot_file_area_hot链表有这种hot_file_area，就要把它再移动回hot_file_area_temp链表
		p_hot_file_area->last_access_count = p_hot_file_area->area_access_count;*/

		//该文件的热hot_file_stat数加1
                p_hot_file_stat->file_area_hot_count ++;
                
		//如果文件file_stat的file_area很多都是热的，判定file_stat是热文件，则把hot_file_stat移动到global hot_file_head链表，
		//global hot_file_head链表上的hot_file_stat不再扫描上边的hot_file_area，有没有必要这样做??????????????????????
		if(!file_stat_in_hot_file_head_list(p_hot_file_stat) && is_file_stat_hot_file(&hot_file_global_info,p_hot_file_stat)){
		    if(!file_stat_in_hot_file_head_temp_list(p_hot_file_stat))
		         panic("%s %s %d hot_file_stat:0x%llx status:0x%x not in hot_file_head_temp_list\n",__func__,current->comm,current->pid,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);
		    //外层有spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock)，这里不应该再关中断，只能spin_lock加锁!!!!!!!!!!!!!!
                    spin_lock(&hot_file_global_info.hot_file_lock);
		    clear_file_stat_in_hot_file_head_temp_list(p_hot_file_stat);
		    set_file_stat_in_hot_file_head_list(p_hot_file_stat);
	            list_move(&p_hot_file_stat->hot_file_list,&hot_file_global_info.hot_file_head);
                    spin_unlock(&hot_file_global_info.hot_file_lock);
		}
	    }

	    //如果file_area处于file_stat的free_list或free_temp_list链表
            if(file_area_in_free_list(p_hot_file_area) || file_area_in_free_temp_list(p_hot_file_area)){
		if(file_area_in_free_list(p_hot_file_area))
		    clear_file_area_in_free_list(p_hot_file_area);
		else
		    clear_file_area_in_free_temp_list(p_hot_file_area);

                //file_area 的page被内存回收后，过了仅1s左右就又被访问则发生了refault，把该hot_file_area移动到hot_file_area_refault链表，
		//不再参与内存回收扫描!!!!需要设个保护期限制
		smp_rmb();
    		if(p_hot_file_area->shrink_time && (ktime_to_ms(ktime_get()) - (p_hot_file_area->shrink_time << 10) < 1000)){
		    p_hot_file_area->shrink_time = 0;
	            set_file_area_in_refault_list(p_hot_file_area);
		    list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_refault);
                }else{
		    p_hot_file_area->shrink_time = 0;
	            //file_area此时正在被内存回收而移动到了file_stat的free_list或free_temp_list链表，则直接移动到hot_file_stat->hot_file_area_temp链表头
		    set_file_area_in_temp_list(p_hot_file_area);
		    //if(file_area_in_free_list(p_hot_file_area))
	            //    list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp_large);
		    //else
			list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
		}
	    }
            //如果file_area处于file_area链表，但是p_hot_file_area->shrink_time不是0.这说明该file_area在之前walk_throuth_all_hot_file_area()函数中扫描
	    //判定该file_area是冷的，然后回收内存page。但是回收内存时，正好这个file_area又被访问了，则把file_area移动到file_stat->hot_file_area_temp链表。
	    //但是内存回收流程执行到hot_file_isolate_lru_pages()函数因并发问题没发现该file_area最近被访问了，只能继续回收该file_area的page。需要避免回收这种
	    //热file_area的page。于是等该file_area下次被访问，执行到这里，if成立，把该file_area移动到file_stat->hot_file_area_refault链表。这样未来一段较长时间
	    //可以避免再次回收该file_area的page。具体详情看hot_file_isolate_lru_pages()函数里的注释
	    if(file_area_in_temp_list(p_hot_file_area) && (p_hot_file_area->shrink_time != 0)){
	        p_hot_file_area->shrink_time = 0;
		clear_file_area_in_temp_list(p_hot_file_area);
	        set_file_area_in_refault_list(p_hot_file_area);
		list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_refault);
	    }
	    spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);

	    //文件file_stat的file_area个数大于阀值则移动到global hot_file_head_large_file_temp链表
	    if(is_file_stat_large_file(&hot_file_global_info,p_hot_file_stat)){
		smp_rmb();
		//walk_throuth_all_hot_file_area()函数中也有的大量的访问file_stat或file_area状态的，他们需要smp_rmb()吗，需要留意???????????????????????????????????????
		if(!file_stat_in_large_file(p_hot_file_stat)){
	            if(open_shrink_printk)
	                printk("%s %s %d hot_file_stat:0x%llx status:0x%x %d:%d is_file_stat_large_file\n",__func__,current->comm,current->pid,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,hot_file_global_info.file_area_count_for_large_file,p_hot_file_stat->file_area_count);
                    spin_lock(&hot_file_global_info.hot_file_lock);
		    //设置file_stat是大文件
		    set_file_stat_in_large_file(p_hot_file_stat);
		    //如果file_stat已经被判定热文件而移动到了ot_file_global_info.hot_file_head链表，不再移动到hot_file_global_info.hot_file_head_temp_large链表。否则
		    //这个file_stat深处hot_file_global_info.hot_file_head_temp_large链表，但是没有file_stat_in_hot_file_head_temp_list标记，将来遍历时会触发crash
		    if(!file_stat_in_hot_file_head_list(p_hot_file_stat))
	                list_move(&p_hot_file_stat->hot_file_list,&hot_file_global_info.hot_file_head_temp_large);
                    spin_unlock(&hot_file_global_info.hot_file_lock);
		}
	    }
	    //parent_node可能是NULL，此时索引是0的file_area保存在hot_file_tree的根节点root_node里
	    if(open_shrink_printk && p_hot_file_area->area_access_count == 1 && parent_node)
	        printk("%s %s %d hot_file_global_info:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x hot_file_area->area_access_count:%d hot_file_area->file_area_age:%lu page:0x%llx page->index:%ld file_area_hot_count:%d file_area_count:%d shrink_time:%d start_index:%ld page_slot_in_tree:0x%llx tree-height:%d parent_node:0x%llx parent_node->count:0x%d\n",__func__,current->comm,current->pid,(u64)(&hot_file_global_info),(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state,p_hot_file_area->area_access_count,p_hot_file_area->file_area_age,(u64)page,page->index,p_hot_file_stat->file_area_hot_count,p_hot_file_stat->file_area_count,p_hot_file_area->shrink_time,p_hot_file_area->start_index,(u64)page_slot_in_tree,p_hot_file_stat->hot_file_area_tree_root_node.height,(u64)parent_node,parent_node->count);
	   
	    if(p_hot_file_area->file_area_age > hot_file_global_info.global_age)
	        panic("p_hot_file_area->file_area_age:%ld > hot_file_global_info.global_age:%ld\n",p_hot_file_area->file_area_age,hot_file_global_info.global_age);
/*	    
	}	
	else//走到这个分支，说明之前为当前访问的文件分配了hot_file_stat结构
	{
            struct hot_file_area_tree_node *parent_node;
	    //从mapping得到该文件绑定的hot_file_stat结构
	    p_hot_file_stat = mapping->hot_file_stat;
	   
	    //根据page索引找到所在的hot_file_area的索引，二者关系默认是 hot_file_area的索引 = page索引/6
            area_index_for_page =  page->index >> PAGE_COUNT_IN_AREA_SHIFT;
	    //需要加锁，多个进程同时访问同一个page索引，得到同一个hot_file_area结构，同时令 p_hot_file_area->area_access_count ++，那就出问题了，多线程同时对同一个变量修改必须加锁
	    spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
	    //根据page索引的hot_file_area的索引，找到对应在file area tree树的槽位，page_slot_in_tree双重指针指向这个槽位。
	    //下边分配真正的hot_file_area结构，把hot_file_area指针保存到这个操作
	    parent_node = hot_file_area_tree_lookup_and_create(&mapping->hot_file_stat->root_node,area_index_for_page,&page_slot_in_tree);
            if(IS_ERR(parent_node)){
	        printk("%s hot_file_area_tree_insert fail\n",__func__);
		goto err;
	    }
	    if(*page_slot_in_tree == NULL){//针对当前page索引的hot_file_area结构还没有分配
		//针对本次page索引，分配hot_file_area一个结构，于是该hot_file_area就代表了page
		p_hot_file_area = kmem_cache_alloc(hot_file_global_info.hot_file_area_cachep,GFP_ATOMIC);
		if (!p_hot_file_area) {
		    printk("%s hot_file_area alloc fail\n",__func__);
		    ret =  -ENOMEM;
		    goto err;
		}
		memset(hot_file_area_cache,sizeof(hot_file_area),0);
	        //把根据page索引分配的hot_file_area结构指针保存到file area tree指定的槽位
	        rcu_assign_pointer(page_slot_in_tree,p_hot_file_area);
	        //把新分配的hot_file_area添加到hot_file_area_temp链表
	        list_add_rcu(p_hot_file_area->hot_file_area_list,p_hot_file_stat->hot_file_area_temp);
		//保存该hot_file_area对应的起始page索引，一个hot_file_area默认包含6个索引挨着依次增大page，start_index保存其中第一个page的索引
		p_hot_file_area->start_index = (page->index >> PAGE_COUNT_IN_AREA_SHIFT) * PAGE_COUNT_IN_AREA;
		//新分配的hot_file_area指向其在hot_file_area_tree的父节点node
		p_hot_file_area->parent = parent_node;
            }
	    p_hot_file_area = *page_slot_in_tree; 
	    //hot_file_area热点区域访问数加1，表示这个hot_file_area的区域的page被访问的次数加1
	    p_hot_file_area->area_access_count ++;
	    //该文件访问次数加1
	    p_hot_file_stat->file_access_count++;
	    spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);

        }
*/
err:
	//不能因为走了err分支，就释放p_hot_file_stat和p_hot_file_area结构。二者都已经添加到ot_file_global_info.hot_file_head 或 p_hot_file_stat->hot_file_area_temp链表，
	//不能释放二者的数据结构。是这样吗，得再考虑一下???????????????????????
	if(p_hot_file_stat){
	    //kmem_cache_free(hot_file_global_info.hot_file_stat_cachep,p_hot_file_stat);
	}
	if(p_hot_file_area){
	    //kmem_cache_free(hot_file_global_info.hot_file_area_cachep,p_hot_file_area);
	}
	return ret;
    }

    return 0;
}
EXPORT_SYMBOL(hot_file_update_file_status);
static unsigned long hot_file_shrink_pages(struct hot_file_global *p_hot_file_global)
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

    struct hot_file_node_pgdat *p_hot_file_node_pgdat = p_hot_file_global->p_hot_file_node_pgdat;
    //遍历每个内存节点上p_hot_file_node_pgdat[i]->pgdat_page_list 上的page，释放它，
    for(i = 0;i < hot_file_global_info.node_count;i ++){
        struct list_head *p_pgdat_page_list = &p_hot_file_node_pgdat[i].pgdat_page_list;
        if(open_shrink_printk)
            printk("1:%s %s %d node:0x%d pgdat:0x%llx\n",__func__,current->comm,current->pid,i,(u64)p_hot_file_node_pgdat[i].pgdat);
        if(!list_empty(p_pgdat_page_list)){
	    //开始释放p_hot_file_node_pgdat[i]->pgdat_page_list链表上的page
            nr_reclaimed += async_shrink_free_page(p_hot_file_node_pgdat[i].pgdat,NULL,p_pgdat_page_list,&sc,&stat);
	    //把p_hot_file_node_pgdat[i]->pgdat_page_list链表上未释放成功的page再移动到lru链表
	    hot_file_putback_inactive_pages(p_hot_file_node_pgdat[i].pgdat,p_pgdat_page_list);

	    //此时p_hot_file_node_pgdat[pgdat->node_id]->pgdat_page_list链表上还残留的page没人再用了，引用计数是0，这里直接释放
	    mem_cgroup_uncharge_list_async(p_pgdat_page_list);
	    free_unref_page_list_async(p_pgdat_page_list);
	}
    }
    return nr_reclaimed;
}
#if 0
-int walk_throuth_all_hot_file_area(struct hot_file_global *p_hot_file_global)
{
    struct hot_file_stat * p_hot_file_stat,*p_hot_file_stat_temp;
    struct hot_file_area *p_hot_file_area,*p_hot_file_area_temp;
    LIST_HEAD(hot_file_area_list);
    LIST_HEAD(global_hot_file_head_temp_list);
    LIST_HEAD(hot_file_stat_free_list);
    unsigned int scan_file_area_count  = 0;
    unsigned int scan_file_area_max = 1024;
    unsigned int scan_file_stat_count  = 0;
    unsigned int scan_file_stat_max = 64;
    
    unsigned int file_area_count_in_cold_list = 0;
    unsigned int file_stat_count_in_cold_list = 0;
    unsigned int scan_cold_file_stat_count,scan_cold_file_area_count;
    
    spin_lock_irq(&p_hot_file_global->hot_file_lock);
    //先从global hot_file_head_temp链表尾隔离scan_file_stat_max个hot_file_stat到 global_hot_file_head_temp_list 临时链表
    list_for_each_entry_safe_reverse(p_hot_file_stat,p_hot_file_stat_temp,&p_hot_file_global->hot_file_head_temp,hot_file_list){
	//这里把hot_file_stat 移动到 global_hot_file_head_temp_list 临时链表，用不用清理的file_stat的 file_area_in_temp_list 标记????????????????????????????????????????????
	//这里用不用把hot_file_stat->file_stat_status设置成无效，因为不在hot_file_global的任何链表了?????????????????????????????????????
        list_move(&p_hot_file_stat->hot_file_list,&global_hot_file_head_temp_list);
	if(scan_file_stat_count ++ > scan_file_stat_max)
	    break;
    }
    spin_unlock_irq(&p_hot_file_global->hot_file_lock);

    //在遍历hot_file_global->hot_file_head_temp链表期间，可能创建了新文件并创建了hot_file_stat并添加到hot_file_global->hot_file_head_temp链表，
    //下边遍历hot_file_global->hot_file_head链表成员期间，是否用hot_file_global_info.hot_file_lock加锁？不用，因为遍历链表期间
    //向链表添加成员没事，只要不删除成员！想想我写的内存屏障那片文章讲解list_del_rcu的代码
    //list_for_each_entry_safe_reverse(p_hot_file_stat,&p_hot_file_global->hot_file_head_temp,hot_file_list)//从链表尾开始遍历，链表尾的成员更老，链表头的成员是最新添加的
    list_for_each_entry_safe(p_hot_file_stat,p_hot_file_stat_temp,&global_hot_file_head_temp_list,hot_file_list)//本质就是遍历p_hot_file_global->hot_file_head_temp链表尾的hot_file_stat
    {
        if(!file_stat_in_hot_file_head_temp(p_hot_file_stat))
	    panic("p_hot_file_stat:0x%llx status:%d not in free_temp_list\n",(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);

	file_area_count_in_cold_list = 0;
	//注意，这里扫描的global hot_file_head_temp上的hot_file_stat肯定有冷hot_file_area，因为hot_file_stat只要50%的hot_file_area是热的，hot_file_stat就要移动到
	//global hot_file_head 链表。
        list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_temp,hot_file_area_list)//从链表尾开始遍历，链表尾的成员更老，链表头的成员是最新添加的
	{
	    if(!file_area_in_temp_list(p_hot_file_area))
		panic("file_area_in_temp_list:0x%llx status:%d not in hot_file_area_temp\n",(u64)p_hot_file_area,p_hot_file_area->file_area_state);

	    scan_file_area_count ++;
	    //本周期内，该p_hot_file_area 依然没有被访问，移动到hot_file_area_cold链表头
	    if(p_hot_file_area->area_access_count == p_hot_file_area->last_access_count){

	        spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
		set_file_area_in_cold_list(p_hot_file_area);
		//需要加锁，此时可能有进程执行hot_file_update_file_status()并发向该p_hot_file_area前或者后插入新的hot_file_area，这里是把该p_hot_file_area从hot_file_area_temp链表剔除，存在同时修改该p_hot_file_area在hot_file_area_temp链表前的hot_file_area结构的next指针和在链表后的hot_file_area结构的prev指针，并发修改同一个变量就需要加锁。
                list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_cold);
	        spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
		file_area_count_in_cold_list ++;
                
		//把有冷hot_file_area的hot_file_stat移动到global cold_file_head链表，并设置file_stat_in_head_temp_list
		if(!file_stat_in_hot_file_head_temp(p_hot_file_stat)){
		    //是否会存在并发设置p_hot_file_stat->file_stat_status的情况??????????????? 这里没有加锁，需要考虑这点???????????????
		    set_file_stat_in_head_temp_list(p_hot_file_stat);
		    //这里不用加锁，此时p_hot_file_stat是在 global_hot_file_head_temp_list临时链表，并且把p_hot_file_stat移动到
		    //global cold_file_head链表，只在walk_throuth_all_hot_file_area()函数单线程操作，不存在并发
		    list_move(&p_hot_file_stat->hot_file_list,&p_hot_file_global->cold_file_head);
		    //本轮扫描移动到global cold_file_head链表头的file_stat个数
		    file_stat_count_in_cold_list ++;
		}
	    }
	    
	    //凡是扫描到的hot_file_area都令last_access_count与area_access_count相等，下轮周期该hot_file_area被访问，则area_access_count就大于last_access_count。
	    //这样做有两个用处。1:该hot_file_area本轮扫描last_access_count与area_access_count就相等，则前边把 p_hot_file_area移动到了hot_file_area_cold链表。
	    //如果后续该 p_hot_file_area又被访问了则last_access_count与area_access_count不等，则把p_hot_file_area移动到hot_file_area_temp链表头。下轮扫描，从
	    //该文件p_hot_file_stat的链表尾扫到的p_hot_file_area都是新的，不会重复扫描。 情况2:本轮扫描p_hot_file_area的last_access_count与area_access_count不等，
	    //说明是热hot_file_area，这里令last_access_count与area_access_count相等，看下轮扫描周期带来时，该p_hot_file_area是否会被再被访问而area_access_count加1，
	    //没被访问那last_access_count与area_access_count下轮扫描就相等，就可以把p_hot_file_area移动到hot_file_area_cold链表了
            p_hot_file_area->last_access_count = p_hot_file_area->area_access_count;
	}
	//把本轮扫描 移动到该文件hot_file_stat的hot_file_area_cold链表上的file_area个数保存到p_hot_file_stat->file_area_count_in_cold_list
        if(file_area_count_in_cold_list > 0)
	    p_hot_file_stat->file_area_count_in_cold_list = file_area_count_in_cold_list;

	if(!list_empty(&p_hot_file_stat->hot_file_area_free)){
	    //hot_file_area_free链表上长时间没访问的hot_file_area释放掉
	    list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_free,hot_file_area_list){
	        if(p_hot_file_area->area_access_count - p_hot_file_area->last_access_count > 0){
	            spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
                    list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
	            set_file_area_in_temp_list(p_hot_file_area);
	            spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);

		    p_hot_file_area->cold_time = 0;//冷却计数清0
 	        }else{
		    p_hot_file_area->cold_time ++;
		    //hot_file_area冷的次数达到阀值则释放掉它
		    if(p_hot_file_area->cold_time > HOT_FILE_AREA_FREE_LEVEL)
		        hot_file_area_detele(p_hot_file_global,p_hot_file_stat,p_hot_file_area);
		}
	    }
	}
        //防止在for循环耗时太长，限制遍历的文件hot_file_stat数。这里两个问题 问题1:单个hot_file_stat上的hot_file_area太多了，只扫描一个hot_file_stat这里就
	//break跳出循环了。这样下边就把global_hot_file_head_temp_list残留的hot_file_stat移动到global hot_file_head_temp链表头了。下轮扫描从
	//global hot_file_head_temp尾就扫描不到该hot_file_stat了。合理的做法是，把这些压根没扫描的hot_file_stat再移动到global hot_file_head_temp尾。问题2：
	//还是 单个hot_file_stat上的hot_file_area太多了，没扫描完，下次再扫描该hot_file_stat时，直接从上次结束的hot_file_area位置处继续扫描，似乎更合理。
	//hot_file_stat断点hot_file_area继续扫描！但是实现起来似乎比较繁琐，算了
	if(scan_file_area_count > scan_file_area_max)
	    break;
    }
    //把global_hot_file_head_temp_list残留的hot_file_stat移动到global hot_file_head_temp链表头。这样做就保证本轮从global hot_file_head_temp尾扫到的
    //hot_file_stat要么移动到了globa cold_file_head链表，要么移动到global hot_file_head_temp链表头。这样下轮从global hot_file_head_temp尾扫到的hot_file_stat之前没扫描过。
    //错了！上边扫描的global hot_file_head_temp链表尾的hot_file_stat肯定有冷hot_file_area。因为hot_file_stat只要50%的hot_file_area是热的，hot_file_stat就要移动到
    //global hot_file_head 链表。global hot_file_head_temp链表上的hot_file_stat肯定有hot_file_area。这里还残留在global_hot_file_head_temp_list上的hot_file_stat,
    //本轮就没有扫描到，因此要移动到global hot_file_head_temp链表尾，下轮扫描继续扫描这些hot_file_stat
    if(!list_empty(&global_hot_file_head_temp_list)){
        spin_lock_irq(&p_hot_file_global->hot_file_lock);
	//set_file_stat_in_head_temp_list(p_hot_file_stat);//不用再设置这些hot_file_stat的状态，这些hot_file_stat没有移动到global hot_file_area_cold链表，没改变状态
        //list_splice(&global_hot_file_head_temp_list,&p_hot_file_global->hot_file_head_temp);//移动到global hot_file_head_temp链表头
        list_splice_tail(&global_hot_file_head_temp_list,&p_hot_file_global->hot_file_head_temp);//global hot_file_head_temp链表尾
        spin_unlock_irq(&p_hot_file_global->hot_file_lock);
    }
    
    //遍历hot_file_area_cold链表尾上p_hot_file_area->old_file_area_count_in_cold_list个hot_file_stat，这些hot_file_stat上一轮扫描因为有
    //冷file_area而移动到了hot_file_stat->hot_file_area_cold链表头。现在新的一轮扫描，再次从hot_file_stat->hot_file_area_cold链表尾巴
    //如果这些hot_file_stat里上一轮被判定是冷的file_area还是冷的，那就释放这些file_area
    /*这个for循环是内存回收的关键，这里要借助上轮扫描在上边的循环中:把有冷file_area的hot_file_stat移动到了global->hot_file_area_cold链表头。现在新的一轮扫描，
     次从hot_file_stat->hot_file_area_cold链表尾巴扫描前一轮扫描移动到hot_file_stat->hot_file_area_cold的hot_file_stat,下边详述

     1:第1轮扫描，上边的循环，从global->hot_file_head_temp链表尾巴扫到64个hot_file_stat，它们全有冷的hot_file_area，于是这些hot_file_stat全移动到了global->hot_file_area_cold链表头,
       注意是，链表头，要记录一共移动了多少个hot_file_stat保存到file_area_count_in_cold_list临时变量.同时呢，这些hot_file_stat链表hot_file_area_temp尾扫到的被判定
       冷的hot_file_area(即area_access_count和last_access_count相等)要移动到hot_file_stat->hot_file_area_cold链表头，注意是链表头，
       同时要记录移动了多少个hot_file_area并保存到p_hot_file_stat->file_area_count_in_cold_list。

       然后，执行到下边for循环，因为是第一次执行 if(free_hot_file_area_count == p_hot_file_area->old_file_area_count_in_cold_list)直接成立，执行
       p_hot_file_area->old_file_area_count_in_cold_list = p_hot_file_area->file_area_count_in_cold_list赋值，然后break跳出for循环。接着
       if(free_hot_file_area_count == p_hot_file_area->old_file_area_count_in_cold_list)成立，执行赋值
       p_hot_file_area->old_file_area_count_in_cold_list = p_hot_file_area->file_area_count_in_cold_list，然后break跳出循环。这就相当于第1轮扫描时，在下边的for循环中，
       p_hot_file_global->cold_file_head上的hot_file_stat 和 p_hot_file_stat->hot_file_area_cold上的hot_file_area一个都没遍历。
       就应该这样，这些都是刚才上边的for循环刚移动到p_hot_file_global->cold_file_head和p_hot_file_stat->hot_file_area_cold上的，要等第2轮扫描再遍历。

      2:第2轮扫描，执行上边的for循环:重复第一步的操作，把global->hot_file_head_temp链表新扫描的hot_file_stat移动到global->hot_file_area_cold链表头,把这些hot_file_stat上被判定
      是冷hot_file_area移动到hot_file_stat的hot_file_area_cold链表头。然后执行下边的for循环，从p_hot_file_stat->hot_file_area_cold链表尾巴遍历
      p_hot_file_area->old_file_area_count_in_cold_list 个hot_file_area，这些个hot_file_area是第1次扫描时上边的for循环从p_hot_file_stat->hot_file_area_temp链表尾移动
      到p_hot_file_area->old_file_area_count_in_cold_list链表头的，现在第2轮扫描，这些hot_file_area在p_hot_file_area->old_file_area_count_in_cold_list链表尾了。为什么？
      。因为现在第2轮扫描，上边的for循环又从p_hot_file_stat->hot_file_area_temp链表移动到了p_hot_file_area->old_file_area_count_in_cold_list 链表头 一些hot_file_area。则第1轮
      扫描移动到p_hot_file_area->old_file_area_count_in_cold_list链表的hot_file_area就成了在p_hot_file_area->old_file_area_count_in_cold_list链表尾了。
      
      继续，在下边大for循环里，从p_hot_file_global->cold_file_head链表尾扫描p_hot_file_stat->file_stat_count_in_cold_list个hot_file_stat后，跳出下边的for循环。
      这 p_hot_file_stat->file_stat_count_in_cold_list个hot_file_stat是第1轮扫描时，上边的for循环从p_hot_file_global->hot_file_head_temp链表尾移动到
      p_hot_file_global->cold_file_head头，现在第2轮扫描，又从p_hot_file_global->hot_file_head_temp链表尾移动的一些hot_file_stat到
      p_hot_file_global->cold_file_head头。于是第1轮扫描时，移动到p_hot_file_global->cold_file_head头的hot_file_stat就成了在
      p_hot_file_global->cold_file_head链表尾。
      
      这个过程解释起来太繁琐了。简单总结说：第1轮扫描，上边的for循环，从global->hot_file_head_temp链表尾移动N1个hot_file_stat到global->hot_file_area_cold链表头。
      同时，遍历这N1个hot_file_stat的hot_file_area_temp链表尾N2个冷hot_file_area，并移动到hot_file_stat的hot_file_area_cold链表头。
      紧接着第2轮扫描，上边的fro循环重复第1轮的操作，再次向global->hot_file_area_cold链表头移动N1_1个hot_file_stat，向这些hot_file_stat的hot_file_area_cold链表头移动N2_1
      个hot_file_area。然后第2轮扫描，在下边for循环，从global->hot_file_area_cold链表尾巴遍历N1个第1轮扫描移动的hot_file_stat，再遍历这些hot_file_stat的hot_file_area_cold
      链表尾巴上N2个第1轮扫描移动的冷hot_file_area。这些hot_file_area第1轮扫描已经判定是冷hot_file_area，现在第2轮扫描，这些hot_file_area如果还是冷的，那就把这些
      hot_file_area移动到hot_file_stat的hot_file_area_free链表，然后就释放这些hot_file_area对应的page。说到底，绕来绕去的，就是保证一个hot_file_area必须经过
      两轮扫描判定都是冷的hot_file_area，才能释放这些hot_file_area对应的page。
      */
    scan_cold_file_stat_count = 0;
    list_for_each_entry_safe_reverse(p_hot_file_stat,p_hot_file_stat_temp,&p_hot_file_global->cold_file_head,hot_file_list)
    {
	/*//该if成立，说明上一轮扫描移动到global cold_file_head链表头的p_hot_file_stat->file_stat_count_in_cold_list个hot_file_stat已经遍历完了，不能继续向前
	//扫描hot_file_stat了，因为再向前的hot_file_stat是本轮扫描移动到global cold_file_head链表的。这个if判断要放到for循环开头,因为第一次执行到这里，
	//scan_cold_file_stat_count和p_hot_file_stat->file_stat_count_in_cold_list都是0-------------不行，这样就无法执行里边的for循环代码:
	//if(free_hot_file_area_count == p_hot_file_area->old_file_area_count_in_cold_list)里的
	//p_hot_file_area->old_file_area_count_in_cold_list = p_hot_file_area->file_area_count_in_cold_list;这个赋值了!!!!!!!!!!。给要移动到后边
        if(scan_cold_file_stat_count == p_hot_file_stat->file_stat_count_in_cold_list){
	    //把本轮扫描移动到global cold_file_head链表的file_stat个数保存到p_hot_file_stat->file_stat_count_in_cold_list
            p_hot_file_global->file_stat_count_in_cold_list = file_stat_count_in_cold_list;
	    break;
	}*/

        if(!file_stat_in_hot_file_head_temp(p_hot_file_stat))
	    panic("p_hot_file_stat:0x%llx status:%d not in free_temp_list\n",(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);

	scan_cold_file_area_count = 0;
        list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_cold,hot_file_area_list)
	{
	    //该if成立，说明上一轮扫描该p_hot_file_area被判定是冷hot_file_area而移动到p_hot_file_stat->hot_file_area_cold链表的p_hot_file_area->old_file_area_count_in_cold_list
	    //个hot_file_area已经都扫描完了，不能再向前扫描了，因为再向前的hot_file_area是本轮扫描移动到p_hot_file_stat->hot_file_area_cold链表的。这if判断要放到for循环最开头，因为
	    //第一次扫描时scan_cold_file_area_count是0，p_hot_file_area->old_file_area_count_in_cold_list也是0
            if(scan_cold_file_area_count == p_hot_file_stat->old_file_area_count_in_cold_list){
		p_hot_file_stat->old_file_area_count_in_cold_list = p_hot_file_stat->file_area_count_in_cold_list;
	        break;
	    }
	    //scan_cold_file_area_count++要放到if判断后边，因为第一次扫描执行到if判断，free_hot_file_area_count 和 p_hot_file_area->old_file_area_count_in_cold_list 都是0，得break跳出
	    scan_cold_file_area_count++;

	    if(!file_area_in_temp_list(p_hot_file_area))
	        panic("file_area_in_temp_list:0x%llx status:%d not in hot_file_area_temp\n",(u64)p_hot_file_area,p_hot_file_area->file_area_state);

	    //file_area 依然没有被访问，就释放 hot_file_stat 对应的page了
	    if(p_hot_file_area->area_access_count == p_hot_file_area->last_access_count){
                list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_free_temp);
	    }
	    //file_area 又被访问了，则把hot_file_area添加到hot_file_area_temp临时链表
	    else{
		//需要加锁，hot_file_update_file_status()函数中会并发向该文件p_hot_file_stat->hot_file_area_temp添加新的hot_file_area结构
	        spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
                list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
		set_file_area_in_temp_list(p_hot_file_area);
		//有没有必要用area_access_count重置last_access_count，重置的话，后续该file_area不再被访问就又要把从hot_file_area_temp移动到hot_file_area_cold链表
		//p_hot_file_area->last_access_count = p_hot_file_area->area_access_count;??????????????????????????????
	        spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
	    }
        }
	//if成立，说明当前p_hot_file_stat，有冷hot_file_area添加到了p_hot_file_stat->hot_file_area_free链表
	if(0 != scan_cold_file_area_count){
            //把有冷hot_file_area的文件的hot_file_stat移动到hot_file_stat_free_list链表
	    //这里用不用把hot_file_stat->file_stat_status设置成无效，因为不在hot_file_global的任何链表了?????????????????????????????????????
            list_move(&p_hot_file_stat->hot_file_list,&hot_file_stat_free_list);
	}
	//该if成立，说明上一轮扫描移动到global cold_file_head链表头的p_hot_file_stat->file_stat_count_in_cold_list个hot_file_stat已经遍历完了，不能继续向前
	//扫描hot_file_stat了，因为再向前的hot_file_stat是本轮扫描移动到global cold_file_head链表的hot_file_stat
        if(scan_cold_file_stat_count == p_hot_file_global->file_stat_count_in_cold_list){
	    //把本轮扫描移动到global cold_file_head链表的file_stat个数保存到p_hot_file_stat->file_stat_count_in_cold_list
            p_hot_file_global->file_stat_count_in_cold_list = file_stat_count_in_cold_list;
	    break;
	}
	//scan_cold_file_stat_count++要放到if判断后边，因为第1轮扫描时，没有要扫描的hot_file_stat，scan_cold_file_stat_count和p_hot_file_stat->file_stat_count_in_cold_list都是0
	//上边直接break条春大的ffor循环
        scan_cold_file_stat_count ++;
    }
    //遍历hot_file_stat_free_list上的hot_file_stat，这些hot_file_stat有两轮扫描都判定是冷的hot_file_area，于是释放这些
    list_for_each_entry_safe_reverse(p_hot_file_stat,p_hot_file_stat_temp,&hot_file_stat_free_list,hot_file_list)
    {
        //对hot_file_area_free_temp上的hot_file_stat上的hot_file_area对应的page进行隔离，隔离成功的移动到p_hot_file_global->hot_file_node_pgdat->pgdat_page_list对应内存节点链表上
        hot_file_isolate_lru_pages(p_hot_file_global,p_hot_file_stat,&p_hot_file_stat->hot_file_area_free_temp);
	//这里真正释放内存page
	hot_file_shrink_pages(p_hot_file_global);
   
        /*注意，hot_file_stat->hot_file_area_free_temp 和 hot_file_stat->hot_file_area_free 各有用处。hot_file_area_free_temp保存每次扫描释放的page的hot_file_area。
	  释放后把这些hot_file_area移动到hot_file_area_free链表，hot_file_area_free保存的是每轮扫描释放page的hot_file_area，是所有的!!!!!!!!!!!!!!*/

	//把hot_file_area_free_temp链表上的hot_file_area结构再移动到hot_file_area_free链表，hot_file_area_free链表上的hot_file_area结构要长时间也没被访问就释放掉
        if(!list_empty(&p_hot_file_stat->hot_file_area_free_temp)){
            list_splice(&p_hot_file_stat->hot_file_area_free_temp,&p_hot_file_stat->hot_file_area_free);
        }
    }

    //把本轮扫描并释放page的hot_file_stat再移动后p_hot_file_global->hot_file_head链表头。注意是链表头，因为上边扫描时是从p_hot_file_global->hot_file_head链表尾
    //开始扫描的。这样做是保证下轮扫描不再扫描到这些hot_file_stat，而是扫描其他p_hot_file_global->hot_file_head链表尾的hot_file_stat
    if(!list_empty(&hot_file_stat_free_list)){
        list_for_each_entry(p_hot_file_stat,&hot_file_stat_free_list,hot_file_list)
            set_file_stat_in_head_temp_list(p_hot_file_stat);//设置hot_file_stat状态为head_temp_list

        spin_lock_irq(&p_hot_file_global->hot_file_lock);
	//把这些hot_file_stat移动回p_hot_file_global->hot_file_head_temp链表头
        list_splice(&hot_file_stat_free_list,&p_hot_file_global->hot_file_head_temp);
	spin_unlock_irq(&p_hot_file_global->hot_file_lock);
    }


    return 0;
}
#else
//遍历hot_file_global->hot_file_head_temp_large或hot_file_head_temp链表尾巴上边的文件file_stat，然后遍历这些file_stat的hot_file_stat->hot_file_area_temp链表尾巴上的file_area，
//被判定是冷的file_area则移动到hot_file_stat->hot_file_area_free_temp链表。把有冷file_area的file_stat移动到file_stat_free_list临时链表。返回值是遍历到的冷file_area个数
static unsigned int get_file_area_from_file_stat_list(struct hot_file_global *p_hot_file_global,unsigned int scan_file_area_max,unsigned int scan_file_stat_max,
	                                 //hot_file_head_temp来自 hot_file_global->hot_file_head_temp 或 hot_file_global->hot_file_head_temp_large 链表
          	                         struct list_head *hot_file_head_temp,struct list_head *file_stat_free_list){
    struct hot_file_stat * p_hot_file_stat,*p_hot_file_stat_temp;
    struct hot_file_area *p_hot_file_area,*p_hot_file_area_temp;

    unsigned int scan_file_area_count  = 0;
    unsigned int scan_file_stat_count  = 0;
    unsigned int scan_cold_file_area_count = 0;
    unsigned int cold_file_area_for_file_stat = 0;
    unsigned int file_stat_count_in_cold_list = 0;
    unsigned int serial_hot_file_area = 0;
    LIST_HEAD(file_stat_list_temp);
    //暂存从hot_file_global->hot_file_head_temp 或 hot_file_global->hot_file_head_temp_large 链表链表尾扫描到的file_stat
    LIST_HEAD(global_hot_file_head_temp_list);

     /*必须要先从hot_file_head_temp或hot_file_head_temp_large隔离多个file_stat，然后去遍历这些file_stat上的file_area，这样只用开关一次hot_file_global->hot_file_lock锁.
      * 否则每遍历一个file_stat，都开关一次hot_file_global->hot_file_lock锁，太损耗性能。*/
    spin_lock_irq(&p_hot_file_global->hot_file_lock);
    //先从global hot_file_head_temp链表尾隔离scan_file_stat_max个hot_file_stat到 global_hot_file_head_temp_list 临时链表
    list_for_each_entry_safe_reverse(p_hot_file_stat,p_hot_file_stat_temp,hot_file_head_temp,hot_file_list){
	//这里把hot_file_stat 移动到 global_hot_file_head_temp_list 临时链表，用不用清理的file_stat的 in_hot_file_head_temp 标记，需要的。因为hot_file_update_file_status()
	//函数中会并发因为file_stat的 in_hot_file_head_temp 标记，而移动到file_stat的hot_file_head链表，不能有这种并发操作
	if(!file_stat_in_hot_file_head_temp_list(p_hot_file_stat))
	    panic("%s file_stat:0x%llx not int hot_file_head_temp status:0x%x\n",__func__,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);
        else if(file_stat_in_delete(p_hot_file_stat)){
		//如果该文件inode被释放了，则把对应file_stat移动到hot_file_global->hot_file_head_delete链表
		list_move(&p_hot_file_stat->hot_file_list,&p_hot_file_global->hot_file_head_delete);
		continue;
	}

	/*hot_file_head_temp来自 hot_file_global->hot_file_head_temp 或 hot_file_global->hot_file_head_temp_large 链表，当是hot_file_global->hot_file_head_temp_large
	 * 时，file_stat_in_large_file(p_hot_file_stat)才会成立*/

        //当file_stat上有些file_area长时间没有被访问则会释放掉file_are结构。此时原本在hot_file_global->hot_file_head_temp_large 链表的大文件file_stat则会因
	//file_area数量减少而需要降级移动到hot_file_global->hot_file_head_temp链表.这个判断起始可以放到hot_file_update_file_status()函数，算了降低损耗
	if(!is_file_stat_large_file(&hot_file_global_info,p_hot_file_stat) && file_stat_in_large_file(p_hot_file_stat)){
	    if(open_shrink_printk)
	        printk("1:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x not is_file_stat_large_file\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);

            clear_file_stat_in_large_file(p_hot_file_stat);
	    //不用现在把file_stat移动到global hot_file_head_temp链表。等该file_stat的file_area经过内存回收后，该file_stat会因为clear_file_stat_in_large_file而移动到hot_file_head_temp链表
	    //想了想，还是现在就移动到file_stat->hot_file_head_temp链表尾，否则内存回收再移动更麻烦。要移动到链表尾，这样紧接着就会从hot_file_head_temp链表链表尾扫描到该file_stat
	    list_move_tail(&p_hot_file_stat->hot_file_list,&p_hot_file_global->hot_file_head_temp);
	    continue;
	}

	//需要设置这些hot_file_stat不再处于hot_file_head_temp链表，否则之后hot_file_update_file_status()会因该file_stat的热file_area很多而移动到global hot_file_head_temp链表
	clear_file_stat_in_hot_file_head_temp_list(p_hot_file_stat);
        //扫描到的file_stat先移动到global_hot_file_head_temp_list临时链表，下边就开始遍历这些file_stat上的file_area
        list_move(&p_hot_file_stat->hot_file_list,&global_hot_file_head_temp_list);
	if(scan_file_stat_count ++ > scan_file_stat_max)
	    break;
    }
    spin_unlock_irq(&p_hot_file_global->hot_file_lock);

    //在遍历hot_file_global->hot_file_head_temp链表期间，可能创建了新文件并创建了hot_file_stat并添加到hot_file_global->hot_file_head_temp链表，
    //下边遍历hot_file_global->hot_file_head链表成员期间，是否用hot_file_global_info.hot_file_lock加锁？不用，因为遍历链表期间
    //向链表添加成员没事，只要不删除成员！想想我写的内存屏障那片文章讲解list_del_rcu的代码
    //list_for_each_entry_safe_reverse(p_hot_file_stat,&p_hot_file_global->hot_file_head_temp,hot_file_list)//从链表尾开始遍历，链表尾的成员更老，链表头的成员是最新添加的
    list_for_each_entry_safe(p_hot_file_stat,p_hot_file_stat_temp,&global_hot_file_head_temp_list,hot_file_list)//本质就是遍历p_hot_file_global->hot_file_head_temp链表尾的hot_file_stat
    {
	//此时file_stat已经在前边被清理in_hot_file_head_temp_list标记了，不应该再做这个判断
        //if(!file_stat_in_hot_file_head_temp_list(p_hot_file_stat))
	//    panic("p_hot_file_stat:0x%llx status:%d not in free_temp_list\n",(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);

	cold_file_area_for_file_stat = 0;
	serial_hot_file_area = 0;
	//注意，这里扫描的global hot_file_head_temp上的hot_file_stat肯定有冷hot_file_area，因为hot_file_stat只要50%的hot_file_area是热的，hot_file_stat就要移动到
	//global hot_file_head 链表。
        list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_temp,hot_file_area_list)//从链表尾开始遍历，链表尾的成员更老，链表头的成员是最新添加的
	{
	    if(!file_area_in_temp_list(p_hot_file_area))
		panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_temp\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

	    scan_file_area_count ++;
	    //本周期内，该p_hot_file_area 依然没有被访问，移动到hot_file_area_cold链表头
	    //if(p_hot_file_area->area_access_count == p_hot_file_area->last_access_count){
	    
            //hot_file_area经过GOLD_FILE_AREA_LEVAL个周期还没有被访问，则被判定是冷file_area，然后就释放该file_area的page
	    if(p_hot_file_global->global_age - p_hot_file_area->file_area_age > GOLD_FILE_AREA_LEVAL){
                //每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
	        spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
		//为什么hot_file_stat_lock加锁后要再判断一次file_area是不是被访问了。因为可能有这种情况:上边的if成立，此时file_area还没被访问。但是此时有进程
		//先执行hot_file_update_file_status()获取hot_file_stat_lock锁，然后访问当前file_area，file_area不再冷了。当前进程此时获取hot_file_stat_lock锁失败。
		//等获取hot_file_stat_lock锁成功后，file_area的file_area_age就和global_age相等了。一次，变量加减后的判断，在spin_lock前后各判断一次有必要的!!!!!!!!!!!!!!!!!!!!!!!!
                if(p_hot_file_global->global_age - p_hot_file_area->file_area_age <= GOLD_FILE_AREA_LEVAL){
		   spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);    
                   continue;
		}
	        //if(open_shrink_printk)
	        //    printk("2:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x is cold file_area\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

                serial_hot_file_area = 0;
		clear_file_area_in_temp_list(p_hot_file_area);
		//设置file_area处于file_stat的free_temp_list链表。这里设定，不管file_area处于hot_file_stat->hot_file_area_free_temp还是hot_file_stat->hot_file_area_free
		//链表，都是file_area_in_free_list状态，没有必要再区分二者。主要设置file_area的状态需要遍历每个file_area并hot_file_stat_lock加锁，
		//再多设置一次set_file_area_in_free_temp_list状态浪费性能。这点需注意!!!!!!!!!!!!!!!!!!!!!!!
		set_file_area_in_free_list(p_hot_file_area);
		//需要加锁，此时可能有进程执行hot_file_update_file_status()并发向该p_hot_file_area前或者后插入新的hot_file_area，这里是把该p_hot_file_area从hot_file_area_temp链表剔除，存在同时修改该p_hot_file_area在hot_file_area_temp链表前的hot_file_area结构的next指针和在链表后的hot_file_area结构的prev指针，并发修改同一个变量就需要加锁。
                //list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_cold);
                list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_free_temp);
	        spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
		//file_area_count_in_cold_list ++;
         #if  0
		/*1:把有冷hot_file_area的hot_file_stat移动到file_stat_free_list临时链表.此时的file_sata已经不在hot_file_head_temp链表，上边已经清理掉
		 *2:如果hot_file_stat->hot_file_area_refault链表非空，说明也需要扫描这上边的file_area，要把上边冷的file_area移动回hot_file_head_temp_list链表，参数内存回收扫描，结束保护期
		 *3:如果hot_file_stat->hot_file_area_free 和 hot_file_stat->hot_file_area_hot链表上也非空，说明上边也有file_area需要遍历，hot_file_area_hot链表上的冷file_area需要移动回hot_file_head_temp_list链表，hot_file_area_free链表上长时间没有被访问的file_area要释放掉file_area结构。
		 因此，hot_file_stat->hot_file_area_temp上有冷page，或者hot_file_stat->hot_file_area_refault、hot_file_area_free、hot_file_area_hot 链表只要非空，有file_area，都要把hot_file_stat结构添加到file_stat_free_list临时链表。然后free_page_from_file_area()中依次扫描这些hot_file_stat的hot_file_area_free_temp、hot_file_area_refault、hot_file_area_free、hot_file_area_hot链表上file_area，按照对应策略该干啥干啥
		 */
		//这个if会成立多次，导致同一个hot_file_stat被list_move到file_stat_free_list链表多次，这样就是导致"list_add corruption. next->prev should be prev"而crash的原因吧
		//并且，这里只有hot_file_stat->hot_file_area_temp链表有冷file_area才会执行到，如果这个链表没有冷file_area，但是hot_file_stat的hot_file_area_free_temp、
		//hot_file_area_refault、hot_file_area_free、hot_file_area_hot链表非空，就无法把hot_file_stat添加到file_stat_free_list链表了，导致后续无法遍历该file_stat。解决方法放到外边。
		if(cold_file_area_for_file_stat == 0 || !list_empty(&p_hot_file_stat->hot_file_area_refault) ||
			!list_empty(&p_hot_file_stat->hot_file_area_free) || !list_empty(&p_hot_file_stat->hot_file_area_hot)){
		    //是否会存在并发设置p_hot_file_stat->file_stat_status的情况??????????????? 这里没有加锁，需要考虑这点???????????????
		    //set_file_stat_in_head_temp_list(p_hot_file_stat);
		    //这里不用加锁，此时p_hot_file_stat是在 global_hot_file_head_temp_list临时链表，并且把p_hot_file_stat移动到
		    //global cold_file_head链表，只在walk_throuth_all_hot_file_area()函数单线程操作，不存在并发
		    //list_move(&p_hot_file_stat->hot_file_list,&p_hot_file_global->cold_file_head);

		    list_move(&p_hot_file_stat->hot_file_list,file_stat_free_list);
		    file_stat_count_in_cold_list ++;
		}
         #endif
		cold_file_area_for_file_stat ++;
	    }
	    //else if(p_hot_file_global->global_age == p_hot_file_area->file_area_age)
	    else //否则就停止遍历hot_file_stat->hot_file_area_temp链表上的file_area，因为该链表上的file_area从左向右，访问频率由大向小递增，这个需要实际测试?????????????????????????
	    {
		//如果hot_file_stat->hot_file_area_temp链表尾连续扫到3个file_area都是热的，才停止扫描该hot_file_stat上的file_area。因为此时hot_file_stat->hot_file_area_temp链表尾
		//上的file_area可能正在被访问，hot_file_area->file_area_age=hot_file_global->global_age，但是file_area还没被移动到hot_file_stat->hot_file_area_temp链表头。
		//这个判断是为了过滤掉这种瞬时的热file_area干扰
		if(serial_hot_file_area ++ > 2)
   		    break;
	    }
	}
	
	/*1:cold_file_area_for_file_stat != 0表示把有冷hot_file_area的hot_file_stat移动到file_stat_free_list临时链表.此时的file_sata已经不在hot_file_head_temp链表，不用clear_file_stat_in_hot_file_head_temp_list
         *2:如果hot_file_stat->hot_file_area_refault链表非空，说明也需要扫描这上边的file_area，要把上边冷的file_area移动回hot_file_head_temp_list链表，参数内存回收扫描，结束保护期
	  *3:如果hot_file_stat->hot_file_area_free 和 hot_file_stat->hot_file_area_hot链表上也非空，说明上边也有file_area需要遍历，hot_file_area_hot链表上的冷file_area需要移动回hot_file_head_temp_list链表，hot_file_area_free链表上长时间没有被访问的file_area要释放掉file_area结构。

          因此，hot_file_stat->hot_file_area_temp上有冷page，或者hot_file_stat->hot_file_area_refault、hot_file_area_free、hot_file_area_hot 链表只要非空，有file_area，
	  都要把hot_file_stat结构添加到file_stat_free_list临时链表。然后free_page_from_file_area()中依次扫描这些hot_file_stat的hot_file_area_free_temp、hot_file_area_refault、
	  hot_file_area_free、hot_file_area_hot链表上file_area，按照对应策略该干啥干啥。

	  这段代码是从上边的for循环移动过来的，放到这里是保证同一个file_stat只list_move到file_stat_free_list链表一次。并且，当file_stat->hot_file_area_temp链表没有冷file_area
	  或者没有一个file_area时，但是file_stat的hot_file_area_free_temp、hot_file_area_refault、hot_file_area_free、hot_file_area_hot链表上file_area要遍历，这样也要把
	  该file_stat移动到file_stat_free_list链表，这样将来free_page_from_file_area()函数中才能从file_stat_free_list链表扫描到该file_stat，否则会出现一些问题，比如
	  file_stat的hot_file_area_free链表上长时间没访问的file_stat无法遍历到，无法释放这些file_stat结构；还有 file_stat的hot_file_area_refault和hot_file_area_hot
	  链表上的冷file_area无法降级移动到file_stat->hot_file_area_temp链表，这些file_stat将无法扫描到参与内存回收
        */
	if(cold_file_area_for_file_stat != 0 || !list_empty(&p_hot_file_stat->hot_file_area_refault) ||
			!list_empty(&p_hot_file_stat->hot_file_area_free) || !list_empty(&p_hot_file_stat->hot_file_area_hot)){
	    list_move(&p_hot_file_stat->hot_file_list,file_stat_free_list);
            //移动到file_stat_free_list链表头的file_stat个数
            file_stat_count_in_cold_list ++;
	}
	/*
	//hot_file_area_free链表上长时间没访问的hot_file_area释放掉
	if(!list_empty(&p_hot_file_stat->hot_file_area_free)){
		//hot_file_area_free链表上长时间没访问的hot_file_area释放掉
		list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_free,hot_file_area_list){
		    if(p_hot_file_global->global_age - p_hot_file_area->file_area_age < GOLD_FILE_AREA_LEVAL -1){//hot_file_area又被访问了，添加回hot_file_area_temp链表
			spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
			list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
			set_file_area_in_temp_list(p_hot_file_area);
			spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);

			//p_hot_file_area->cold_time = 0;//冷却计数清0
		    }else{
			//hot_file_area冷的次数达到阀值则释放掉它
			//if(p_hot_file_area->cold_time > HOT_FILE_AREA_FREE_LEVEL)
			if(p_hot_file_global->global_age - p_hot_file_area->file_area_age > (GOLD_FILE_AREA_LEVAL + 6))
			    hot_file_area_detele(p_hot_file_global,p_hot_file_stat,p_hot_file_area);
		    }
		}
	    }
        */
	//累计遍历到的冷file_area个数
        scan_cold_file_area_count += cold_file_area_for_file_stat;

        //防止在for循环耗时太长，限制遍历的文件hot_file_stat数。这里两个问题 问题1:单个hot_file_stat上的hot_file_area太多了，只扫描一个hot_file_stat这里就
	//break跳出循环了。这样下边就把global_hot_file_head_temp_list残留的hot_file_stat移动到global hot_file_head_temp链表头了。下轮扫描从
	//global hot_file_head_temp尾就扫描不到该hot_file_stat了。合理的做法是，把这些压根没扫描的hot_file_stat再移动到global hot_file_head_temp尾。问题2：
	//还是 单个hot_file_stat上的hot_file_area太多了，没扫描完，下次再扫描该hot_file_stat时，直接从上次结束的hot_file_area位置处继续扫描，似乎更合理。
	//hot_file_stat断点hot_file_area继续扫描！但是实现起来似乎比较繁琐，算了
	if(scan_file_area_count > scan_file_area_max)
	    break;
    }
    //把global_hot_file_head_temp_list没遍历到的hot_file_stat移动到global hot_file_head_temp链表头。这样做就保证本轮从global hot_file_head_temp尾扫到的
    //hot_file_stat要么移动到了globa cold_file_head链表，要么移动到global hot_file_head_temp链表头。这样下轮从global hot_file_head_temp尾扫到的hot_file_stat之前没扫描过。
    //错了！上边扫描的global hot_file_head_temp链表尾的hot_file_stat肯定有冷hot_file_area。因为hot_file_stat只要50%的hot_file_area是热的，hot_file_stat就要移动到
    //global hot_file_head 链表。global hot_file_head_temp链表上的hot_file_stat肯定有hot_file_area。这里还残留在global_hot_file_head_temp_list上的hot_file_stat,
    //本轮就没有扫描到，因此要移动到global hot_file_head_temp链表尾，下轮扫描继续扫描这些hot_file_stat
    if(!list_empty(&global_hot_file_head_temp_list)){

        spin_lock_irq(&p_hot_file_global->hot_file_lock);
	//设置file_stat状态要加锁
	list_for_each_entry(p_hot_file_stat,&global_hot_file_head_temp_list,hot_file_list)
	    set_file_stat_in_hot_file_head_temp_list(p_hot_file_stat);//设置hot_file_stat状态为head_temp_list 
	//set_file_stat_in_head_temp_list(p_hot_file_stat);//不用再设置这些hot_file_stat的状态，这些hot_file_stat没有移动到global hot_file_area_cold链表，没改变状态
        //list_splice(&global_hot_file_head_temp_list,&p_hot_file_global->hot_file_head_temp);//移动到global hot_file_head_temp链表头
        //list_splice_tail(&global_hot_file_head_temp_list,&p_hot_file_global->hot_file_head_temp);//移动到 global hot_file_head_temp链表尾
	
	//把未遍历的file_stat再移动回hot_file_global->hot_file_head_temp或hot_file_global->hot_file_head_temp_large 链表尾巴
        list_splice_tail(&global_hot_file_head_temp_list,hot_file_head_temp);//移动到 global hot_file_head_temp 或 hot_file_head_temp_large 链表尾
	
	//list_splice把前者的链表成员a1...an移动到后者链表，并不会清空前者链表。必须INIT_LIST_HEAD清空前者链表，否则它一直指向之前的链表成员a1...an。后续再向该链表添加新成员
	//b1...bn。这个链表就指向的成员就有a1...an + b1...+bn。而此时a1...an已经移动到了后者链表，相当于前者和后者链表都指向了a1...an成员，这样肯定会出问题.
	//之前get_file_area_from_file_stat_list()函数报错"list_add corruption. next->prev should be prev"而crash估计就是这个原因!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	//INIT_LIST_HEAD(&p_hot_file_stat->hot_file_area_free_temp)//global_hot_file_head_temp_list是局部链表，不用清，只有全局变量才必须list_splice_tail后清空链表

        spin_unlock_irq(&p_hot_file_global->hot_file_lock);
    }

    if(open_shrink_printk)
        printk("3:%s %s %d p_hot_file_global:0x%llx scan_file_stat_count:%d scan_file_area_count:%d scan_cold_file_area_count:%d file_stat_count_in_cold_list:%d\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,scan_file_stat_count,scan_file_area_count,scan_cold_file_area_count,file_stat_count_in_cold_list);

    return scan_cold_file_area_count;
}
/*该函数主要有3个作用
 * 1：释放file_stat_free_list链表上的file_stat的hot_file_area_free_temp链表上冷file_area的page。释放这些page后，把这些file_area移动到file_stat->hot_file_area_free链表头
 * 2：遍历file_stat_free_list链表上的file_stat的hot_file_area_hot链表尾上的热file_area，如果长时间没有被访问，说明变成冷file_area了，则移动到file_stat->hot_file_area_temp链表头
 * 3：遍历file_stat_free_list链表上的file_stat的hot_file_area_free链表尾上的file_area，如果还是长时间没有被访问，则释放掉这些file_area结构
 * 4: 遍历file_stat_free_list链表上的file_stat的hot_file_area_refault链表尾巴的file_area，如果长时间没有被访问，则移动到file_stat->hot_file_area_temp链表头
 * 5: 把file_stat_free_list链表上的file_stat再移动回hot_file_head_temp链表(即global hot_file_head_temp或hot_file_head_temp_large)头，这样下轮walk_throuth_all_hot_file_area()
 * 再扫描，从global hot_file_head_temp或hot_file_head_temp_large链表尾巴扫到的file_stat都是最近没有被扫描过的，避免重复扫描
 */
//file_stat_free_list链表上的file_stat来自本轮扫描从global hot_file_head_temp或hot_file_head_temp_large链表尾获取到的
//hot_file_head_temp是global hot_file_head_temp或hot_file_head_temp_large
unsigned long free_page_from_file_area(struct hot_file_global *p_hot_file_global,struct list_head * file_stat_free_list,struct list_head *hot_file_head_temp)
{
    unsigned int free_pages = 0;
    struct hot_file_stat * p_hot_file_stat/*,*p_hot_file_stat_temp*/;
    struct hot_file_area *p_hot_file_area,*p_hot_file_area_temp;
    unsigned int cold_file_area_count;
    unsigned int hot_file_area_count;
    unsigned int isolate_lru_pages = 0;
    unsigned int file_area_refault_to_temp_list_count = 0;
    unsigned int file_area_free_count = 0;
    unsigned int file_area_hot_to_temp_list_count = 0;

    /*同一个文件file_stat的file_area对应的page，更大可能是属于同一个内存节点node，所以要基于一个个文件的file_stat来扫描file_area，避免频繁开关内存节点锁pgdat->lru_lock锁*/  

    //遍历file_stat_free_list临时链表上的hot_file_stat，释放这些file_stat的hot_file_stat->hot_file_area_free_temp链表上的冷file_area的page
    list_for_each_entry(p_hot_file_stat,file_stat_free_list,hot_file_list)
    {
	if(file_stat_in_hot_file_head_temp_list(p_hot_file_stat) || file_stat_in_hot_file_head_list(p_hot_file_stat))
	    panic("%s file_stat:0x%llx in int hot_file_head_temp or hot_file_head_list status:0x%x\n",__func__,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);

        //对hot_file_area_free_temp上的hot_file_stat上的hot_file_area对应的page进行隔离，隔离成功的移动到p_hot_file_global->hot_file_node_pgdat->pgdat_page_list对应内存节点链表上
        isolate_lru_pages += hot_file_isolate_lru_pages(p_hot_file_global,p_hot_file_stat,&p_hot_file_stat->hot_file_area_free_temp);
	//这里真正释放p_hot_file_global->hot_file_node_pgdat->pgdat_page_list链表上的内存page
	free_pages += hot_file_shrink_pages(p_hot_file_global);
	
	if(open_shrink_printk)
	    printk("1:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x free_pages:%d\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,free_pages);
   
        /*注意，hot_file_stat->hot_file_area_free_temp 和 hot_file_stat->hot_file_area_free 各有用处。hot_file_area_free_temp保存每次扫描释放的page的hot_file_area。
	  释放后把这些hot_file_area移动到hot_file_area_free链表，hot_file_area_free保存的是每轮扫描释放page的所有hot_file_area，是所有的!!!!!!!!!!!!!!*/

	//p_hot_file_stat->hot_file_area_free_temp上的file_area的冷内存page释放过后,则把hot_file_area_free_temp链表上的hot_file_area结构再移动到hot_file_area_free链表头，
	//hot_file_area_free链表上的hot_file_area结构要长时间也没被访问就释放掉
        if(!list_empty(&p_hot_file_stat->hot_file_area_free_temp)){
	    //hot_file_update_file_status()函数中会并发把file_area从hot_file_stat->hot_file_area_free_temp链表移动到hot_file_stat->hot_file_area_free_temp链表.
	    //这里把hot_file_stat->hot_file_area_free_temp链表上的file_area移动到hot_file_stat->hot_file_area_free，需要加锁
	    spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);

            list_splice(&p_hot_file_stat->hot_file_area_free_temp,&p_hot_file_stat->hot_file_area_free);
	    //list_splice把前者的链表成员a1...an移动到后者链表，并不会清空前者链表。必须INIT_LIST_HEAD清空前者链表，否则它一直指向之前的链表成员a1...an。后续再向该链表添加新成员
	    //b1...bn。这个链表就指向的成员就有a1...an + b1...+bn。而此时a1...an已经移动到了后者链表，相当于前者和后者链表都指向了a1...an成员，这样肯定会出问题.
	    //之前get_file_area_from_file_stat_list()函数报错"list_add corruption. next->prev should be prev"而crash估计就是这个原因!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	    INIT_LIST_HEAD(&p_hot_file_stat->hot_file_area_free_temp);

	    spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
        }
    }
    //需要调度的话休眠一下
    cond_resched();
    
    /*这里有个隐藏很深但很重要的问题：在walk_throuth_all_hot_file_area()内存回收过程执行到该函数，把file_area移动到了hot_file_stat->hot_file_area_free_temp
     *或者hot_file_stat->hot_file_area_free链表后，此时hot_file_update_file_status()函数中又访问到这些file_area了，怎么办？这种情况完全有可能！
     *为了减少spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock)锁的使用。目前设定只有file_area在file_stat的hot_file_area_hot、hot_file_area_temp、hot_file_area_temp_large
     *这3个有关的链表之间移动来移动去时，才会使用spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock)。file_area从hot_file_stat->hot_file_area_free_temp移动到
     *hot_file_stat->hot_file_area_free链表上是没有解锁的！
     
     *如果file_area移动到了hot_file_stat->hot_file_area_free_temp或者hot_file_stat->hot_file_area_free链表后，此时hot_file_update_file_status()函数中又访问到这些file_area了，
     *如果直接hot_file_update_file_status()函数中把这些file_area直接移动到file_stat的hot_file_area_temp链表，那就又得spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock)
     *加锁了，并且file_area从hot_file_stat->hot_file_area_free_temp移动到hot_file_stat->hot_file_area_free链表也得hot_file_stat_lock加锁。可以这样吗??????????
     *最后妥协了，就这样改吧。但是允许 hot_file_update_file_status()函数把file_area从hot_file_stat->hot_file_area_free_temp或hot_file_area_free链表移动到
     *file_stat的hot_file_area_temp链表后。hot_file_update_file_status()函数移动时需要spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock)加锁，
     *该函数中把file_area从hot_file_stat->hot_file_area_free_temp移动到hot_file_stat->hot_file_area_free，也需要hot_file_stat_lock加锁；并且，从hot_file_stat->hot_file_area_free
     *释放长时间没有被访问的file_area时，也需要hot_file_stat_lock加锁!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
     */

    //遍历file_stat_free_list临时链表上的hot_file_stat，然后遍历着这些hot_file_stat->hot_file_area_hot链表尾巴上热file_area。这些file_area之前被判定是热file_area
    //而被移动到了hot_file_stat->hot_file_area_hot链表。之后，hot_file_stat->hot_file_area_hot链表头的file_area访问频繁，链表尾巴的file_area就会变冷。则把这些
    //hot_file_stat->hot_file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->hot_file_area_temp链表头
    list_for_each_entry(p_hot_file_stat,file_stat_free_list,hot_file_list){
        cold_file_area_count = 0;
        list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_hot,hot_file_area_list){
	    if(!file_area_in_hot_list(p_hot_file_area))
		panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_hot\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

	    //hot_file_stat->hot_file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->hot_file_area_temp链表头
            if(p_hot_file_global->global_age - p_hot_file_area->file_area_age > GOLD_FILE_AREA_LEVAL + 3){
		cold_file_area_count = 0;
	        //if(open_shrink_printk)
	        //    printk("2:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x in file_stat->hot_file_area_hot\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

		file_area_hot_to_temp_list_count ++;
                //每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
	        spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
		clear_file_area_in_hot_list(p_hot_file_area);
		//file_stat的热file_area个数减1
		p_hot_file_stat->file_area_hot_count --;
		set_file_area_in_temp_list(p_hot_file_area);
	        list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
                spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);	    
	    }else{//到这里，file_area被判定还是热file_area，还是继续存在hot_file_stat->hot_file_area_hot链表

	//如果hot_file_stat->hot_file_area_hot尾巴上连续出现2个file_area还是热file_area，则说明hot_file_stat->hot_file_area_hot链表尾巴上的冷file_area都遍历完了,遇到链表头的热
	//file_area了，则停止遍历。hot_file_stat->hot_file_area_hot链表头到链表尾，file_area是由热到冷顺序排布的。之所以要限制连续碰到两个热file_area再break，是因为hot_file_stat->
	//hot_file_area_hot尾巴上的冷file_area可能此时hot_file_update_file_status()中并发被频繁访问，变成热file_area，但还没来得及移动到hot_file_stat->hot_file_area_hot链表头
	        if(cold_file_area_count ++ > 1)
		    break;
	    }
	}
    }
     
    //需要调度的话休眠一下
    cond_resched();
   
    //遍历file_stat_free_list临时链表上的file_stat，然后看这些file_stat的hot_file_area_free链表上的哪些file_area长时间未被访问，抓到的话就释放掉file_area结构
    //如果hot_file_stat->hot_file_area_free链表上有很多file_area导致这里遍历时间很长怎么办？需要考虑一下??????????????????????????
    list_for_each_entry(p_hot_file_stat,file_stat_free_list,hot_file_list){
	hot_file_area_count = 0;
	list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_free,hot_file_area_list){
        #if 0
            //如果hot_file_stat->hot_file_area_free链表上的file_area最近又被访问了，hot_file_update_file_status()函数会把该file_area移动回
	    //global hot_file_head_temp或hot_file_head_temp_large链表，这里就不用再重复操作了

	    //hot_file_area又被访问了，添加回hot_file_area_temp链表
	    if(p_hot_file_global->global_age - p_hot_file_area->file_area_age < GOLD_FILE_AREA_LEVAL -1){
		
		//每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表?????????
		spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
		list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
		clear_file_area_in_free_list(p_hot_file_area);
		set_file_area_in_temp_list(p_hot_file_area);
		spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
                //如果hot_file_stat->hot_file_area_free链表尾连续出现3个file_area最近被访问过，则结束遍历该hot_file_stat->hot_file_area_free上的file_area
		if(hot_file_area_count ++ > 2)
		    break;
	    }else{
		hot_file_area_count = 0;
		//hot_file_area_free链表上长时间没访问的hot_file_area释放掉
		if(p_hot_file_global->global_age - p_hot_file_area->file_area_age > (GOLD_FILE_AREA_LEVAL + 3))
		    hot_file_area_detele(p_hot_file_global,p_hot_file_stat,p_hot_file_area);
	    }
        #else
	    //由于这个过程没有spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock)加锁，hot_file_area可能正在被访问，清理的file_area_in_free_list标记，并设置了file_area_in_hot_list或
	    //file_area_in_temp_list标记，但是file_area还没移动到file_stat的hot_file_area_temp或hot_file_area_hot链表。此时if(!file_area_in_free_list(p_hot_file_area))成立，但这是正常现象。
	    if(!file_area_in_free_list(p_hot_file_area)){
		printk("%s hot_file_area:0x%llx status:0x%x not in hot_file_area_free !!!!!!!!!!!!\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);
		continue;
            }
	    //如果hot_file_stat->hot_file_area_free链表上的file_area长时间没有被访问则释放掉file_area结构
            if(p_hot_file_global->global_age - p_hot_file_area->file_area_age > GOLD_FILE_AREA_LEVAL + 5){
                file_area_free_count ++;
	        //if(open_shrink_printk)
	        //    printk("3:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x in hot_file_stat->hot_file_area_free\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);
		hot_file_area_count = 0;
	        //hot_file_update_file_status()函数中会并发把file_area从hot_file_stat->hot_file_area_free链表移动到hot_file_stat->hot_file_area_free_temp链表.
	        //这里把hot_file_stat->hot_file_area_free链表上的file_area剔除掉并释放掉，需要spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock)加锁，这个函数里有加锁
	        hot_file_area_detele(p_hot_file_global,p_hot_file_stat,p_hot_file_area);
	    }else{
		//如果hot_file_stat->hot_file_area_free链表尾连续出现3个file_area未达到释放标准,说明可能最近被访问过，则结束遍历该hot_file_stat->hot_file_area_free上的file_area
		//这是防止遍历耗时太长，并且遍历到本轮扫描添加到hot_file_stat->hot_file_area_free上的file_area，浪费
	        if(hot_file_area_count ++ > 2)
		    break;
	    }
	#endif
	}
    }

    //遍历 file_stat_free_list临时链表上的file_stat，然后看这些file_stat的hot_file_area_refault链表上的file_area，如果长时间没有被访问，
    //则要移动到hot_file_stat->hot_file_area_temp链表
    list_for_each_entry(p_hot_file_stat,file_stat_free_list,hot_file_list){
	hot_file_area_count = 0;
        list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_refault,hot_file_area_list){
	    if(!file_area_in_refault_list(p_hot_file_area))
		panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_refault\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

	    //hot_file_stat->hot_file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->hot_file_area_temp链表头
            if(p_hot_file_global->global_age - p_hot_file_area->file_area_age > GOLD_FILE_AREA_LEVAL + 3){
		file_area_refault_to_temp_list_count ++;
	        //if(open_shrink_printk)
	        //    printk("4:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x in file_stat->hot_file_area_refault\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

		hot_file_area_count = 0;
                //每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
	        spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
		clear_file_area_in_refault_list(p_hot_file_area);
		set_file_area_in_temp_list(p_hot_file_area);
		/*if(file_stat_in_large_file(p_hot_file_stat))
                    list_move(&p_hot_file_stat->hot_file_list,&p_hot_file_global->hot_file_head_temp_large);
		else
                    list_move(&p_hot_file_stat->hot_file_list,&p_hot_file_global->hot_file_head_temp);*/
		list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
                spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);	    
	    }else{
	//如果hot_file_stat->hot_file_area_refault尾巴上连续出现2个file_area还是热file_area，则说明hot_file_stat->hot_file_area_hot链表尾巴上的冷file_area都遍历完了,遇到链表头的热
	//file_area了，则停止遍历。hot_file_stat->hot_file_area_refault链表头到链表尾，file_area是由热到冷顺序排布的。之所以要限制连续碰到两个热file_area再break，是因为hot_file_stat->
	//hot_file_area_refault尾巴上的冷file_area可能此时hot_file_update_file_status()中并发被频繁访问，变成热file_area，但还没来得及移动到hot_file_area_refault链表头
	        if(hot_file_area_count ++ >2)
		    break;
	    }
	}
    }
   
    /*-------这是遍历全局hot_file_global->hot_file_head上的file_stat，不遍历file_stat_free_list上的file_stat，不应该放在这里
    //遍历hot_file_global->hot_file_head链表上的热文件file_stat，如果哪些file_stat不再是热文件，再要把file_stat移动回global->hot_file_head_temp或hot_file_head_temp_large链表
    list_for_each_entry(p_hot_file_stat,p_hot_file_global->hot_file_head,hot_file_list){
	    //file_stat不再是热文件则移动回hot_file_global->hot_file_head_temp 或 hot_file_global->hot_file_head_temp_large链表
	    if(!is_file_stat_hot_file(p_hot_file_global,p_hot_file_stat)){
	        clear_file_area_in_hot_list(p_hot_file_stat);
	        set_file_stat_in_hot_file_head_temp_list(p_hot_file_stat);//设置hot_file_stat状态为in_head_temp_list
		if(file_stat_in_large_file(p_hot_file_stat))
                    list_move(&p_hot_file_stat->hot_file_list,p_hot_file_global->hot_file_head_temp);
		else
                    list_move(&p_hot_file_stat->hot_file_list,p_hot_file_global->hot_file_head_temp_large);
	    }
        }
    }*/

    //需要调度的话休眠一下
    cond_resched();

    //把file_stat_free_list临时链表上释放过内存page的file_stat再移动回global hot_file_head_temp或hot_file_head_temp_large链表头
    if(!list_empty(file_stat_free_list)){
        spin_lock_irq(&p_hot_file_global->hot_file_lock);
        list_for_each_entry(p_hot_file_stat,file_stat_free_list,hot_file_list){
            set_file_stat_in_hot_file_head_temp_list(p_hot_file_stat);//设置hot_file_stat状态为in_head_temp_list
        }
	//把这些遍历过的hot_file_stat移动回global hot_file_head_temp或hot_file_head_temp_large链表头,注意是链表头。这是因为，把这些遍历过的file_stat移动到 
	//global hot_file_head_temp或hot_file_head_temp_large链表头，下轮扫描才能从global hot_file_head_temp或hot_file_head_temp_large链表尾遍历没有遍历过的的file_stat
        list_splice(file_stat_free_list,hot_file_head_temp);//hot_file_head_temp来自 global hot_file_head_temp或hot_file_head_temp_large链表
	
	//list_splice把前者的链表成员a1...an移动到后者链表，并不会清空前者链表。必须INIT_LIST_HEAD清空前者链表，否则它一直指向之前的链表成员a1...an。后续再向该链表添加新成员
	//b1...bn。这个链表就指向的成员就有a1...an + b1...+bn。而此时a1...an已经移动到了后者链表，相当于前者和后者链表都指向了a1...an成员，这样肯定会出问题.
	//之前get_file_area_from_file_stat_list()函数报错"list_add corruption. next->prev should be prev"而crash估计就是这个原因!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	INIT_LIST_HEAD(file_stat_free_list);
	spin_unlock_irq(&p_hot_file_global->hot_file_lock);
    }
    
    if(open_shrink_printk)
    	printk("5:%s %s %d p_hot_file_global:0x%llx free_pages:%d isolate_lru_pages:%d hot_file_head_temp:0x%llx file_area_free_count:%d file_area_refault_to_list_temp_count:%d file_area_hot_to_temp_list_count:%d\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,free_pages,isolate_lru_pages,(u64)hot_file_head_temp,file_area_free_count,file_area_refault_to_temp_list_count,file_area_hot_to_temp_list_count);
    return free_pages;
}
int walk_throuth_all_hot_file_area(struct hot_file_global *p_hot_file_global)
{
    struct hot_file_stat * p_hot_file_stat,*p_hot_file_stat_temp;
    struct hot_file_area *p_hot_file_area,*p_hot_file_area_temp;
    //LIST_HEAD(hot_file_area_list);
    LIST_HEAD(file_stat_free_list_from_head_temp);
    LIST_HEAD(file_stat_free_list_from_head_temp_large);
    unsigned int scan_file_area_max,scan_file_stat_max;
    unsigned int scan_cold_file_area_count = 0;
    unsigned long nr_reclaimed = 0;
    unsigned int cold_file_area_count;
    unsigned int file_area_hot_to_temp_list_count = 0;
    unsigned int del_file_stat_count = 0,del_file_area_count = 0;
    //每个周期global_age加1
    hot_file_global_info.global_age ++;

    scan_file_stat_max = 10;
    scan_file_area_max = 1024;
    //遍历hot_file_global->hot_file_head_temp_large链表尾巴上边的大文件file_stat，然后遍历这些大文件file_stat的hot_file_stat->hot_file_area_temp链表尾巴上的file_area，被判定是冷的
    //file_area则移动到hot_file_stat->hot_file_area_free_temp链表。把有冷file_area的file_stat移动到file_stat_free_list_from_head_temp_large临时链表。返回值是遍历到的冷file_area个数
    scan_cold_file_area_count += get_file_area_from_file_stat_list(p_hot_file_global,scan_file_area_max,scan_file_stat_max, 
	                               &p_hot_file_global->hot_file_head_temp_large,&file_stat_free_list_from_head_temp_large);
    //需要调度的话休眠一下
    cond_resched();
    scan_file_stat_max = 64;
    scan_file_area_max = 1024;
    //遍历hot_file_global->hot_file_head_temp链表尾巴上边的小文件file_stat，然后遍历这些小文件file_stat的hot_file_stat->hot_file_area_temp链表尾巴上的file_area，被判定是冷的
    //file_area则移动到hot_file_stat->hot_file_area_free_temp链表。把有冷file_area的file_stat移动到file_stat_free_list_from_head_temp临时链表。返回值是遍历到的冷file_area个数
    scan_cold_file_area_count += get_file_area_from_file_stat_list(p_hot_file_global,scan_file_area_max,scan_file_stat_max, 
	                               &p_hot_file_global->hot_file_head_temp,&file_stat_free_list_from_head_temp);
#if 0 
    scan_cold_file_stat_count = 0;
    list_for_each_entry_safe_reverse(p_hot_file_stat,p_hot_file_stat_temp,&p_hot_file_global->cold_file_head,hot_file_list)
    {
	/*//该if成立，说明上一轮扫描移动到global cold_file_head链表头的p_hot_file_stat->file_stat_count_in_cold_list个hot_file_stat已经遍历完了，不能继续向前
	//扫描hot_file_stat了，因为再向前的hot_file_stat是本轮扫描移动到global cold_file_head链表的。这个if判断要放到for循环开头,因为第一次执行到这里，
	//scan_cold_file_stat_count和p_hot_file_stat->file_stat_count_in_cold_list都是0-------------不行，这样就无法执行里边的for循环代码:
	//if(free_hot_file_area_count == p_hot_file_area->old_file_area_count_in_cold_list)里的
	//p_hot_file_area->old_file_area_count_in_cold_list = p_hot_file_area->file_area_count_in_cold_list;这个赋值了!!!!!!!!!!。给要移动到后边
        if(scan_cold_file_stat_count == p_hot_file_stat->file_stat_count_in_cold_list){
	    //把本轮扫描移动到global cold_file_head链表的file_stat个数保存到p_hot_file_stat->file_stat_count_in_cold_list
            p_hot_file_global->file_stat_count_in_cold_list = file_stat_count_in_cold_list;
	    break;
	}*/

        if(!file_stat_in_hot_file_head_temp(p_hot_file_stat))
	    panic("p_hot_file_stat:0x%llx status:%d not in free_temp_list\n",(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);

	scan_cold_file_area_count = 0;
        list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_cold,hot_file_area_list)
	{
	    //该if成立，说明上一轮扫描该p_hot_file_area被判定是冷hot_file_area而移动到p_hot_file_stat->hot_file_area_cold链表的p_hot_file_area->old_file_area_count_in_cold_list
	    //个hot_file_area已经都扫描完了，不能再向前扫描了，因为再向前的hot_file_area是本轮扫描移动到p_hot_file_stat->hot_file_area_cold链表的。这if判断要放到for循环最开头，因为
	    //第一次扫描时scan_cold_file_area_count是0，p_hot_file_area->old_file_area_count_in_cold_list也是0
            if(scan_cold_file_area_count == p_hot_file_stat->old_file_area_count_in_cold_list){
		p_hot_file_stat->old_file_area_count_in_cold_list = p_hot_file_stat->file_area_count_in_cold_list;
	        break;
	    }
	    //scan_cold_file_area_count++要放到if判断后边，因为第一次扫描执行到if判断，free_hot_file_area_count 和 p_hot_file_area->old_file_area_count_in_cold_list 都是0，得break跳出
	    scan_cold_file_area_count++;

	    if(!file_area_in_temp_list(p_hot_file_area))
	        panic("file_area_in_temp_list:0x%llx status:%d not in hot_file_area_temp\n",(u64)p_hot_file_area,p_hot_file_area->file_area_state);

	    //file_area 依然没有被访问，就释放 hot_file_stat 对应的page了
	    if(p_hot_file_area->area_access_count == p_hot_file_area->last_access_count){
                list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_free_temp);
	    }
	    //file_area 又被访问了，则把hot_file_area添加到hot_file_area_temp临时链表
	    else{
		//需要加锁，hot_file_update_file_status()函数中会并发向该文件p_hot_file_stat->hot_file_area_temp添加新的hot_file_area结构
	        spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
                list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
		set_file_area_in_temp_list(p_hot_file_area);
		//有没有必要用area_access_count重置last_access_count，重置的话，后续该file_area不再被访问就又要把从hot_file_area_temp移动到hot_file_area_cold链表
		//p_hot_file_area->last_access_count = p_hot_file_area->area_access_count;??????????????????????????????
	        spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);
	    }
        }
	//if成立，说明当前p_hot_file_stat，有冷hot_file_area添加到了p_hot_file_stat->hot_file_area_free链表
	if(0 != scan_cold_file_area_count){
            //把有冷hot_file_area的文件的hot_file_stat移动到hot_file_stat_free_list链表
	    //这里用不用把hot_file_stat->file_stat_status设置成无效，因为不在hot_file_global的任何链表了?????????????????????????????????????
            list_move(&p_hot_file_stat->hot_file_list,&hot_file_stat_free_list);
	}
	//该if成立，说明上一轮扫描移动到global cold_file_head链表头的p_hot_file_stat->file_stat_count_in_cold_list个hot_file_stat已经遍历完了，不能继续向前
	//扫描hot_file_stat了，因为再向前的hot_file_stat是本轮扫描移动到global cold_file_head链表的hot_file_stat
        if(scan_cold_file_stat_count == p_hot_file_global->file_stat_count_in_cold_list){
	    //把本轮扫描移动到global cold_file_head链表的file_stat个数保存到p_hot_file_stat->file_stat_count_in_cold_list
            p_hot_file_global->file_stat_count_in_cold_list = file_stat_count_in_cold_list;
	    break;
	}
	//scan_cold_file_stat_count++要放到if判断后边，因为第1轮扫描时，没有要扫描的hot_file_stat，scan_cold_file_stat_count和p_hot_file_stat->file_stat_count_in_cold_list都是0
	//上边直接break条春大的ffor循环
        scan_cold_file_stat_count ++;
    }
#endif  
    /*该函数主要有5个作用
 * 1：释放file_stat_free_list_from_head_temp_large链表上的file_stat的hot_file_area_free_temp链表上冷file_area的page。释放这些page后，把这些file_area移动到file_stat->hot_file_area_free链表头
 * 2：遍历file_stat_free_list_from_head_temp_large的hot_file_area_hot链表尾上的热file_area，如果长时间没有被访问，说明变成冷file_area了，则移动到file_stat->hot_file_area_temp链表头
 * 3：遍历file_stat_free_list_from_head_temp_large链表上的file_stat的hot_file_area_free链表尾上的file_area，如果还是长时间没有被访问，则释放掉这些file_area结构
 * 4: 遍历file_stat_free_list_from_head_temp_large链表上的file_stat的hot_file_area_refault链表尾巴的file_area，如果长时间没有被访问，则移动到file_stat->hot_file_area_temp链表头
 * 5: 把file_stat_free_list_from_head_temp_large链表上的file_stat再移动回hot_file_head_temp链表(即global hot_file_head_temp或hot_file_head_temp_large)头，这样下轮walk_throuth_all_hot_file_area()再扫描，从global hot_file_head_temp或hot_file_head_temp_large链表尾巴扫到的file_stat都是最近没有被扫描过的，避免重复扫描
 */
    nr_reclaimed =  free_page_from_file_area(p_hot_file_global,&file_stat_free_list_from_head_temp_large,&p_hot_file_global->hot_file_head_temp_large); 
    nr_reclaimed += free_page_from_file_area(p_hot_file_global,&file_stat_free_list_from_head_temp,&p_hot_file_global->hot_file_head_temp); 

    //遍历hot_file_global->hot_file_head链表上的热文件file_stat，如果哪些file_stat不再是热文件，再要把file_stat移动回global->hot_file_head_temp或hot_file_head_temp_large链表
    list_for_each_entry_safe_reverse(p_hot_file_stat,p_hot_file_stat_temp,&p_hot_file_global->hot_file_head,hot_file_list){
	if(!file_stat_in_hot_file_head_list(p_hot_file_stat))
	    panic("%s file_stat:0x%llx not int hot_file_head_list status:0x%x\n",__func__,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);
    
	cold_file_area_count = 0;
	//遍历global->hot_file_head上的热文件file_stat的hot_file_area_hot链表上的热file_area，如果哪些file_area不再被访问了，则要把file_area移动回file_stat->hot_file_area_temp链表。
	//同时令改文件的热file_area个数file_stat->file_area_hot_count减1
        list_for_each_entry_safe_reverse(p_hot_file_area,p_hot_file_area_temp,&p_hot_file_stat->hot_file_area_hot,hot_file_area_list){
	    //hot_file_stat->hot_file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->hot_file_area_temp链表头
            if(p_hot_file_global->global_age - p_hot_file_area->file_area_age > GOLD_FILE_AREA_LEVAL + 3){
		cold_file_area_count = 0;
	        if(!file_area_in_hot_list(p_hot_file_area))
		    panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_hot\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);
	        //if(open_shrink_printk)
	        //    printk("2:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x in file_stat->hot_file_area_hot\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

		file_area_hot_to_temp_list_count ++;
                //每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
	        spin_lock_irq(&p_hot_file_stat->hot_file_stat_lock);
		p_hot_file_stat->file_area_hot_count --;
		clear_file_area_in_hot_list(p_hot_file_area);
		set_file_area_in_temp_list(p_hot_file_area);
	        list_move(&p_hot_file_area->hot_file_area_list,&p_hot_file_stat->hot_file_area_temp);
                spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);	    
	    }else{//到这里，file_area被判定还是热file_area，还是继续存在hot_file_stat->hot_file_area_hot链表

	//如果hot_file_stat->hot_file_area_hot尾巴上连续出现2个file_area还是热file_area，则说明hot_file_stat->hot_file_area_hot链表尾巴上的冷file_area都遍历完了,遇到链表头的热
	//file_area了，则停止遍历。hot_file_stat->hot_file_area_hot链表头到链表尾，file_area是由热到冷顺序排布的。之所以要限制连续碰到两个热file_area再break，是因为hot_file_stat->
	//hot_file_area_hot尾巴上的冷file_area可能此时hot_file_update_file_status()中并发被频繁访问，变成热file_area，但还没来得及移动到hot_file_stat->hot_file_area_hot链表头
	        if(cold_file_area_count ++ > 1)
		    break;
	    }
	}
	if(open_shrink_printk)
	    printk("2:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x file_area_hot_count:%d file_area_count:%d file_area_hot_to_temp_list_count:%d\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,p_hot_file_stat->file_area_hot_count,p_hot_file_stat->file_area_count,file_area_hot_to_temp_list_count);

	//该文件file_stat的热file_area个数file_stat->file_area_hot_count小于阀值，则被判定不再是热文件
	//然后file_stat就要移动回hot_file_global->hot_file_head_temp 或 hot_file_global->hot_file_head_temp_large链表
	if(!is_file_stat_hot_file(p_hot_file_global,p_hot_file_stat)){

            spin_lock_irq(&p_hot_file_global->hot_file_lock);
	    clear_file_stat_in_hot_file_head_list(p_hot_file_stat);
	    set_file_stat_in_hot_file_head_temp_list(p_hot_file_stat);//设置hot_file_stat状态为in_head_temp_list
	    if(file_stat_in_large_file(p_hot_file_stat))
		list_move(&p_hot_file_stat->hot_file_list,&p_hot_file_global->hot_file_head_temp_large);
	    else
		list_move(&p_hot_file_stat->hot_file_list,&p_hot_file_global->hot_file_head_temp);
            spin_unlock_irq(&p_hot_file_global->hot_file_lock);
	}
    }

    //遍历global hot_file_head_delete链表上已经被删除的文件的file_stat，
    //一次不能删除太多的hot_file_stat对应的file_area，会长时间占有cpu，后期需要调优一下
    list_for_each_entry_safe_reverse(p_hot_file_stat,p_hot_file_stat_temp,&p_hot_file_global->hot_file_head_delete,hot_file_list){
	if(!file_stat_in_delete(p_hot_file_stat))
	    panic("%s file_stat:0x%llx not delete status:0x%x\n",__func__,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status);

        del_file_area_count += hot_file_tree_delete_all(p_hot_file_global,p_hot_file_stat);
	del_file_stat_count ++;
    }
    printk(">>>>>global_age:%ld file_stat_count:%ld free_pages:%ld del_file_area_count:%d del_file_stat_count:%d scan_cold_file_area_count:%d<<<<<<\n",p_hot_file_global->global_age,p_hot_file_global->file_stat_count,nr_reclaimed,del_file_area_count,del_file_stat_count,scan_cold_file_area_count);
    return 0;
}
#endif


static int hot_file_thread(void *p){
    struct hot_file_global *p_hot_file_global = (struct hot_file_global *)p;
    int sleep_count = 0;

    while(1){
	sleep_count = 0;
        while(!hot_file_shrink_enable || sleep_count ++ < 10)
            msleep(1000);

	walk_throuth_all_hot_file_area(p_hot_file_global);
	if (kthread_should_stop())
	    break;
    }
    return 0;
}

int hot_file_init(void)
{
    int node_count,i,ret;
    //hot_file_global_info.hot_file_stat_cachep = KMEM_CACHE(hot_file_stat,0);
    hot_file_global_info.hot_file_stat_cachep = kmem_cache_create("hot_file_stat",sizeof(struct hot_file_stat),0,0,NULL);
    hot_file_global_info.hot_file_area_cachep = kmem_cache_create("hot_file_area",sizeof(struct hot_file_area),0,0,NULL);
    hot_file_global_info.hot_file_area_tree_node_cachep = kmem_cache_create("hot_file_area_tree_node",sizeof(struct hot_file_area_tree_node),0,0,NULL);

    INIT_LIST_HEAD(&hot_file_global_info.hot_file_head);
    INIT_LIST_HEAD(&hot_file_global_info.hot_file_head_temp);
    INIT_LIST_HEAD(&hot_file_global_info.hot_file_head_temp_large);

    INIT_LIST_HEAD(&hot_file_global_info.cold_file_head);
    INIT_LIST_HEAD(&hot_file_global_info.hot_file_head_delete);
    spin_lock_init(&hot_file_global_info.hot_file_lock);

    //1G的page cache对应多少个file_area
    hot_file_global_info.file_area_count_for_large_file = (1024*1024*1024)/(4096 *PAGE_COUNT_IN_AREA);
    node_count = 0;
    for_each_node_state(i, N_MEMORY)
	node_count ++;

    hot_file_global_info.node_count = node_count;
    //按照内存节点数node_count分配node_count个hot_file_node_pgdat结构体，保存到数组
    hot_file_global_info.p_hot_file_node_pgdat = (struct hot_file_node_pgdat *)kmalloc(node_count*sizeof(struct hot_file_node_pgdat),GFP_KERNEL);
    for(i = 0;i < node_count;i++){
	//保存每个内存节点的pgdat指针
        hot_file_global_info.p_hot_file_node_pgdat[i].pgdat = NODE_DATA(i);
	//初始化每个内存节点的pgdat_page_list链表，将来内存回收时，把每个内存节点要回收的内存保存到pgdat_page_list链表上
        INIT_LIST_HEAD(&hot_file_global_info.p_hot_file_node_pgdat[i].pgdat_page_list);
    }

    hot_file_global_info.hot_file_thead = kthread_run(hot_file_thread,&hot_file_global_info, "hot_file_thread");
    if (IS_ERR(hot_file_global_info.hot_file_thead)) {
	printk("Failed to start  hot_file_thead\n");
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

    return 0;
}
/*****************************************************************************************/
 #if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static struct kprobe kp_mark_page_accessed = {
    .symbol_name    = "mark_page_accessed",
};
#else
static struct kprobe kp_mark_page_accessed = {
    .symbol_name    = "folio_mark_accessed",
};
#endif
static struct kprobe kp__destroy_inode = {
    .symbol_name    = "__destroy_inode",
};
/*static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    pr_info("fault_handler: p->addr = %pF, trap #%dn", p->addr, trapnr);
    return 0;
}*/
static void mark_page_accessed_handler_post(struct kprobe *p, struct pt_regs *regs,
	                unsigned long flags)
{
    struct page *page = (struct page *)(regs->di);
    if(page){
        hot_file_update_file_status(page);
    }
}
static void __destroy_inode_handler_post(struct kprobe *p, struct pt_regs *regs,
	                unsigned long flags)
{
    struct inode *inode = (struct inode *)(regs->di);
    if(inode && inode->i_mapping && inode->i_mapping->rh_reserved1){
	struct hot_file_stat *p_hot_file_stat = (struct hot_file_stat *)(inode->i_mapping->rh_reserved1);
	//如果该inode被地方后，不用立即把inode->mapping对应的hot_file_stat立即加锁释放掉。因为即便这个inode被释放后立即又被其他进程分配，
	//但分配后会先对inode清0，inode->mapping 和 inode->mapping->rh_reserved1 全是0，不会受inode->mapping->rh_reserved1指向的老hot_file_stat结构的影响。只用异步内存回收线程
	//里这个hot_file_stat对应的hot file tree中的节点hot_file_area_tree_node结构和该文件的所有file_area结构。
	if(p_hot_file_stat->mapping == inode->i_mapping){
	    //xfs文件系统不会对新分配的inode清0，因此要主动对inode->i_mapping->rh_reserved1清0，防止该file_stat和inode被释放后。立即被其他进程分配了这个inode，但是没有对
	    //inode清0，导致inode->i_mapping->rh_reserved1还保存着老的已经释放的file_stat，因为inode->i_mapping->rh_reserved1不是0，不对这个file_stat初始化，
	    //然后把file_area添加到这个无效file_stat，就要crash。但是要把inode->i_mapping->rh_reserved1 = 0放到set_file_stat_in_delete(p_hot_file_stat)
	    //前边。否则的话，set_file_stat_in_delete(p_hot_file_stat)标记file_stat的delete标记位后，file_stat不能再被用到，但是inode->i_mapping->rh_reserved1还不是0，
	    //这样可能inode->i_mapping->rh_reserved1指向的file_stat还会被添加file_area，会出问题的，导致crash都有可能!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	    inode->i_mapping->rh_reserved1 = 0;
	    smp_wmb(); 
	    //这里有个很大的隐患，此时file_stat可能处于global hot_file_head、hot_file_head_temp、hot_file_head_temp_large 3个链表，这里突然设置set_file_stat_in_delete，
	    //将来这些global 链表遍历这个file_stat，发现没有 file_stat_in_hot_file_head等标记，会主动触发panic()。不对，set_file_stat_in_delete并不会清理原有的
	    //file_stat_in_hot_file_head等标记，杞人忧天了。
            set_file_stat_in_delete(p_hot_file_stat);
	    //inode->i_mapping->rh_reserved1 = NULL;
	    //smp_wmb();
	    printk("hot_file_stat:0x%llx delete !!!!!!!!!!!!!!!!\n",(u64)p_hot_file_stat);
	}
    }
}
static int __init async_memory_reclaime_for_cold_file_area_init(void)
{
    int ret;
    kp_mark_page_accessed.post_handler = mark_page_accessed_handler_post;
    //kp_mark_page_accessed.fault_handler = handler_fault;
    kp__destroy_inode.post_handler = __destroy_inode_handler_post;
    //kp_mark_page_accessed.fault_handler = handler_fault;

    
    ret = register_kprobe(&kp_mark_page_accessed);
    if (ret < 0) {
        pr_err("kp_mark_page_accessed register_kprobe failed, returned %d\n", ret);
        goto err;
    }
    ret = register_kprobe(&kp__destroy_inode); 
    if (ret < 0) {
        pr_err("kp__destroy_inode register_kprobe failed, returned %d\n", ret);
        goto err;
    }
    ret = hot_file_init();
    if(ret < 0){
        goto err;
    }
    return 0;
err:
    if(kp_mark_page_accessed.post_handler)
	unregister_kprobe(&kp_mark_page_accessed);

    if(kp__destroy_inode.post_handler)
	unregister_kprobe(&kp__destroy_inode);

    if(hot_file_global_info.hot_file_thead)
	kthread_stop(hot_file_global_info.hot_file_thead);

   return ret;
}
static void __exit async_memory_reclaime_for_cold_file_area_exit(void)
{ 
    unregister_kprobe(&kp_mark_page_accessed);
    unregister_kprobe(&kp__destroy_inode);
    kthread_stop(hot_file_global_info.hot_file_thead);
}
module_init(async_memory_reclaime_for_cold_file_area_init);
module_exit(async_memory_reclaime_for_cold_file_area_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hujunpeng : dongzhiyan_linux@163.com");
