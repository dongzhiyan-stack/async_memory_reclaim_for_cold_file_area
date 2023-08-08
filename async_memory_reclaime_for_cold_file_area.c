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

int open_shrink_printk = 0;
int open_shrink_printk1 = 0;
unsigned long file_area_shrink_page_enable = 1;
void inline update_async_shrink_page(struct page *page);
int hot_cold_file_init(void);
/***************************************************************/
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
};

//最大文件名字长度
#define MAX_FILE_NAME_LEN 100
//当一个文件file_stat长时间不被访问，释放掉了所有的file_area，再过FILE_STAT_DELETE_AGE_DX个周期，则释放掉file_stat结构
#define FILE_STAT_DELETE_AGE_DX  50

//一个 file_area 包含的page数，默认6个
#define PAGE_COUNT_IN_AREA_SHIFT 3
#define PAGE_COUNT_IN_AREA (1UL << PAGE_COUNT_IN_AREA_SHIFT)

#define TREE_MAP_SHIFT	6
#define TREE_MAP_SIZE	(1UL << TREE_MAP_SHIFT)
#define TREE_MAP_MASK (TREE_MAP_SIZE - 1)

#define TREE_ENTRY_MASK 3
#define TREE_INTERNAL_NODE 1

//file_area在 GOLD_FILE_AREA_LEVAL 个周期内没有被访问则被判定是冷file_area，然后释放这个file_area的page
#define GOLD_FILE_AREA_LEVAL  5

#define FILE_AREA_HOT_BIT (1 << 0)//file_area的bit0是1表示是热的file_area_hot,是0则是冷的。bit1是1表示是热的大文件，是0则是小文件
//一个冷file_area，如果经过HOT_FILE_AREA_FREE_LEVEL个周期，仍然没有被访问，则释放掉file_area结构
#define HOT_FILE_AREA_FREE_LEVEL  6
//当一个file_area在一个周期内访问超过FILE_AREA_HOT_LEVEL次数，则判定是热的file_area
#define FILE_AREA_HOT_LEVEL 3
//一个file_area表示了一片page范围(默认6个page)的冷热情况，比如page索引是0~5、6~11、12~17各用一个file_area来表示
struct file_area
{
    //每次file_stat的file_area_free链表上的file_area，每次遍历cold_time加1，如果cold_time达到阀值就释放掉file_area结构。
    //如果在这个过程中file_area又被访问了，则cold_time清0，并且把file_area移动到file_area_temp链表。
    //unsigned char cold_time;
    //不同取值表示file_area当前处于哪种链表，file_area_temp:0 file_area_hot:1 file_area_cold:2 file_area_free_temp:3 file_area_free:4 file_area_refault:5
    unsigned char file_area_state;
    //该file_area 上轮被访问的次数
    //unsigned int last_access_count;
    //该file_area最新依次被访问时的global_age，global_age - file_area_age差值大于 GOLD_FILE_AREA_LEVAL，则判定file_area是冷file_area，然后释放该file_area的page
    unsigned long file_area_age;
    //该file_area当前周期被访问的次数
    unsigned int area_access_count;
    //该file_area里的某个page最近一次被回收的时间点，单位秒
    unsigned int shrink_time;
    //file_area通过file_area_list添加file_stat的各种链表
    struct list_head file_area_list;
    //指向父hot_cold_file_area_tree_node节点，作用是在cold_file_area_detele()函数把file_area从hot file tree剔除时，顺便剔除没有成员的父节点，并且逐级向上剔除
    //父节点，最终删除整个hot file tree。其实这个parent可以没有，因为可以根据file_area的start_index从hot file tree找到它的父节点，也能实现同样效果呢。
    //但是这样耗时比较多，并且根据file_area的start_index从hot file tree找到它的父节点需要file_stat_lock加锁，稍微耗时，影响hot_file_update_file_status()获取file_stat_lock锁
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
    unsigned long file_stat_status;//bit0表示冷文件还是热文件，bit1表示大文件还是小文件
    unsigned int file_area_count;//总file_area结构个数
    unsigned int file_area_hot_count;//热file_area结构个数
//  unsigned char *file_area_cache;
    struct hot_cold_file_area_tree_root hot_cold_file_area_tree_root_node;
    spinlock_t file_stat_lock;
    //频繁被访问的文件page对应的file_area存入这个头结点
    struct list_head file_area_hot;
    //不冷不热处于中间状态的file_area结构添加到这个链表，新分配的file_area就添加到这里
    struct list_head file_area_temp;
    //访问很少的文件page对应的file_area，移动到该链表
    struct list_head file_area_cold;
    //每轮扫描被释放内存page的file_area结构临时先添加到这个链表。file_area_free_temp有存在的必要
    struct list_head file_area_free_temp;
    //所有被释放内存page的file_area结构最后添加到这个链表，如果长时间还没被访问，就释放file_area结构。
    struct list_head file_area_free;
    //file_area的page被释放后，但很快又被访问，发生了refault，于是要把这种page添加到file_area_refault链表，短时间内不再考虑扫描和释放
    struct list_head file_area_refault;
    //本轮扫描移动到file_area_cold链表的file_area个数
    //unsigned int file_area_count_in_cold_list;
    //上一轮扫描移动到file_area_cold链表的file_area个数
    //unsigned int old_file_area_count_in_cold_list;
    //file_stat里age最大的file_area的age
    unsigned long max_file_area_age;
    unsigned long recent_access_age;
};
struct hot_cold_file_node_pgdat
{
    pg_data_t *pgdat;
    struct list_head pgdat_page_list;
};
//热点文件统计信息全局结构体
struct hot_cold_file_global
{
    //被判定是热文本的file_stat添加到file_stat_hot_head链表,超过50%或者80%的file_area都是热的，则该文件就是热文件，文件的file_stat要移动到global的file_stat_hot_head链表
    struct list_head file_stat_hot_head;
    //新分配的文件file_stat默认添加到file_stat_temp_head链表
    struct list_head file_stat_temp_head;
    //如果文件file_stat上的page cache数超过1G，则把file_stat移动到这个链表。将来内存回收时，优先遍历这种file_stat，因为file_area足够多，能遍历到更多的冷file_area，回收到内存page
    struct list_head file_stat_temp_large_file_head;
    //当file_stat的file_area个数达到file_area_count_for_large_file时，表示该文件的page cache数达到1G。因为一个file_area包含了多个page，一个file_area并不能填满page，
    //因此实际file_stat的file_area个数达到file_area_count_for_large_file时，实际该文件的的page cache数应该小于1G
    int file_area_count_for_large_file;

    struct list_head cold_file_head;
    struct list_head file_stat_delete_head;
    struct list_head file_stat_zero_file_area_head;//0个file_area的file_stat移动到这个链表
    //在cold_fiLe_head链表的file_stat个数
    //unsigned int file_stat_count_in_cold_list;
    unsigned int file_stat_hot_count;
    unsigned int file_stat_count ;
    unsigned int file_stat_count_zero_file_area;//0个file_area的file_stat个数

    unsigned long global_age;//每个周期加1
    struct kmem_cache *file_stat_cachep;
    struct kmem_cache *file_area_cachep;
    struct kmem_cache *hot_cold_file_area_tree_node_cachep;
    spinlock_t global_lock;
    struct hot_cold_file_node_pgdat *p_hot_cold_file_node_pgdat;
    struct task_struct *hot_cold_file_thead;
    int node_count;
    atomic_t   ref_count;
    atomic_t   inode_del_count;
    struct hot_cold_file_shrink_counter hot_cold_file_shrink_counter;
};

static struct kprobe kp_kallsyms_lookup_name = {
    .symbol_name    = "kallsyms_lookup_name",
};
static void kallsyms_lookup_name_handler_post(struct kprobe *p, struct pt_regs *regs,
	                unsigned long flags)
{
}
static void inline cold_file_stat_delete(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat_del);
enum file_area_status{
    F_file_area_in_temp_list,
    F_file_area_in_cold_list,
    F_file_area_in_hot_list,
    F_file_area_in_free_temp_list,
    F_file_area_in_free_list,
    F_file_area_in_refault_list
};
//不能使用 clear_bit、set_bit、test_bit，因为要求p_file_area->file_area_state是64位数据，但实际只是u8型数据

//设置file_area的状态，在哪个链表
#define CLEAR_FILE_AREA_STATUS(list_name) \
static inline void clear_file_area_in_##list_name(struct file_area *p_file_area)\
      { p_file_area->file_area_state &= ~(1 << F_file_area_in_##list_name);}
//    {clear_bit(file_area_in_##list_name,p_file_area->file_area_state);}
//清理file_area在哪个链表的状态
#define SET_FILE_AREA_STATUS(list_name) \
static inline void set_file_area_in_##list_name(struct file_area *p_file_area)\
    { p_file_area->file_area_state |= (1 << F_file_area_in_##list_name);}
    //{set_bit(file_area_in_##list_name,p_file_area->file_area_state);}
//测试file_area在哪个链表
#define TEST_FILE_AREA_STATUS(list_name) \
static inline int file_area_in_##list_name(struct file_area *p_file_area)\
    {return p_file_area->file_area_state & (1 << F_file_area_in_##list_name);}
    //{return test_bit(file_area_in_##list_name,p_file_area->file_area_state);}

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

enum file_stat_status{
    F_file_stat_in_file_stat_hot_head_list,
    F_file_stat_in_file_stat_temp_head_list,
    F_file_stat_in_zero_file_area_list,
    F_file_stat_in_large_file,
    F_file_stat_in_delete,
    F_file_stat_lock,
};
//不能使用 clear_bit、set_bit、test_bit，因为要求p_file_stat->file_stat_status是64位数据，但这里只是u8型数据

//设置file_stat的状态，在哪个链表
#define CLEAR_FILE_STAT_STATUS(name)\
static inline void clear_file_stat_in_##name##_list(struct file_stat *p_file_stat)\
    {p_file_stat->file_stat_status &= ~(1 << F_file_stat_in_##name##_list);}
//    {clear_bit(file_stat_in_##list_name,p_file_stat->file_stat_status);}
//清理file_stat在哪个链表的状态
#define SET_FILE_STAT_STATUS(name)\
static inline void set_file_stat_in_##name##_list(struct file_stat *p_file_stat)\
    {p_file_stat->file_stat_status |= (1 << F_file_stat_in_##name##_list);}
//    {set_bit(file_stat_in_##list_name,p_file_stat->file_stat_status);}
//测试file_stat在哪个链表
#define TEST_FILE_STAT_STATUS(name)\
static inline int file_stat_in_##name##_list(struct file_stat *p_file_stat)\
    {return (p_file_stat->file_stat_status & (1 << F_file_stat_in_##name##_list));}
//    {return test_bit(file_stat_in_##list_name,p_file_stat->file_stat_status);}

#define FILE_STAT_STATUS(name) \
    CLEAR_FILE_STAT_STATUS(name) \
    SET_FILE_STAT_STATUS(name) \
    TEST_FILE_STAT_STATUS(name)

FILE_STAT_STATUS(file_stat_hot_head)
FILE_STAT_STATUS(file_stat_temp_head)
FILE_STAT_STATUS(zero_file_area)
    
//设置文件的状态，大小文件等
#define CLEAR_FILE_STATUS(name)\
static inline void clear_file_stat_in_##name(struct file_stat *p_file_stat)\
    {p_file_stat->file_stat_status &= ~(1 << F_file_stat_in_##name);}
//清理文件的状态，大小文件等
#define SET_FILE_STATUS(name)\
static inline void set_file_stat_in_##name(struct file_stat *p_file_stat)\
    {p_file_stat->file_stat_status |= (1 << F_file_stat_in_##name);}
//测试文件的状态，大小文件等
#define TEST_FILE_STATUS(name)\
static inline int file_stat_in_##name(struct file_stat *p_file_stat)\
    {return (p_file_stat->file_stat_status & (1 << F_file_stat_in_##name));}

#define FILE_STATUS(name) \
    CLEAR_FILE_STATUS(name) \
    SET_FILE_STATUS(name) \
    TEST_FILE_STATUS(name)

FILE_STATUS(large_file)
FILE_STATUS(delete)

static inline void lock_file_stat(struct file_stat * p_file_stat){
     //如果有其他进程对file_stat的lock加锁，while成立，则休眠等待这个进程释放掉lock，然后自己加锁
     while(test_and_set_bit_lock(F_file_stat_lock, &p_file_stat->file_stat_status)){
          msleep(1);
	  dump_stack();
     }
}
static inline void unlock_file_stat(struct file_stat * p_file_stat){
    clear_bit_unlock(F_file_stat_lock, &p_file_stat->file_stat_status);
}


struct hot_cold_file_global hot_cold_file_global_info;

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
	    mapping_count ++;

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
    //hot_cold_file_global_info.hot_cold_file_shrink_counter.page_unevictable_count += page_unevictable_count;

    return nr_reclaimed;
}
static int __hot_cold_file_isolate_lru_pages(pg_data_t *pgdat,struct page * page,struct list_head *dst,isolate_mode_t mode)
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

                if(open_shrink_printk)
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
                        if(open_shrink_printk)
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

                    if(open_shrink_printk)
		        printk("1:%s %s %d page:0x%llx page->flags:0x%lx trylock_page(page)\n",__func__,current->comm,current->pid,(u64)page,page->flags);
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
		        writeback_count ++;

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

                    if(open_shrink_printk)
		        printk("3:%s %s %d page:0x%llx page->flags:0x%lx PageDirtyn",__func__,current->comm,current->pid,(u64)page,page->flags);
		    goto activate_locked;
		    //这里goto keep 分支，忘了unlock_page()了，导致其他进程访问到该page时因为page lock就休眠了!!!!!!!!!!!!!!!!
		    //goto keep;
		}

		if (page_has_private(page)) {
		        page_has_private_count ++;

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
		    mapping_count ++;
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
//static unsigned int move_pages_to_lru(struct lruvec *lruvec,struct list_head *list)
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
        printk("mem_cgroup_disabled_async:0x%llx != mem_cgroup_disabled:0x%llx %d\n",(u64)mem_cgroup_disabled_async,(u64)mem_cgroup_disabled,mem_cgroup_disabled_async());
        //return -1;
    }
#endif

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
     
    //对file_stat加锁
    lock_file_stat(p_file_stat);
    //如果文件inode和mapping已经释放了，则不能再使用mapping了，必须直接return
    if(NULL == p_file_stat->mapping || file_stat_in_delete(p_file_stat))
        goto err;
    mapping = p_file_stat->mapping;

    //!!!!!!!!!!!!!!隐藏非常深的地方，这里遍历file_area_free(即)链表上的file_area时，可能该file_area在hot_file_update_file_status()中被访问而移动到了temp链表
    //这里要用list_for_each_entry_safe()，不能用list_for_each_entry!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    list_for_each_entry_safe(p_file_area,tmp_file_area,file_area_free,file_area_list){
	//如果在遍历file_stat的file_area过程，__destroy_inode_handler_post()里释放该file_stat对应的inode和mapping，则对file_stat加锁前先p_file_stat->mapping =NULL.
	//然后这里立即goto err并释放file_stat锁，最后__destroy_inode_handler_post()可以立即获取file_stat锁
        if(NULL == p_file_stat->mapping)
            goto err;

        //if(open_shrink_printk)
	//    printk("%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%x p_file_area:0x%llx status:0x%x\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status,(u64)p_file_area,p_file_area->file_area_state);

#if 0 
	//--------这段注释不要删除-------------------很重要

	/*这里要对p_file_area->shrink_time的赋值需要加锁。
	  情况1：这里先加锁。对p_file_area->shrink_time赋值，然后1s内执行hot_file_update_file_status()获取锁，访问到该file_area，则判定该file_area是refault file_area。
	  情况2:hot_file_update_file_status()先加锁，访问该file_area，令p_hot_cold_file_global->global_age和p_file_area->file_area_age相等，则
	        这里直接continue，不再释放file_area的page。

	  有了file_stat_lock加锁，完美解决p_file_area->shrink_time在这里的赋值 和 在hot_file_update_file_status()函数的访问 时，数据不同步的问题，但是
	  这个加锁真的有必要吗????????要多次加锁,太浪费性能了，影响hot_file_update_file_status()函数的spin_lock(&p_file_stat->file_stat_lock)加锁
	 */
	spin_lock(&p_file_stat->file_stat_lock);
	//如果此时file_area又被访问了，则不再释放，并移动回file_area_temp链表
	//if(p_file_area->area_access_count - p_file_area->last_access_count  0){
	if(p_hot_cold_file_global->global_age == p_file_area->file_area_age){
            list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
	    set_file_area_in_temp_list(p_file_area);
	    spin_unlock(&p_file_stat->file_stat_lock);
	    continue;
	}
        //获取file_area内存回收的时间，ktime_to_ms获取的时间是ms，右移10近似除以1000，变成单位秒
	p_file_area->shrink_time = ktime_to_ms(ktime_get()) >> 10;
	spin_unlock(&p_file_stat->file_stat_lock);
#else
	/*对p_file_area->shrink_time的赋值不再加锁，
	 *情况1:如果这里先对p_file_area->shrink_time赋值，然后1s内hot_file_update_file_status()函数访问该file_area，则file_area被判定是refault file_area。
	 *情况2:先有hot_file_update_file_status()函数访问该file_area,但p_file_area->shrink_time还是0，则file_area无法被判定是refault file_area.
          但因为file_area处于file_stat->file_area_free_temp链表上，故把file_area移动到file_stat->file_area_temp链表。然后这里执行到
	  if(!file_area_in_free_list(p_file_area))，if成立，则不再不再回收该file_area的page。这种情况也没事

	 *情况3:如果这里快要对p_file_area->shrink_time赋值，但是先有hot_file_update_file_status()函数访问该file_area，但p_file_area->shrink_time还是0，
	        则file_area无法被判定是refault file_area.但因为file_area处于file_stat->file_area_free_temp链表上，故把file_area移动到file_stat->file_area_temp链表。
		但是，在把file_area移动到file_stat->file_area_free_temp链表上前，这里并发先执行了对p_file_area->shrink_time赋值当前时间和
		if(!file_area_in_free_list(p_file_area))，但if不成立。然后该file_area的page还要继续走内存回收流程。相当于刚访问过的file_area却被回收内存page了.
		这种情况没有办法。只有在hot_file_update_file_status()函数中，再次访问该file_area时，发现p_file_area->shrink_time不是0，说明刚该file_area经历过一次
		重度refault现象，于是也要把file_area移动到refault链表。注意，此时file_area处于file_stat->file_area_free_temp链表。
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
#endif
	//设置 file_area的状态为 in_free_list
	//set_file_area_in_free_list(p_file_area);------这里不再设置set_file_area_in_free_list的状态，因为设置需要file_stat_lock加锁，浪费性能
	
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
	//得到file_area对应的page
	for(i = 0;i < PAGE_COUNT_IN_AREA;i ++){
	    page = xa_load(&mapping->i_pages, p_file_area->start_index + i);
	    if (page && !xa_is_value(page)) {
		//正常情况每个文件的page cache的page都应该属于同一个node，进行一次spin_lock(&pgdat->lru_lock)就行，但是也有可能属于不同的内存节点node，
		//那就需要每次出现新的page所属的内存节点node的pgdat=page_pgdat(page)时，那就把老的pgdat=page_pgdat(page)解锁，对新的pgdat=page_pgdat(page)加锁
		//pgdat != page_pgdat(page)成立说明前后两个page所属node不一样，那就要把前一个page所属pgdat spin unlock，然后对新的page所属pgdat spin lock
                if(unlikely(pgdat != page_pgdat(page)))
		{
		    //第一次进入这个if，pgdat是NULL，此时不用spin unlock，只有后续的page才需要
		    if(pgdat){
			//对之前page所属pgdat进行spin unlock
                        spin_unlock(&pgdat->lru_lock);
		    }
		    //pgdat最新的page所属node节点对应的pgdat
		    pgdat = page_pgdat(page);
		    if(pgdat != p_hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat)
	                panic("pgdat not equal\n");
		    //对新的page所属的pgdat进行spin lock
		    spin_lock(&pgdat->lru_lock);
		}
		//在把page从lru链表移动到dst临时链表时，必须spin_lock(&pgdat->lru_lock)加锁
		//list_move(&page->lru,dst);-----在下边的file_area_isolate_lru_pages实现
		
                /*这里又是另外一个核心点。由于现在前后两次的page不能保证处于同一个内存node、同一个memory、同一个lruvec，因此
		 * 只能每来一个page，都执行类似原版内存回收的isolate_lru_pages，判断能否隔离，可以隔离的话。再计算当前page所属的
		 * pgdat、lruvec、active/inacitve lru编号，然后把page从lru链表剔除，再令lru链表的page数减1。而原来内存回收的isolate_lru_pages函数，进行隔离的
		 * 多个page一定来自同一个pgdat、lruvec、active/inacitve lru编号，就不用针对隔离的每个page再计算这些参数了。并且把所有page
		 * 都隔离后，同一执行update_lru_sizes()令lru链表的page数减去隔离成功的page数。显然，这样更节省cpu，我的方法稍微有点耗cpu，尤其是隔离page多的情况下*/
		dst = &p_hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat_page_list;//把page保存到对应node的hot_cold_file_node_pgdat链表上
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
	    //folio = xa_load(&mapping->i_pages, p_file_area->start_index + i);
	    //if (folio && !xa_is_value(folio)) {
	    page = xa_load(&mapping->i_pages, p_file_area->start_index + i);
	    if (page && !xa_is_value(page)) {
		//为了保持兼容，还是把每个内存节点的page都移动到对应hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat_page_list链表上
		if(pgdat != page_pgdat(page))
		    pgdat = page_pgdat(page);

		lruvec_new = mem_cgroup_lruvec_async(page_memcg(page),pgdat);
                if(unlikely(lruvec != lruvec_new)){
		    if(lruvec){
                        spin_unlock(&lruvec->lru_lock);
		    }
		    lruvec = lruvec_new;
		    //对新的page所属的pgdat进行spin lock
		    spin_lock(&lruvec->lru_lock);
		}

		dst = &p_hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat_page_list;//把page保存到对应node的hot_cold_file_node_pgdat链表上
		if(__hot_cold_file_isolate_lru_pages(pgdat,page,dst,mode) != 0){
		    //goto err; 到这里说明page busy，不能直接goto err返回错误，继续遍历page，否则就中断了整个内存回收流程，完全没必要
		    continue;
		}
		isolate_pages ++;
	    }
	}
    #endif
    }
err:   
  
    //file_stat解锁
    unlock_file_stat(p_file_stat);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
    if(pgdat)
	spin_unlock(&pgdat->lru_lock);
#else
    if(lruvec)
	spin_unlock(&lruvec->lru_lock);
#endif
    return isolate_pages;
}

/*************以上代码不同内核版本可能有差异******************************************************************************************/

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
int hot_cold_file_area_tree_extend(struct hot_cold_file_area_tree_root *root,unsigned long area_index,unsigned int shift)
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
	//在分配radix tree node前，是spin lock加了file_stat->file_stat_lock锁的，故这里分配内存禁止休眠，否则低内存场景就会占着spin锁休眠，然后导致其他进程获取spin lock失败而soft lockup
        //struct hot_cold_file_area_tree_node* node = kmem_cache_alloc(hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep,GFP_KERNEL);
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
	//当file_area tree只保存索引是0的file_area时，file_area指针是保存在root->root_node指针里。后续file_area tree添加其他成员时，就需要增加tree层数，就在这个循环完成。
	//可能file_area tree一次只增加一层，或者增加多层。这行代码是限制，当第一层增加tree层数时，slot是root->root_node，并且slot保存的是索引是0的file_area指针，不是节点。
	//则hot_cold_file_area_tree_is_internal_node(slot)返回flase，然后执行slot->parent = node令索引是0的file_area的parent指向父节点。没有这样代码，该file_area就成没有父亲的孤儿了，后续释放tree就会有问题
        else if(slot == root->root_node && !hot_cold_file_area_tree_is_internal_node(slot))
	    /*此时根节点root->root_node保存的是file_area指针，并不是hot_cold_file_area_tree_node指针，要强制转换成file_area指针并令其parent成员指向父节点。否则还是以
	     * hot_cold_file_area_tree_node->parent=node形式赋值，实际赋值到了file_area->file_area_age成员那里，内存越界了,导致它很大!!这个else if只在tree由0层向1层增加时才成立，
	     * 只会成立这一次，后续tree再增长高度，这里都不成立。此时slot=root->root_node保存的file_area指针,bit1是0，不是internal_node.后续到这里slot都是internal_node，bit0是1.*/
	      //slot->parent = node; 此时根节点root->root_node保存的是file_area指针，并不是hot_cold_file_area_tree_node指针，要强制转换成file_area指针并
	    ((struct file_area *)slot)->parent = node;

	node->slots[0] = slot;
	slot = node_to_entry(node);
	rcu_assign_pointer(root->root_node, slot);
	shift += TREE_MAP_SHIFT;
        //printk("%s %s %d node:0x%llx slot:0x%llx shift:%d\n",__func__,current->comm,current->pid,(u64)node,(u64)slot,shift);
    }while (shift <= maxshift);
out:
    return maxshift + RADIX_TREE_MAP_SHIFT;    
}
struct hot_cold_file_area_tree_node *hot_cold_file_area_tree_lookup_and_create(struct hot_cold_file_area_tree_root *root,
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
	//此时的根节点node指针的bit0是1，表示是个节点，并不是真正的hot_cold_file_area_tree_node指针，此时node->shift永远错误是0。下边每次就有很大概率执行hot_cold_file_area_tree_extend()
	//反复创建tree新的层数，即便对应的层数之前已经创建过了
        node = entry_to_node(node);
        //file_area_tree根节点的的shift+6
        shift = node->shift + TREE_MAP_SHIFT;
        max_area_index = hot_cold_file_area_tree_shift_maxindex(node->shift);
	//这里要把node的bit0置1，否则下边child = node后，child的bit0是0，不再表示根节点，导致下边的while循环中直接走else if (!hot_cold_file_area_tree_is_internal_node(child))分支,
	//这样每次都无法遍历tree，返回的
	node = node_to_entry(node);
    }
    else//到这里说明file_area_tree 是空的，没有根节点
    {
	shift = 0;
	max_area_index = 0;
    }
    //此时child指向根节点
    child = node;
    //这里再赋值NULL是为了保证shift=0的场景，就是tree没有一个节点，只有索引是0的成员保存在root->root_node根节点，此时到这里shift是0，下边的while (shift > 0)不成立。
    //此时该函数返回的父节点node应是NULL，因为返回的slot就指向根节点的root->root_node，它的父节点是NULL
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
	    //在分配radix tree node前，是spin lock加了file_stat->file_stat_lock锁的，故这里分配内存禁止休眠，否则低内存场景就会占着spin锁休眠，然后导致其他进程获取spin lock失败而soft lockup
            //child = kmem_cache_alloc(hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep,GFP_KERNEL);
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
        /*下轮循环，node= child 成为新的父节点。slot指向父节点node的某个槽位，这个槽位保存child这个节点指针 或者file_area_tree树最下层节点的file_area_tree指针*/
        //printk("%s %s %d node:0x%llx child:0x%llx slot:0x%llx offset:%d max_area_index:%ld shift:%d\n",__func__,current->comm,current->pid,(u64)node,(u64)child,(u64)slot,offset,max_area_index,shift);
    }
    //page_slot_in_tree是3重指针，*page_slot_in_tree 和 slot 是2重指针，*page_slot_in_tree和slot才能彼此赋值。赋值后*page_slot_in_tree保存的是槽位的地址
    *page_slot_in_tree = slot;
    return node;
}
//释放file_area结构，返回0说明释放成功，返回1说明file_area此时又被访问了，没有释放
int cold_file_area_detele(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct file_area *p_file_area)
{
    struct hot_cold_file_area_tree_node *p_hot_cold_file_area_tree_node = p_file_area->parent;
    struct hot_cold_file_area_tree_node * p_hot_cold_file_area_tree_node_tmp;
    int file_area_index = p_file_area->start_index >>PAGE_COUNT_IN_AREA_SHIFT;
    //取出file_area在父节点的槽位号，这个计算方法是错误的，p_file_area->start_index是起始page的索引，不是file_area索引，这样会导致计算出的
    //槽位号slot_number是错误的，这样会导致错剔除其他的file_area
    //int slot_number = p_file_area->start_index & TREE_MAP_MASK;
    int slot_number = file_area_index & TREE_MAP_MASK;

    //在释放file_area时，可能正有进程执行hot_file_update_file_status()遍历file_area_tree树中p_file_area指向的file_area结构，
    //这里又在释放file_area结构，因此需要加锁。
    spin_lock(&p_file_stat->file_stat_lock);
    //如果近期file_area被访问了
    if(hot_cold_file_global_info.global_age - p_file_area->file_area_age < 2 ){
	//那就把它再移动回file_stat->file_area_temp链表头。有这个必要吗？没有必要的!因为该file_area是在file_stat->file_area_free链表上，如果
	//被访问了而执行hot_file_update_file_status()函数，会把这个file_area立即移动到file_stat->file_area_temp链表，这里就没有必要做了!!!!!!!!!!!!!!!
	
        //set_file_area_in_temp_list(p_file_area);
	//list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
        spin_unlock(&p_file_stat->file_stat_lock);
	return 1;
    }
    //该文件file_stat的file_area个数减1，这个过程已经加了锁。这个减1要放到这里，保证"仅有一个索引是0的file_area指针保存在根节点file_stat->hot_cold_file_area_tree_root_node.root_node"的
    //file_area结构释放时，也能令file_stat总file_area个数减1
    p_file_stat->file_area_count --;

    //这个if成立，说明当前hot file tree是空树，仅有一个索引是0的file_area指针保存在根节点file_stat->hot_cold_file_area_tree_root_node.root_node，
    //现在这个file_area被剔除了，仅仅把file_stat->hot_cold_file_area_tree_root_node.root_node设置成NULL即可，表示之后该hot file tree一个file_area都没保存
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
    //该文件file_stat的file_area个数减1，这个过程已经加了锁
    //p_file_stat->file_area_count --;
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
	//如果此时p_hot_cold_file_area_tree_node是NULL，说明上一部hot file tree只有一层，p_hot_cold_file_area_tree_node指向第一层的节点，而它的父节点即p_hot_cold_file_area_tree_node->parent
	//就是NULL。此时if成立，并且hot file tree此时唯一的节点也释放了，是空树，则要设置file_stat->hot_cold_file_area_tree_root_node.root_node=NULL，表示一个成员都没有了。
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
unsigned int cold_file_area_detele_quick(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct file_area *p_file_area)
{
    struct hot_cold_file_area_tree_node *p_hot_cold_file_area_tree_node = p_file_area->parent;
    struct hot_cold_file_area_tree_node * p_hot_cold_file_area_tree_node_tmp;

    int file_area_index = p_file_area->start_index >>PAGE_COUNT_IN_AREA_SHIFT;
    int slot_number = file_area_index & TREE_MAP_MASK;
    
    //该文件file_stat的file_area个数减1，这个过程已经加了锁。这个减1要放到这里，保证"仅有一个索引是0的file_area指针保存在根节点file_stat->hot_cold_file_area_tree_root_node.root_node"的
    //file_area结构释放时，也能令file_stat总file_area个数减1
    p_file_stat->file_area_count --;

    //这个if成立，说明当前hot file tree是空树，仅有一个索引是0的file_area指针保存在根节点file_stat->hot_cold_file_area_tree_root_node.root_node，
    //现在这个file_area被剔除了，仅仅把file_stat->hot_cold_file_area_tree_root_node.root_node设置成NULL即可，表示之后该hot file tree一个file_area都没保存
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
    //该文件file_stat的file_area个数减1
    //p_file_stat->file_area_count --;
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
	//如果此时p_hot_cold_file_area_tree_node是NULL，说明上一部hot file tree只有一层，p_hot_cold_file_area_tree_node指向第一层的节点，而它的父节点即p_hot_cold_file_area_tree_node->parent
	//就是NULL。此时if成立，并且hot file tree此时唯一的节点也释放了，是空树，则要设置file_stat->hot_cold_file_area_tree_root_node.root_node=NULL，表示一个成员都没有了。
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

    //差点就犯的超隐藏错误!!!!!!!!!!!!!!!!!!把file_stat从hot_cold_file_global的链表剔除，然后kmem_cache_free释放后，p_file_stat_del->hot_cold_file_list的next和prev
    //就设置成LIST_POISON1/LIST_POISON2.之后能通过下边的if判断判定file_stat是否已经从hot_cold_file_global的链表剔除了吗？第一印象可以，但实际p_file_stat_del->
    //hot_cold_file_list.next就会非法内存访问而crash，因为此时这file_stat结构体已经释放了，p_file_stat_del->hot_cold_file_list指向的这个结构体内存已经释放了，是无效内存!!!
#if 0
    if((p_file_stat_del->hot_cold_file_list.next == LIST_POISON1) || (p_file_stat_del->hot_cold_file_list.prev == LIST_POISON2)){
         spin_unlock(&p_hot_cold_file_global->global_lock);
         unlock_file_stat(p_file_stat_del);
         return;	 
    }
#else
    //lock_file_stat加锁原因是:当异步内存回收线程在这里释放file_stat结构时，同一时间file_stat对应文件inode正在被释放而执行到__destroy_inode_handler_post()函数。
    //如果这里把file_stat释放了，__destroy_inode_handler_post()使用file_stat就要crash。而lock_file_stat()防止这种情况。同时，__destroy_inode_handler_post()执行后会
    //立即释放inode和mapping，然后此时这里要用到p_file_stat->mapping->rh_reserved1，此时同样也会因file_stat已经释放而crash
    lock_file_stat(p_file_stat_del);
    if(p_file_stat_del->mapping){
        //文件inode的mapping->rh_reserved1清0表示file_stat无效，这__destroy_inode_handler_post()删除inode时，发现inode的mapping->rh_reserved1是0就不再使用file_stat了，会crash
        p_file_stat_del->mapping->rh_reserved1 = 0;
	p_file_stat_del->mapping = NULL;
    }
    //下边的spin_unlock有内存屏障操作吗？算了，这里主动调用一下
    smp_wmb();
    unlock_file_stat(p_file_stat_del);
#endif

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
    //释放file_stat后，必须要把p_file_stat->mapping清NULL
    p_file_stat_del->mapping = NULL;
    //主动删除的file_stat也要标记delete，防止这个已经被释放file_stat在hot_file_update_file_status()里被再次使用，会因file_stat有delete标记而触发crash
    set_file_stat_in_delete(p_file_stat_del);
    //从global的链表中剔除该file_stat，这个过程需要加锁，因为同时其他进程会执行hot_file_update_file_status()向global的链表添加新的文件file_stat
    list_del(&p_file_stat_del->hot_cold_file_list);
    //释放该file_stat结构
    kmem_cache_free(p_hot_cold_file_global->file_stat_cachep,p_file_stat_del);
    //file_stat个数减1
    hot_cold_file_global_info.file_stat_count--;
    spin_unlock(&p_hot_cold_file_global->global_lock);

    printk("%s file_stat:0x%llx delete !!!!!!!!!!!!!!!!\n",__func__,(u64)p_file_stat_del);
}
//删除p_file_stat_del对应文件的file_stat上所有的file_area，已经对应hot file tree的所有节点hot_cold_file_area_tree_node结构。最后释放掉p_file_stat_del这个file_stat数据结构
unsigned int cold_file_stat_delete_all_file_area(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat_del)
{
    //struct file_stat * p_file_stat,*p_file_stat_temp;
    struct file_area *p_file_area,*p_file_area_temp;
    unsigned int del_file_area_count = 0;
    //refault链表
    list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_refault,file_area_list){
        if(!file_area_in_refault_list(p_file_area))
	    panic("%s file_area:0x%llx status:%d not in file_area_refault\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

        cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
	del_file_area_count ++;
    }
    //hot链表
    list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_hot,file_area_list){
        if(!file_area_in_hot_list(p_file_area))
	    panic("%s file_area:0x%llx status:%d not in file_area_hot\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

        cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
	del_file_area_count ++;
    }
    //temp链表
    list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_temp,file_area_list){
        if(!file_area_in_temp_list(p_file_area))
	    panic("%s file_area:0x%llx status:%d not in file_area_temp\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

        cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
	del_file_area_count ++;
    }
    //free链表
    list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_free,file_area_list){
        if(!file_area_in_free_list(p_file_area))
	    panic("%s file_area:0x%llx status:%d not in file_area_free\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

        cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
	del_file_area_count ++;
    }
    //free_temp链表
    list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_free_temp,file_area_list){
        if(!file_area_in_free_list(p_file_area))
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
int is_file_stat_hot_file(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat){
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
int inline is_file_stat_large_file(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat)
{
    if(p_file_stat->file_area_count > hot_cold_file_global_info.file_area_count_for_large_file)
	return 1;
    else
	return 0;
}
//模仿page_mapping()判断是否是page cache
inline struct address_space * hot_cold_file_page_mapping(struct page *page)
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
    mapping = hot_cold_file_page_mapping(page);
    /*注意，遇到一个奇葩现象，因mapping->host->i_sb不合法而导致 mapping->host->i_sb->s_dev 非法内存访问而crash，竟然直接重启了，没有生成vmcore。难道是因为
     * 现在hot_file_update_file_status()是在kprobe里调用，kprobe里非法内存访问导致系统crash，不会生成vmcore?这对调试太不利了!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
    if(mapping && mapping->host && mapping->host->i_sb/* && (file_area_shrink_page_enable == mapping->host->i_sb->s_dev || file_area_shrink_page_enable == mapping->host->i_sb->s_dev >> 20)*/){
        void **page_slot_in_tree = NULL;
	//page所在的file_area的索引
	unsigned int area_index_for_page;
        struct hot_cold_file_area_tree_node *parent_node;
        int ret = 0;
        struct file_stat * p_file_stat = NULL;
        struct file_area *p_file_area = NULL; 
        
	//驱动卸载后，file_area_shrink_page_enable清0，此时不再执行对file_stat和file_area更新的代码了
     #if 0
	smp_rmb();
	if(0 == file_area_shrink_page_enable)
	    return 0;
     #else
	//file_area_shrink_page_enable不再使用smp_rmb内存屏障，而直接使用set_bit/clear_bit原子操作
	if(!test_bit(0,&file_area_shrink_page_enable))
	    return 0;
     #endif 
	
        atomic_inc(&hot_cold_file_global_info.ref_count);
	
	//还要再判断一次file_area_shrink_page_enable是否是0，因为驱动卸载会先获取原子变量ref_count的值0，然后这里再执行atomic_inc(&hot_cold_file_global_info.ref_count)令ref_count加1.
	//这种情况必须判断file_area_shrink_page_enable是0，直接return返回。否则驱动卸载过程会释放掉file_stat结构，然后该函数再使用这个file_stat结构，触发crash
	//smp_rmb();
	//if(0 == file_area_shrink_page_enable)
	//    return 0;
	if(!test_bit(0,&file_area_shrink_page_enable))
	    goto err;

	//与 __destroy_inode_handler_post()函数mapping->rh_reserved1清0的smp_wmb()成对，详细看注释
	smp_rmb();
	//如果两个进程同时访问同一个文件的page0和page1，这就就有问题了，因为这个if会同时成立。然后下边针对
	if(mapping->rh_reserved1 == 0 ){

	    if(!hot_cold_file_global_info.file_stat_cachep || !hot_cold_file_global_info.file_area_cachep){
	        ret =  -ENOMEM;
		goto err;
	    }

	    //这里有个问题，hot_cold_file_global_info.global_lock有个全局大锁，每个进程执行到这里就会获取到。合理的是
	    //应该用每个文件自己的spin lock锁!比如file_stat里的spin lock锁，但是在这里，每个文件的file_stat结构还没分配!!!!!!!!!!!!
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
		goto err;
	    }
	    //file_stat个数加1
	    hot_cold_file_global_info.file_stat_count++;

	    memset(p_file_stat,0,sizeof(struct file_stat));
	    //初始化file_area_hot头结点
	    INIT_LIST_HEAD(&p_file_stat->file_area_hot);
	    INIT_LIST_HEAD(&p_file_stat->file_area_temp);
	    INIT_LIST_HEAD(&p_file_stat->file_area_cold);
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
		goto err;
	    }
	    //如果当前正在使用的file_stat的inode已经释放了，主动触发crash 
	    if(file_stat_in_delete(p_file_stat)){
	        panic("%s %s %d file_stat:0x%llx status:0x%lx in delete\n",__func__,current->comm,current->pid,(u64)p_file_stat,p_file_stat->file_stat_status);
	    }


            spin_lock(&p_file_stat->file_stat_lock);
	    //根据page索引的file_area的索引，找到对应在file area tree树的槽位，page_slot_in_tree双重指针指向这个槽位。
	    //下边分配真正的file_area结构，把file_area指针保存到这个操作
	    parent_node = hot_cold_file_area_tree_lookup_and_create(&p_file_stat->hot_cold_file_area_tree_root_node,area_index_for_page,&page_slot_in_tree);
            if(IS_ERR(parent_node)){
	        spin_unlock(&p_file_stat->file_stat_lock);
	        printk("%s file_area_tree_insert fail\n",__func__);
		goto err;
	    }
	    //两个进程并发执行该函数时，进程1获取file_stat_lock锁成功，执行file_area_tree_insert()查找page绑定的file_area的
	    //在file_area_tree的槽位，*page_slot_in_tree 是NULL，然后对它赋值。进程2获取file_stat_lock锁后，*page_slot_in_tree就不是NULL了
	    if(*page_slot_in_tree == NULL){//针对当前page索引的file_area结构还没有分配,page_slot_in_tree是槽位地址，*page_slot_in_tree是槽位里的数据，就是file_area指针
		//针对本次page索引，分配file_area一个结构，于是该file_area就代表了page
		p_file_area = kmem_cache_alloc(hot_cold_file_global_info.file_area_cachep,GFP_ATOMIC);
		if (!p_file_area) {
	            spin_unlock(&p_file_stat->file_stat_lock);
		    printk("%s file_area alloc fail\n",__func__);
		    ret =  -ENOMEM;
		    goto err;
		}
		memset(p_file_area,0,sizeof(struct file_area));
	        //把根据page索引分配的file_area结构指针保存到file area tree指定的槽位
	        rcu_assign_pointer(*page_slot_in_tree,p_file_area);

		//set_file_area_in_temp_list(p_file_area);
	        //把新分配的file_area添加到file_area_temp链表
	        list_add(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
		//保存该file_area对应的起始page索引，一个file_area默认包含8个索引挨着依次增大page，start_index保存其中第一个page的索引
		p_file_area->start_index = area_index_for_page * PAGE_COUNT_IN_AREA;
		//新分配的file_area指向其在file_area_tree的父节点node
		p_file_area->parent = parent_node;
		//如果第一次把索引是0的file_area插入file_area tree，是把该file_area指针保存到file_area tree的根节点，此时parent_node是NULL
		if(parent_node)
		    parent_node->count ++;//父节点下的file_area个数加1
		//令新创建的file_area的last_access_count为1，跟area_access_count相等。如果将来walk_throuth_all_file_area()扫描到file_area
		//的last_access_count和area_access_count都是1，说明后续该file_area就没被访问过。
		//p_file_area->last_access_count = 1;
		
		p_file_stat->file_area_count ++;//文件file_stat的file_area个数加1
		set_file_area_in_temp_list(p_file_area);//新分配的file_area必须设置in_temp_list链表
            }
	    p_file_area = *page_slot_in_tree;
	    //hot_cold_file_global_info.global_age更新了，把最新的global age更新到本次访问的file_area->file_area_age。并对file_area->area_access_count清0，本周期被访问1次则加1
	    if(p_file_area->file_area_age < hot_cold_file_global_info.global_age){
		p_file_area->file_area_age = hot_cold_file_global_info.global_age;
		if(p_file_area->file_area_age > p_file_stat->max_file_area_age)
                    p_file_stat->max_file_area_age = p_file_area->file_area_age;

	        p_file_area->area_access_count = 0;
	    }
	    //file_area区域的page被访问的次数加1
	    p_file_area->area_access_count ++;

	    //如果p_file_area在当前周期第1次被访问，则把移动到file_area_hot链表头，该链表头的file_area访问比较频繁，链表尾的file_area很少访问。
	    //将来walk_throuth_all_file_area()函数扫描释放page时过程，遍历到file_area所处的file_stat并释放内存page时，遍历这些file_stat的file_area_hot
	    //链表尾巴的file_area，如果这些file_area在移动到file_area_hot链表后,很少访问了，则把把这些file_area再降级移动回file_area_temp链表头
            if(p_file_area->area_access_count == 1)
	    {
		//如果p_file_area不在file_area_hot或file_area_temp链表头，才把它添加到file_area_hot或file_area_temp链表头
		//file_stat的file_area_hot或file_area_temp链表头的file_area是最频繁访问的，链表尾的file_area访问频次低，内存回收光顾这些链表尾的file_area
                
		if(file_area_in_temp_list(p_file_area)){
		    if(!list_is_first(&p_file_area->file_area_list,&p_file_stat->file_area_temp))
		        list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
		}else if(file_area_in_hot_list(p_file_area)){
		    if(!list_is_first(&p_file_area->file_area_list,&p_file_stat->file_area_hot))
		        list_move(&p_file_area->file_area_list,&p_file_stat->file_area_hot);
		}else if(file_area_in_refault_list(p_file_area)){//在refault链表的file_area如果被访问了也移动到链表头
		        list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
		}
	    }

            //如果p_file_area是冷热不定的，并且file_area的本轮访问次数大于阀值，则设置file_area热，并且把该file_area移动到file_area_hot链表
	    if(file_area_in_temp_list(p_file_area) &&  
		    //p_file_area->area_access_count - p_file_area->last_access_count >= FILE_AREA_HOT_LEVEL){
		p_file_area->area_access_count > FILE_AREA_HOT_LEVEL){

		clear_file_area_in_temp_list(p_file_area);
                //设置file_area 处于 file_area_hot链表
	        set_file_area_in_hot_list(p_file_area);
	        list_move(&p_file_area->file_area_list,&p_file_stat->file_area_hot);
		
		//该文件的热file_stat数加1
                p_file_stat->file_area_hot_count ++;
               
	        /*这段代码:把file_stat移动到file_stat_hot_head链表的代码可以考虑移动到get_file_area_from_file_stat_list()函数开头遍历file_stat的for循环里
		   以降低这里使用spin lock的性能损耗*/

		//如果文件file_stat的file_area很多都是热的，判定file_stat是热文件，则把file_stat移动到global file_stat_hot_head链表，
		//global file_stat_hot_head链表上的file_stat不再扫描上边的file_area，有没有必要这样做??????????????????????
		if(file_stat_in_file_stat_temp_head_list(p_file_stat) && is_file_stat_hot_file(&hot_cold_file_global_info,p_file_stat)){
		    //外层有spin_lock(&p_file_stat->file_stat_lock)，这里不应该再关中断，只能spin_lock加锁
		    //这个spin lock加锁可以移动到get_file_area_from_file_stat_list()函数开头遍历file_stat的for循环里，判断出热文件则把file_stat移动到
		    //hot_cold_file_global_info.file_stat_hot_head链表，否则在这个函数，可能频繁spin lock加锁而导致性能损失!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    spin_lock(&hot_cold_file_global_info.global_lock);
		    hot_cold_file_global_info.file_stat_hot_count ++;//热文件数加1
		    clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
		    //设置file_stat处于热文件链表
		    set_file_stat_in_file_stat_hot_head_list(p_file_stat);
		    //把file_stat移动到热文件链表
	            list_move(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.file_stat_hot_head);
                    spin_unlock(&hot_cold_file_global_info.global_lock);
		}
	    }

	    //如果file_area处于file_stat的free_list或free_temp_list链表
            if(file_area_in_free_list(p_file_area) || file_area_in_free_temp_list(p_file_area)){
		if(file_area_in_free_list(p_file_area))
		    clear_file_area_in_free_list(p_file_area);
		else
		    clear_file_area_in_free_temp_list(p_file_area);

                //file_area 的page被内存回收后，过了仅1s左右就又被访问则发生了refault，把该file_area移动到file_area_refault链表，
		//不再参与内存回收扫描!!!!需要设个保护期限制
		smp_rmb();
    		if(p_file_area->shrink_time && (ktime_to_ms(ktime_get()) - (p_file_area->shrink_time << 10) < 1000)){
		    p_file_area->shrink_time = 0;
	            set_file_area_in_refault_list(p_file_area);
		    list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
                }else{
		    p_file_area->shrink_time = 0;
	            //file_area此时正在被内存回收而移动到了file_stat的free_list或free_temp_list链表，则直接移动到file_stat->file_area_temp链表头
		    set_file_area_in_temp_list(p_file_area);
		    //if(file_area_in_free_list(p_file_area))
	            //    list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp_large);
		    //else
			list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
		}
	    }
            //如果file_area处于file_area链表，但是p_file_area->shrink_time不是0.这说明该file_area在之前walk_throuth_all_file_area()函数中扫描
	    //判定该file_area是冷的，然后回收内存page。但是回收内存时，正好这个file_area又被访问了，则把file_area移动到file_stat->file_area_temp链表。
	    //但是内存回收流程执行到cold_file_isolate_lru_pages()函数因并发问题没发现该file_area最近被访问了，只能继续回收该file_area的page。需要避免回收这种
	    //热file_area的page。于是等该file_area下次被访问，执行到这里，if成立，把该file_area移动到file_stat->file_area_refault链表。这样未来一段较长时间
	    //可以避免再次回收该file_area的page。具体详情看cold_file_isolate_lru_pages()函数里的注释
	    if(file_area_in_temp_list(p_file_area) && (p_file_area->shrink_time != 0)){
	        p_file_area->shrink_time = 0;
		clear_file_area_in_temp_list(p_file_area);
	        set_file_area_in_refault_list(p_file_area);
		list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
	    }
	    spin_unlock(&p_file_stat->file_stat_lock);

	    //文件file_stat的file_area个数大于阀值则移动到global file_stat_hot_head_large_file_temp链表
	    if(is_file_stat_large_file(&hot_cold_file_global_info,p_file_stat)){
		smp_rmb();
		//walk_throuth_all_file_area()函数中也有的大量的访问file_stat或file_area状态的，他们需要smp_rmb()吗，需要留意???????????????????????????????????????
		if(!file_stat_in_large_file(p_file_stat)){
	            if(open_shrink_printk)
	                printk("%s %s %d file_stat:0x%llx status:0x%lx %d:%d is_file_stat_large_file\n",__func__,current->comm,current->pid,(u64)p_file_stat,p_file_stat->file_stat_status,hot_cold_file_global_info.file_area_count_for_large_file,p_file_stat->file_area_count);
                    spin_lock(&hot_cold_file_global_info.global_lock);
		    //设置file_stat是大文件
		    set_file_stat_in_large_file(p_file_stat);
		    //如果file_stat已经被判定热文件而移动到了ot_file_global_info.file_stat_hot_head链表，不再移动到hot_cold_file_global_info.file_stat_temp_large_file_head链表。否则
		    //这个file_stat处于hot_cold_file_global_info.file_stat_temp_large_file_head链表，但是没有file_stat_in_file_stat_temp_head_list标记，将来遍历时会触发crash
		    if(!file_stat_in_file_stat_hot_head_list(p_file_stat))
	                list_move(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.file_stat_temp_large_file_head);
                    spin_unlock(&hot_cold_file_global_info.global_lock);
		}
	    }
	    //parent_node可能是NULL，此时索引是0的file_area保存在hot_cold_file_tree的根节点root_node里
	    if(0 && open_shrink_printk && p_file_area->area_access_count == 1 && parent_node)
	        printk("%s %s %d hot_cold_file_global_info:0x%llx p_file_stat:0x%llx status:0x%lx p_file_area:0x%llx status:0x%x file_area->area_access_count:%d file_area->file_area_age:%lu page:0x%llx page->index:%ld file_area_hot_count:%d file_area_count:%d shrink_time:%d start_index:%ld page_slot_in_tree:0x%llx tree-height:%d parent_node:0x%llx parent_node->count:0x%d\n",__func__,current->comm,current->pid,(u64)(&hot_cold_file_global_info),(u64)p_file_stat,p_file_stat->file_stat_status,(u64)p_file_area,p_file_area->file_area_state,p_file_area->area_access_count,p_file_area->file_area_age,(u64)page,page->index,p_file_stat->file_area_hot_count,p_file_stat->file_area_count,p_file_area->shrink_time,p_file_area->start_index,(u64)page_slot_in_tree,p_file_stat->hot_cold_file_area_tree_root_node.height,(u64)parent_node,parent_node->count);
	   
	    if(p_file_area->file_area_age > hot_cold_file_global_info.global_age)
	        panic("p_file_area->file_area_age:%ld > hot_cold_file_global_info.global_age:%ld\n",p_file_area->file_area_age,hot_cold_file_global_info.global_age);
err:
	atomic_dec(&hot_cold_file_global_info.ref_count);
	//不能因为走了err分支，就释放p_file_stat和p_file_area结构。二者都已经添加到ot_file_global_info.file_stat_hot_head 或 p_file_stat->file_area_temp链表，
	//不能释放二者的数据结构。是这样吗，得再考虑一下???????????????????????
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
EXPORT_SYMBOL(hot_file_update_file_status);
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
        if(open_shrink_printk)
            printk("1:%s %s %d node:0x%d pgdat:0x%llx\n",__func__,current->comm,current->pid,i,(u64)p_hot_cold_file_node_pgdat[i].pgdat);
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
    char file_name_path_tmp[MAX_FILE_NAME_LEN];
    struct dentry *dentry = NULL;
    unsigned int name_len = 0;

    file_name_path[0] = '\0';
    file_name_path_tmp[0] = '\0';
    //必须 hlist_empty()判断文件inode是否有dentry，没有则返回true
    //这里必须增加inode和dentry的应用计数，然后才能放心使用，不用担心使用时inode和dentry释放了 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    if(p_file_stat->mapping && p_file_stat->mapping->host && !hlist_empty(&p_file_stat->mapping->host->i_dentry)){
        //内核大量使用 hlist_for_each_entry(alias, &inode->i_dentry, d_u.d_alias) 遍历inode->d_u.d_alias 链表上的dentry，这里要优化下!!!!!!!!!!!!!
	dentry = hlist_entry(p_file_stat->mapping->host->i_dentry.first, struct dentry, d_u.d_alias);
        while(dentry && strcmp(dentry->d_iname,"/") != 0){
	    name_len += strlen(dentry->d_iname);
	    if(name_len > MAX_FILE_NAME_LEN - 2)
		break;
            
	    if(file_name_path[0] != '\0')
	        strcpy(file_name_path_tmp,file_name_path);
	    sprintf(file_name_path,"/%s",dentry->d_iname);
	    if(file_name_path_tmp[0] != '\0')
	        strcat(file_name_path,file_name_path_tmp);

	    dentry = dentry->d_parent;//父目录
	}
    }
}
//遍历p_hot_cold_file_global各个链表上的file_stat的file_area个数及page个数
int hot_cold_file_print_all_file_stat(struct hot_cold_file_global *p_hot_cold_file_global)
{
    struct file_stat * p_file_stat;
    unsigned int file_stat_one_file_area_count = 0,file_stat_many_file_area_count = 0;
    unsigned int file_stat_one_file_area_pages = 0,all_pages = 0;
    char file_name_path[MAX_FILE_NAME_LEN];

    //如果驱动在卸载，禁止再打印file_stat信息
    if(0 == test_bit(0,&file_area_shrink_page_enable)){
        printk("async_memory_reclaime ko is remove\n");
	return 0;
    }

    //hot_cold_file_global->file_stat_hot_head链表
    if(!list_empty(&p_hot_cold_file_global->file_stat_hot_head))
        printk("hot_cold_file_global->file_stat_hot_head list********\n");
    list_for_each_entry_rcu(p_file_stat,&p_hot_cold_file_global->file_stat_hot_head,hot_cold_file_list){
	atomic_inc(&hot_cold_file_global_info.ref_count);
	lock_file_stat(p_file_stat);
	//如果file_stat对应的文件inode释放了，file_stat被标记了delete，此时不能再使用p_file_stat->mapping，因为mapping已经释放了
	//但执行这个函数时，必须禁止执行cold_file_stat_delete_all_file_area()释放掉file_stat!!!!!!!!!!!!!!!!!!!!
	smp_rmb();//内存屏障获取最新的file_stat状态
	if(0 == file_stat_in_delete(p_file_stat)){
	    if(p_file_stat->file_area_count > 1){
		file_stat_many_file_area_count ++;
		get_file_name(file_name_path,p_file_stat);
		all_pages += p_file_stat->mapping->nrpages;

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
    if(!list_empty(&p_hot_cold_file_global->file_stat_temp_head))
        printk("hot_cold_file_global->file_stat_temp_head list********\n");
    list_for_each_entry_rcu(p_file_stat,&p_hot_cold_file_global->file_stat_temp_head,hot_cold_file_list){
	atomic_inc(&hot_cold_file_global_info.ref_count);
	lock_file_stat(p_file_stat);
	//如果file_stat对应的文件inode释放了，file_stat被标记了delete，此时不能再使用p_file_stat->mapping，因为mapping已经释放了
	//但执行这个函数时，必须禁止执行cold_file_stat_delete_all_file_area()释放掉file_stat!!!!!!!!!!!!!!!!!!!!
	smp_rmb();//内存屏障获取最新的file_stat状态
	if(0 == file_stat_in_delete(p_file_stat)){
	    if(p_file_stat->file_area_count > 1){
		file_stat_many_file_area_count ++;
		get_file_name(file_name_path,p_file_stat);
		all_pages += p_file_stat->mapping->nrpages;

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
    if(!list_empty(&p_hot_cold_file_global->file_stat_temp_large_file_head))
        printk("hot_cold_file_global->file_stat_temp_large_file_head list********\n");
    list_for_each_entry_rcu(p_file_stat,&p_hot_cold_file_global->file_stat_temp_large_file_head,hot_cold_file_list){
	atomic_inc(&hot_cold_file_global_info.ref_count);

	lock_file_stat(p_file_stat);
	//如果file_stat对应的文件inode释放了，file_stat被标记了delete，此时不能再使用p_file_stat->mapping，因为mapping已经释放了
	//但执行这个函数时，必须禁止执行cold_file_stat_delete_all_file_area()释放掉file_stat!!!!!!!!!!!!!!!!!!!!
	smp_rmb();//内存屏障获取最新的file_stat状态
	if(0 == file_stat_in_delete(p_file_stat)){
	    if(p_file_stat->file_area_count > 1){
		file_stat_many_file_area_count ++;
		get_file_name(file_name_path,p_file_stat);
		all_pages += p_file_stat->mapping->nrpages;

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

    printk("file_stat_one_file_area_count:%d pages:%d  file_stat_many_file_area_count:%d all_pages:%d\n",file_stat_one_file_area_count,file_stat_one_file_area_pages,file_stat_many_file_area_count,all_pages);
    return 0;
}

//遍历hot_cold_file_global->file_stat_temp_large_file_head或file_stat_temp_head链表尾巴上边的文件file_stat，然后遍历这些file_stat的file_stat->file_area_temp链表尾巴上的file_area，
//被判定是冷的file_area则移动到file_stat->file_area_free_temp链表。把有冷file_area的file_stat移动到file_stat_free_list临时链表。返回值是遍历到的冷file_area个数
static unsigned int get_file_area_from_file_stat_list(struct hot_cold_file_global *p_hot_cold_file_global,unsigned int scan_file_area_max,unsigned int scan_file_stat_max,
	                                 //file_stat_temp_head来自 hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head 链表
          	                         struct list_head *file_stat_temp_head,struct list_head *file_stat_free_list){
    struct file_stat * p_file_stat,*p_file_stat_temp;
    struct file_area *p_file_area,*p_file_area_temp;

    unsigned int scan_file_area_count  = 0;
    unsigned int scan_file_stat_count  = 0;
    unsigned int scan_delete_file_stat_count = 0;
    unsigned int scan_cold_file_area_count = 0;
    unsigned int scan_large_to_small_count = 0;
    unsigned int scan_fail_file_stat_count = 0;

    unsigned int cold_file_area_for_file_stat = 0;
    unsigned int file_stat_count_in_cold_list = 0;
    unsigned int serial_file_area = 0;
    LIST_HEAD(file_stat_list_temp);
    //暂存从hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head 链表链表尾扫描到的file_stat
    LIST_HEAD(global_file_stat_temp_head_list);

     /*必须要先从file_stat_temp_head或file_stat_temp_large_file_head隔离多个file_stat，然后去遍历这些file_stat上的file_area，这样只用开关一次hot_cold_file_global->global_lock锁.
      * 否则每遍历一个file_stat，都开关一次hot_cold_file_global->global_lock锁，太损耗性能。*/
    spin_lock(&p_hot_cold_file_global->global_lock);
    //先从global file_stat_temp_head链表尾隔离scan_file_stat_max个file_stat到 global_file_stat_temp_head_list 临时链表
    list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,file_stat_temp_head,hot_cold_file_list){
	//这里把file_stat 移动到 global_file_stat_temp_head_list 临时链表，用不用清理的file_stat的 in_file_stat_temp_head 标记，需要的。因为hot_file_update_file_status()
	//函数中会并发因为file_stat的 in_file_stat_temp_head 标记，而移动到file_stat的file_stat_hot_head链表，不能有这种并发操作
	if(!file_stat_in_file_stat_temp_head_list(p_file_stat))
	    panic("%s file_stat:0x%llx not int file_stat_temp_head status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
        else if(file_stat_in_delete(p_file_stat)){
	        scan_delete_file_stat_count ++;
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
    
	/*file_stat_temp_head来自 hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head 链表，当是hot_cold_file_global->file_stat_temp_large_file_head
	 * 时，file_stat_in_large_file(p_file_stat)才会成立*/

        //当file_stat上有些file_area长时间没有被访问则会释放掉file_are结构。此时原本在hot_cold_file_global->file_stat_temp_large_file_head 链表的大文件file_stat则会因
	//file_area数量减少而需要降级移动到hot_cold_file_global->file_stat_temp_head链表.这个判断起始可以放到hot_file_update_file_status()函数，算了降低损耗
	if(!is_file_stat_large_file(&hot_cold_file_global_info,p_file_stat) && file_stat_in_large_file(p_file_stat)){
	    if(open_shrink_printk)
	        printk("1:%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%lx not is_file_stat_large_file\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status);

	    scan_large_to_small_count ++;
            clear_file_stat_in_large_file(p_file_stat);
	    //不用现在把file_stat移动到global file_stat_temp_head链表。等该file_stat的file_area经过内存回收后，该file_stat会因为clear_file_stat_in_large_file而移动到file_stat_temp_head链表
	    //想了想，还是现在就移动到file_stat->file_stat_temp_head链表尾，否则内存回收再移动更麻烦。要移动到链表尾，这样紧接着就会从file_stat_temp_head链表链表尾扫描到该file_stat
	    list_move_tail(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);
	    continue;
	}
        if(p_file_stat->recent_access_age < p_hot_cold_file_global->global_age)
	    p_file_stat->recent_access_age = p_hot_cold_file_global->global_age;

	//需要设置这些file_stat不再处于file_stat_temp_head链表，否则之后hot_file_update_file_status()会因该file_stat的热file_area很多而移动到global file_stat_temp_head链表
	clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
        //扫描到的file_stat先移动到global_file_stat_temp_head_list临时链表，下边就开始遍历这些file_stat上的file_area
        list_move(&p_file_stat->hot_cold_file_list,&global_file_stat_temp_head_list);
	if(scan_file_stat_count ++ > scan_file_stat_max)
	    break;
    }
    spin_unlock(&p_hot_cold_file_global->global_lock);

    //在遍历hot_cold_file_global->file_stat_temp_head链表期间，可能创建了新文件并创建了file_stat并添加到hot_cold_file_global->file_stat_temp_head链表，
    //下边遍历hot_cold_file_global->file_stat_hot_head链表成员期间，是否用hot_cold_file_global_info.global_lock加锁？不用，因为遍历链表期间
    //向链表添加成员没事，只要不删除成员！想想我写的内存屏障那片文章讲解list_del_rcu的代码
    //list_for_each_entry_safe_reverse(p_file_stat,&p_hot_cold_file_global->file_stat_temp_head,hot_cold_file_list)//从链表尾开始遍历，链表尾的成员更老，链表头的成员是最新添加的
    list_for_each_entry_safe(p_file_stat,p_file_stat_temp,&global_file_stat_temp_head_list,hot_cold_file_list)//本质就是遍历p_hot_cold_file_global->file_stat_temp_head链表尾的file_stat
    {
	//此时file_stat已经在前边被清理in_file_stat_temp_head_list标记了，不应该再做这个判断
        //if(!file_stat_in_file_stat_temp_head_list(p_file_stat))
	//    panic("p_file_stat:0x%llx status:%d not in free_temp_list\n",(u64)p_file_stat,p_file_stat->file_stat_status);

	cold_file_area_for_file_stat = 0;
	serial_file_area = 0;
	//注意，这里扫描的global file_stat_temp_head上的file_stat肯定有冷file_area，因为file_stat只要50%的file_area是热的，file_stat就要移动到
	//global file_stat_hot_head 链表。
        list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_temp,file_area_list)//从链表尾开始遍历，链表尾的成员更老，链表头的成员是最新添加的
	{
	    if(!file_area_in_temp_list(p_file_area))
		panic("%s file_area:0x%llx status:%d not in file_area_temp\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

	    scan_file_area_count ++;
	    //本周期内，该p_file_area 依然没有被访问，移动到file_area_cold链表头
	    //if(p_file_area->area_access_count == p_file_area->last_access_count){
	    
            //file_area经过GOLD_FILE_AREA_LEVAL个周期还没有被访问，则被判定是冷file_area，然后就释放该file_area的page
	    if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > GOLD_FILE_AREA_LEVAL){
                //每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
	        spin_lock(&p_file_stat->file_stat_lock);
		//为什么file_stat_lock加锁后要再判断一次file_area是不是被访问了。因为可能有这种情况:上边的if成立，此时file_area还没被访问。但是此时有进程
		//先执行hot_file_update_file_status()获取file_stat_lock锁，然后访问当前file_area，file_area不再冷了。当前进程此时获取file_stat_lock锁失败。
		//等获取file_stat_lock锁成功后，file_area的file_area_age就和global_age相等了。一次，变量加减后的判断，在spin_lock前后各判断一次有必要的!!!!!!!!!!!!!!!!!!!!!!!!
                if(p_hot_cold_file_global->global_age - p_file_area->file_area_age <= GOLD_FILE_AREA_LEVAL){
		   spin_unlock(&p_file_stat->file_stat_lock);    
                   continue;
		}
	        //if(open_shrink_printk)
	        //    printk("2:%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%x p_file_area:0x%llx status:0x%x is cold file_area\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status,(u64)p_file_area,p_file_area->file_area_state);

                serial_file_area = 0;
		clear_file_area_in_temp_list(p_file_area);
		//设置file_area处于file_stat的free_temp_list链表。这里设定，不管file_area处于file_stat->file_area_free_temp还是file_stat->file_area_free
		//链表，都是file_area_in_free_list状态，没有必要再区分二者。主要设置file_area的状态需要遍历每个file_area并file_stat_lock加锁，
		//再多设置一次set_file_area_in_free_temp_list状态浪费性能。这点需注意!!!!!!!!!!!!!!!!!!!!!!!
		set_file_area_in_free_list(p_file_area);
		//需要加锁，此时可能有进程执行hot_file_update_file_status()并发向该p_file_area前或者后插入新的file_area，这里是把该p_file_area从file_area_temp链表剔除，存在同时修改该p_file_area在file_area_temp链表前的file_area结构的next指针和在链表后的file_area结构的prev指针，并发修改同一个变量就需要加锁。
                //list_move(&p_file_area->file_area_list,&p_file_stat->file_area_cold);
                list_move(&p_file_area->file_area_list,&p_file_stat->file_area_free_temp);
	        spin_unlock(&p_file_stat->file_stat_lock);
		//file_area_count_in_cold_list ++;
         #if  0
		/*1:把有冷file_area的file_stat移动到file_stat_free_list临时链表.此时的file_sata已经不在file_stat_temp_head链表，上边已经清理掉
		 *2:如果file_stat->file_area_refault链表非空，说明也需要扫描这上边的file_area，要把上边冷的file_area移动回file_stat_temp_head_list链表，参数内存回收扫描，结束保护期
		 *3:如果file_stat->file_area_free 和 file_stat->file_area_hot链表上也非空，说明上边也有file_area需要遍历，file_area_hot链表上的冷file_area需要移动回file_stat_temp_head_list链表，file_area_free链表上长时间没有被访问的file_area要释放掉file_area结构。
		 因此，file_stat->file_area_temp上有冷page，或者file_stat->file_area_refault、file_area_free、file_area_hot 链表只要非空，有file_area，都要把file_stat结构添加到file_stat_free_list临时链表。然后free_page_from_file_area()中依次扫描这些file_stat的file_area_free_temp、file_area_refault、file_area_free、file_area_hot链表上file_area，按照对应策略该干啥干啥
		 */
		//这个if会成立多次，导致同一个file_stat被list_move到file_stat_free_list链表多次，这样就是导致"list_add corruption. next->prev should be prev"而crash的原因吧
		//并且，这里只有file_stat->file_area_temp链表有冷file_area才会执行到，如果这个链表没有冷file_area，但是file_stat的file_area_free_temp、
		//file_area_refault、file_area_free、file_area_hot链表非空，就无法把file_stat添加到file_stat_free_list链表了，导致后续无法遍历该file_stat。解决方法放到外边。
		if(cold_file_area_for_file_stat == 0 || !list_empty(&p_file_stat->file_area_refault) ||
			!list_empty(&p_file_stat->file_area_free) || !list_empty(&p_file_stat->file_area_hot)){
		    //是否会存在并发设置p_file_stat->file_stat_status的情况??????????????? 这里没有加锁，需要考虑这点???????????????
		    //set_file_stat_in_head_temp_list(p_file_stat);
		    //这里不用加锁，此时p_file_stat是在 global_file_stat_temp_head_list临时链表，并且把p_file_stat移动到
		    //global cold_file_head链表，只在walk_throuth_all_file_area()函数单线程操作，不存在并发
		    //list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->cold_file_head);

		    list_move(&p_file_stat->hot_cold_file_list,file_stat_free_list);
		    file_stat_count_in_cold_list ++;
		}
         #endif
		cold_file_area_for_file_stat ++;
	    }
	    //else if(p_hot_cold_file_global->global_age == p_file_area->file_area_age)
	    else //否则就停止遍历file_stat->file_area_temp链表上的file_area，因为该链表上的file_area从左向右，访问频率由大向小递增，这个需要实际测试?????????????????????????
	    {
		//如果file_stat->file_area_temp链表尾连续扫到3个file_area都是热的，才停止扫描该file_stat上的file_area。因为此时file_stat->file_area_temp链表尾
		//上的file_area可能正在被访问，file_area->file_area_age=hot_cold_file_global->global_age，但是file_area还没被移动到file_stat->file_area_temp链表头。
		//这个判断是为了过滤掉这种瞬时的热file_area干扰
		if(serial_file_area ++ > 2)
   		    break;
	    }
	}
	
	/*1:cold_file_area_for_file_stat != 0表示把有冷file_area的file_stat移动到file_stat_free_list临时链表.此时的file_sata已经不在file_stat_temp_head链表，不用clear_file_stat_in_file_stat_temp_head_list
         *2:如果file_stat->file_area_refault链表非空，说明也需要扫描这上边的file_area，要把上边冷的file_area移动回file_stat_temp_head_list链表，参数内存回收扫描，结束保护期
	  *3:如果file_stat->file_area_free 和 file_stat->file_area_hot链表上也非空，说明上边也有file_area需要遍历，file_area_hot链表上的冷file_area需要移动回file_stat_temp_head_list链表，file_area_free链表上长时间没有被访问的file_area要释放掉file_area结构。

          因此，file_stat->file_area_temp上有冷page，或者file_stat->file_area_refault、file_area_free、file_area_hot 链表只要非空，有file_area，
	  都要把file_stat结构添加到file_stat_free_list临时链表。然后free_page_from_file_area()中依次扫描这些file_stat的file_area_free_temp、file_area_refault、
	  file_area_free、file_area_hot链表上file_area，按照对应策略该干啥干啥。

	  这段代码是从上边的for循环移动过来的，放到这里是保证同一个file_stat只list_move到file_stat_free_list链表一次。并且，当file_stat->file_area_temp链表没有冷file_area
	  或者没有一个file_area时，但是file_stat的file_area_free_temp、file_area_refault、file_area_free、file_area_hot链表上file_area要遍历，这样也要把
	  该file_stat移动到file_stat_free_list链表，这样将来free_page_from_file_area()函数中才能从file_stat_free_list链表扫描到该file_stat，否则会出现一些问题，比如
	  file_stat的file_area_free链表上长时间没访问的file_stat无法遍历到，无法释放这些file_stat结构；还有 file_stat的file_area_refault和file_area_hot
	  链表上的冷file_area无法降级移动到file_stat->file_area_temp链表，这些file_stat将无法扫描到参与内存回收
        */
	if(cold_file_area_for_file_stat != 0 || !list_empty(&p_file_stat->file_area_refault) ||
			!list_empty(&p_file_stat->file_area_free) || !list_empty(&p_file_stat->file_area_hot)){
	    list_move(&p_file_stat->hot_cold_file_list,file_stat_free_list);
            //移动到file_stat_free_list链表头的file_stat个数
            file_stat_count_in_cold_list ++;
	}
	//累计遍历到的冷file_area个数
        scan_cold_file_area_count += cold_file_area_for_file_stat;

        //防止在for循环耗时太长，限制遍历的文件file_stat数。这里两个问题 问题1:单个file_stat上的file_area太多了，只扫描一个file_stat这里就
	//break跳出循环了。这样下边就把global_file_stat_temp_head_list残留的file_stat移动到global file_stat_temp_head链表头了。下轮扫描从
	//global file_stat_temp_head尾就扫描不到该file_stat了。合理的做法是，把这些压根没扫描的file_stat再移动到global file_stat_temp_head尾。问题2：
	//还是 单个file_stat上的file_area太多了，没扫描完，下次再扫描该file_stat时，直接从上次结束的file_area位置处继续扫描，似乎更合理。
	//file_stat断点file_area继续扫描！但是实现起来似乎比较繁琐，算了
	if(scan_file_area_count > scan_file_area_max)
	    break;
    }
    //把global_file_stat_temp_head_list没遍历到的file_stat移动到global file_stat_temp_head链表头。这样做就保证本轮从global file_stat_temp_head尾扫到的
    //file_stat要么移动到了globa cold_file_head链表，要么移动到global file_stat_temp_head链表头。这样下轮从global file_stat_temp_head尾扫到的file_stat之前没扫描过。
    //错了！上边扫描的global file_stat_temp_head链表尾的file_stat肯定有冷file_area。因为file_stat只要50%的file_area是热的，file_stat就要移动到
    //global file_stat_hot_head 链表。global file_stat_temp_head链表上的file_stat肯定有file_area。这里还残留在global_file_stat_temp_head_list上的file_stat,
    //本轮就没有扫描到，因此要移动到global file_stat_temp_head链表尾，下轮扫描继续扫描这些file_stat
    if(!list_empty(&global_file_stat_temp_head_list)){

        spin_lock(&p_hot_cold_file_global->global_lock);
	//设置file_stat状态要加锁
	list_for_each_entry(p_file_stat,&global_file_stat_temp_head_list,hot_cold_file_list){
	    set_file_stat_in_file_stat_temp_head_list(p_file_stat);//设置file_stat状态为head_temp_list 
	    scan_fail_file_stat_count ++;
	}
	//set_file_stat_in_head_temp_list(p_file_stat);//不用再设置这些file_stat的状态，这些file_stat没有移动到global file_area_cold链表，没改变状态
        //list_splice(&global_file_stat_temp_head_list,&p_hot_cold_file_global->file_stat_temp_head);//移动到global file_stat_temp_head链表头
        //list_splice_tail(&global_file_stat_temp_head_list,&p_hot_cold_file_global->file_stat_temp_head);//移动到 global file_stat_temp_head链表尾
	
	//把未遍历的file_stat再移动回hot_cold_file_global->file_stat_temp_head或hot_cold_file_global->file_stat_temp_large_file_head 链表尾巴
        list_splice_tail(&global_file_stat_temp_head_list,file_stat_temp_head);//移动到 global file_stat_temp_head 或 file_stat_temp_large_file_head 链表尾
	
	//list_splice把前者的链表成员a1...an移动到后者链表，并不会清空前者链表。必须INIT_LIST_HEAD清空前者链表，否则它一直指向之前的链表成员a1...an。后续再向该链表添加新成员
	//b1...bn。这个链表就指向的成员就有a1...an + b1...+bn。而此时a1...an已经移动到了后者链表，相当于前者和后者链表都指向了a1...an成员，这样肯定会出问题.
	//之前get_file_area_from_file_stat_list()函数报错"list_add corruption. next->prev should be prev"而crash估计就是这个原因!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	//INIT_LIST_HEAD(&p_file_stat->file_area_free_temp)//global_file_stat_temp_head_list是局部链表，不用清，只有全局变量才必须list_splice_tail后清空链表

        spin_unlock(&p_hot_cold_file_global->global_lock);
    }

    if(open_shrink_printk)
        printk("3:%s %s %d p_hot_cold_file_global:0x%llx scan_file_stat_count:%d scan_file_area_count:%d scan_cold_file_area_count:%d file_stat_count_in_cold_list:%d\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,scan_file_stat_count,scan_file_area_count,scan_cold_file_area_count,file_stat_count_in_cold_list);

    //扫描的file_area个数
    p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_file_area_count = scan_file_area_count;
    //扫描的file_stat个数
    p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_file_stat_count = scan_file_stat_count;
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
 * 1：释放file_stat_free_list链表上的file_stat的file_area_free_temp链表上冷file_area的page。释放这些page后，把这些file_area移动到file_stat->file_area_free链表头
 * 2：遍历file_stat_free_list链表上的file_stat的file_area_hot链表尾上的热file_area，如果长时间没有被访问，说明变成冷file_area了，则移动到file_stat->file_area_temp链表头
 * 3：遍历file_stat_free_list链表上的file_stat的file_area_free链表尾上的file_area，如果还是长时间没有被访问，则释放掉这些file_area结构
 * 4: 遍历file_stat_free_list链表上的file_stat的file_area_refault链表尾巴的file_area，如果长时间没有被访问，则移动到file_stat->file_area_temp链表头
 * 5: 把file_stat_free_list链表上的file_stat再移动回file_stat_temp_head链表(即global file_stat_temp_head或file_stat_temp_large_file_head)头，这样下轮walk_throuth_all_file_area()
 * 再扫描，从global file_stat_temp_head或file_stat_temp_large_file_head链表尾巴扫到的file_stat都是最近没有被扫描过的，避免重复扫描
 */
//file_stat_free_list链表上的file_stat来自本轮扫描从global file_stat_temp_head或file_stat_temp_large_file_head链表尾获取到的
//file_stat_temp_head是global file_stat_temp_head或file_stat_temp_large_file_head
unsigned long free_page_from_file_area(struct hot_cold_file_global *p_hot_cold_file_global,struct list_head * file_stat_free_list,struct list_head *file_stat_temp_head)
{
    struct file_stat * p_file_stat/*,*p_file_stat_temp*/;
    struct file_area *p_file_area,*p_file_area_temp;
    unsigned int cold_file_area_count;
    unsigned int free_pages = 0;
    unsigned int file_area_count;
    unsigned int isolate_lru_pages = 0;
    unsigned int file_area_refault_to_temp_list_count = 0;
    unsigned int file_area_free_count = 0;
    unsigned int file_area_hot_to_temp_list_count = 0;

    /*同一个文件file_stat的file_area对应的page，更大可能是属于同一个内存节点node，所以要基于一个个文件的file_stat来扫描file_area，避免频繁开关内存节点锁pgdat->lru_lock锁*/  

    //遍历file_stat_free_list临时链表上的file_stat，释放这些file_stat的file_stat->file_area_free_temp链表上的冷file_area的page
    list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list)
    {
	if(file_stat_in_file_stat_temp_head_list(p_file_stat) || file_stat_in_file_stat_hot_head_list(p_file_stat))
	    panic("%s file_stat:0x%llx in int file_stat_temp_head or file_stat_hot_head_list status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

        //对file_area_free_temp上的file_stat上的file_area对应的page进行隔离，隔离成功的移动到p_hot_cold_file_global->hot_cold_file_node_pgdat->pgdat_page_list对应内存节点链表上
        isolate_lru_pages += cold_file_isolate_lru_pages(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_free_temp);
	//这里真正释放p_hot_cold_file_global->hot_cold_file_node_pgdat->pgdat_page_list链表上的内存page
	free_pages += cold_file_shrink_pages(p_hot_cold_file_global);
	
	
	printk("1:%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%lx free_pages:%d\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status,free_pages);
   
        /*注意，file_stat->file_area_free_temp 和 file_stat->file_area_free 各有用处。file_area_free_temp保存每次扫描释放的page的file_area。
	  释放后把这些file_area移动到file_area_free链表，file_area_free保存的是每轮扫描释放page的所有file_area，是所有的!!!!!!!!!!!!!!*/

	//p_file_stat->file_area_free_temp上的file_area的冷内存page释放过后,则把file_area_free_temp链表上的file_area结构再移动到file_area_free链表头，
	//file_area_free链表上的file_area结构要长时间也没被访问就释放掉
        if(!list_empty(&p_file_stat->file_area_free_temp)){
	    //hot_file_update_file_status()函数中会并发把file_area从file_stat->file_area_free_temp链表移动到file_stat->file_area_free_temp链表.
	    //这里把file_stat->file_area_free_temp链表上的file_area移动到file_stat->file_area_free，需要加锁
	    spin_lock(&p_file_stat->file_stat_lock);

            list_splice(&p_file_stat->file_area_free_temp,&p_file_stat->file_area_free);
	    //list_splice把前者的链表成员a1...an移动到后者链表，并不会清空前者链表。必须INIT_LIST_HEAD清空前者链表，否则它一直指向之前的链表成员a1...an。后续再向该链表添加新成员
	    //b1...bn。这个链表就指向的成员就有a1...an + b1...+bn。而此时a1...an已经移动到了后者链表，相当于前者和后者链表都指向了a1...an成员，这样肯定会出问题.
	    //之前get_file_area_from_file_stat_list()函数报错"list_add corruption. next->prev should be prev"而crash估计就是这个原因!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	    INIT_LIST_HEAD(&p_file_stat->file_area_free_temp);

	    spin_unlock(&p_file_stat->file_stat_lock);
        }
    }
    //需要调度的话休眠一下
    cond_resched();
    
    /*这里有个隐藏很深但很重要的问题：在walk_throuth_all_file_area()内存回收过程执行到该函数，把file_area移动到了file_stat->file_area_free_temp
     *或者file_stat->file_area_free链表后，此时hot_file_update_file_status()函数中又访问到这些file_area了，怎么办？这种情况完全有可能！
     *为了减少spin_lock(&p_file_stat->file_stat_lock)锁的使用。目前设定只有file_area在file_stat的file_area_hot、file_area_temp、file_area_temp_large
     *这3个有关的链表之间移动来移动去时，才会使用spin_lock(&p_file_stat->file_stat_lock)。file_area从file_stat->file_area_free_temp移动到
     *file_stat->file_area_free链表上是没有解锁的！
     
     *如果file_area移动到了file_stat->file_area_free_temp或者file_stat->file_area_free链表后，此时hot_file_update_file_status()函数中又访问到这些file_area了，
     *如果直接hot_file_update_file_status()函数中把这些file_area直接移动到file_stat的file_area_temp链表，那就又得spin_lock(&p_file_stat->file_stat_lock)
     *加锁了，并且file_area从file_stat->file_area_free_temp移动到file_stat->file_area_free链表也得file_stat_lock加锁。可以这样吗??????????
     *最后妥协了，就这样改吧。但是允许 hot_file_update_file_status()函数把file_area从file_stat->file_area_free_temp或file_area_free链表移动到
     *file_stat的file_area_temp链表后。hot_file_update_file_status()函数移动时需要spin_lock(&p_file_stat->file_stat_lock)加锁，
     *该函数中把file_area从file_stat->file_area_free_temp移动到file_stat->file_area_free，也需要file_stat_lock加锁；并且，从file_stat->file_area_free
     *释放长时间没有被访问的file_area时，也需要file_stat_lock加锁!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
     */

    //遍历file_stat_free_list临时链表上的file_stat，然后遍历着这些file_stat->file_area_hot链表尾巴上热file_area。这些file_area之前被判定是热file_area
    //而被移动到了file_stat->file_area_hot链表。之后，file_stat->file_area_hot链表头的file_area访问频繁，链表尾巴的file_area就会变冷。则把这些
    //file_stat->file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->file_area_temp链表头
    list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list){
        cold_file_area_count = 0;
        list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_hot,file_area_list){
	    if(!file_area_in_hot_list(p_file_area))
		panic("%s file_area:0x%llx status:%d not in file_area_hot\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

	    //file_stat->file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->file_area_temp链表头
            if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > GOLD_FILE_AREA_LEVAL + 3){
		cold_file_area_count = 0;
	        //if(open_shrink_printk)
	        //    printk("2:%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%x p_file_area:0x%llx status:0x%x in file_stat->file_area_hot\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status,(u64)p_file_area,p_file_area->file_area_state);

		file_area_hot_to_temp_list_count ++;
                //每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
	        spin_lock(&p_file_stat->file_stat_lock);
		clear_file_area_in_hot_list(p_file_area);
		//file_stat的热file_area个数减1
		p_file_stat->file_area_hot_count --;
		set_file_area_in_temp_list(p_file_area);
	        list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
                spin_unlock(&p_file_stat->file_stat_lock);	    
	    }else{//到这里，file_area被判定还是热file_area，还是继续存在file_stat->file_area_hot链表

	//如果file_stat->file_area_hot尾巴上连续出现2个file_area还是热file_area，则说明file_stat->file_area_hot链表尾巴上的冷file_area都遍历完了,遇到链表头的热
	//file_area了，则停止遍历。file_stat->file_area_hot链表头到链表尾，file_area是由热到冷顺序排布的。之所以要限制连续碰到两个热file_area再break，是因为file_stat->
	//file_area_hot尾巴上的冷file_area可能此时hot_file_update_file_status()中并发被频繁访问，变成热file_area，但还没来得及移动到file_stat->file_area_hot链表头
	        if(cold_file_area_count ++ > 1)
		    break;
	    }
	}
    }
     
    //需要调度的话休眠一下
    cond_resched();
   
    //遍历file_stat_free_list临时链表上的file_stat，然后看这些file_stat的file_area_free链表上的哪些file_area长时间未被访问，抓到的话就释放掉file_area结构
    //如果file_stat->file_area_free链表上有很多file_area导致这里遍历时间很长怎么办？需要考虑一下??????????????????????????
    list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list){
	file_area_count = 0;
	list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_free,file_area_list){
       	    //由于这个过程没有spin_lock(&p_file_stat->file_stat_lock)加锁，file_area可能正在被访问，清理的file_area_in_free_list标记，并设置了file_area_in_hot_list或
	    //file_area_in_temp_list标记，但是file_area还没移动到file_stat的file_area_temp或file_area_hot链表。此时if(!file_area_in_free_list(p_file_area))成立，
	    //但这是正常现象。如果file_area_free链表上file_stat又被访问了，则在hot_file_update_file_status()函数中再被移动到p_file_stat->file_area_temp链表
	    if(!file_area_in_free_list(p_file_area)){
		printk("%s file_area:0x%llx status:0x%x not in file_area_free !!!!!!!!!!!!\n",__func__,(u64)p_file_area,p_file_area->file_area_state);
		continue;
            }
	    //如果file_stat->file_area_free链表上的file_area长时间没有被访问则释放掉file_area结构
            if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > GOLD_FILE_AREA_LEVAL + 5){
                file_area_free_count ++;
	        //if(open_shrink_printk)
	        //    printk("3:%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%x p_file_area:0x%llx status:0x%x in file_stat->file_area_free\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status,(u64)p_file_area,p_file_area->file_area_state);
		file_area_count = 0;
	        //hot_file_update_file_status()函数中会并发把file_area从file_stat->file_area_free链表移动到file_stat->file_area_free_temp链表.
	        //这里把file_stat->file_area_free链表上的file_area剔除掉并释放掉，需要spin_lock(&p_file_stat->file_stat_lock)加锁，这个函数里有加锁
	        cold_file_area_detele(p_hot_cold_file_global,p_file_stat,p_file_area);
	    }else{
		//如果file_stat->file_area_free链表尾连续出现3个file_area未达到释放标准,说明可能最近被访问过，则结束遍历该file_stat->file_area_free上的file_area
		//这是防止遍历耗时太长，并且遍历到本轮扫描添加到file_stat->file_area_free上的file_area，浪费
	        if(file_area_count ++ > 2)
		    break;
	    }
	}
    }

    //遍历 file_stat_free_list临时链表上的file_stat，然后看这些file_stat的file_area_refault链表上的file_area，如果长时间没有被访问，
    //则要移动到file_stat->file_area_temp链表
    list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list){
	file_area_count = 0;
        list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_refault,file_area_list){
	    if(!file_area_in_refault_list(p_file_area))
		panic("%s file_area:0x%llx status:%d not in file_area_refault\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

	    //file_stat->file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->file_area_temp链表头
            if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > GOLD_FILE_AREA_LEVAL + 3){
		file_area_refault_to_temp_list_count ++;
	        //if(open_shrink_printk)
	        //    printk("4:%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%x p_file_area:0x%llx status:0x%x in file_stat->file_area_refault\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status,(u64)p_file_area,p_file_area->file_area_state);

		file_area_count = 0;
                //每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
	        spin_lock(&p_file_stat->file_stat_lock);
		clear_file_area_in_refault_list(p_file_area);
		set_file_area_in_temp_list(p_file_area);
		/*if(file_stat_in_large_file(p_file_stat))
                    list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_large_file_head);
		else
                    list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);*/
		list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
                spin_unlock(&p_file_stat->file_stat_lock);	    
	    }else{
	//如果file_stat->file_area_refault尾巴上连续出现2个file_area还是热file_area，则说明file_stat->file_area_hot链表尾巴上的冷file_area都遍历完了,遇到链表头的热
	//file_area了，则停止遍历。file_stat->file_area_refault链表头到链表尾，file_area是由热到冷顺序排布的。之所以要限制连续碰到两个热file_area再break，是因为file_stat->
	//file_area_refault尾巴上的冷file_area可能此时hot_file_update_file_status()中并发被频繁访问，变成热file_area，但还没来得及移动到file_area_refault链表头
	        if(file_area_count ++ >2)
		    break;
	    }
	}
    }
   
    /*-------这是遍历全局hot_cold_file_global->file_stat_hot_head上的file_stat，不遍历file_stat_free_list上的file_stat，不应该放在这里
    //遍历hot_cold_file_global->file_stat_hot_head链表上的热文件file_stat，如果哪些file_stat不再是热文件，再要把file_stat移动回global->file_stat_temp_head或file_stat_temp_large_file_head链表
    list_for_each_entry(p_file_stat,p_hot_cold_file_global->file_stat_hot_head,hot_cold_file_list){
	    //file_stat不再是热文件则移动回hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head链表
	    if(!is_file_stat_hot_file(p_hot_cold_file_global,p_file_stat)){
	        clear_file_area_in_hot_list(p_file_stat);
	        set_file_stat_in_file_stat_temp_head_list(p_file_stat);//设置file_stat状态为in_head_temp_list
		if(file_stat_in_large_file(p_file_stat))
                    list_move(&p_file_stat->hot_cold_file_list,p_hot_cold_file_global->file_stat_temp_head);
		else
                    list_move(&p_file_stat->hot_cold_file_list,p_hot_cold_file_global->file_stat_temp_large_file_head);
	    }
        }
    }*/

    //需要调度的话休眠一下
    cond_resched();

    //把file_stat_free_list临时链表上释放过内存page的file_stat再移动回global file_stat_temp_head或file_stat_temp_large_file_head链表头
    if(!list_empty(file_stat_free_list)){
        spin_lock(&p_hot_cold_file_global->global_lock);
        list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list){
            set_file_stat_in_file_stat_temp_head_list(p_file_stat);//设置file_stat状态为in_head_temp_list
        }
	//把这些遍历过的file_stat移动回global file_stat_temp_head或file_stat_temp_large_file_head链表头,注意是链表头。这是因为，把这些遍历过的file_stat移动到 
	//global file_stat_temp_head或file_stat_temp_large_file_head链表头，下轮扫描才能从global file_stat_temp_head或file_stat_temp_large_file_head链表尾遍历没有遍历过的的file_stat
        list_splice(file_stat_free_list,file_stat_temp_head);//file_stat_temp_head来自 global file_stat_temp_head或file_stat_temp_large_file_head链表
	
	//list_splice把前者的链表成员a1...an移动到后者链表，并不会清空前者链表。必须INIT_LIST_HEAD清空前者链表，否则它一直指向之前的链表成员a1...an。后续再向该链表添加新成员
	//b1...bn。这个链表就指向的成员就有a1...an + b1...+bn。而此时a1...an已经移动到了后者链表，相当于前者和后者链表都指向了a1...an成员，这样肯定会出问题.
	//之前get_file_area_from_file_stat_list()函数报错"list_add corruption. next->prev should be prev"而crash估计就是这个原因!!!!!!!!!!!!!!!!!!!!!!!!!!!!
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

    if(open_shrink_printk)
    	printk("5:%s %s %d p_hot_cold_file_global:0x%llx free_pages:%d isolate_lru_pages:%d file_stat_temp_head:0x%llx file_area_free_count:%d file_area_refault_to_list_temp_count:%d file_area_hot_to_temp_list_count:%d\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,free_pages,isolate_lru_pages,(u64)file_stat_temp_head,file_area_free_count,file_area_refault_to_temp_list_count,file_area_hot_to_temp_list_count);
    return free_pages;
}
static void printk_shrink_param(struct hot_cold_file_global *p_hot_cold_file_global)
{
    struct hot_cold_file_shrink_counter *p = &p_hot_cold_file_global->hot_cold_file_shrink_counter;

    printk("scan_file_area_count:%d scan_file_stat_count:%d scan_delete_file_stat_count:%d scan_cold_file_area_count:%d scan_large_to_small_count:%d scan_fail_file_stat_count:%d file_area_refault_to_temp_list_count:%d file_area_free_count:%d file_area_hot_to_temp_list_count:%d---%d\n",p->scan_file_area_count,p->scan_file_stat_count,p->scan_delete_file_stat_count,p->scan_cold_file_area_count,p->scan_large_to_small_count,p->scan_fail_file_stat_count,p->file_area_refault_to_temp_list_count,p->file_area_free_count,p->file_area_hot_to_temp_list_count,p->file_area_hot_to_temp_list_count2);

    printk("isolate_lru_pages:%d del_file_stat_count:%d del_file_area_count:%d lock_fail_count:%d writeback_count:%d dirty_count:%d page_has_private_count:%d mapping_count:%d free_pages_count:%d free_pages_fail_count:%d scan_zero_file_area_file_stat_count:%d page_unevictable_count:%d\n",p->isolate_lru_pages,p->del_file_stat_count,p->del_file_area_count,p->lock_fail_count,p->writeback_count,p->dirty_count,p->page_has_private_count,p->mapping_count,p->free_pages_count,p->free_pages_fail_count,p->scan_zero_file_area_file_stat_count,p->page_unevictable_count);
}
/*
 *遍历global file_stat_zero_file_area_head链表上的file_stat，如果file_stat对应文件长时间不被访问杂释放掉file_stat。如果file_stat对应文件又被访问了，则把file_stat再移动回 gloabl file_stat_temp_head、file_stat_temp_large_file_head、file_stat_hot_head链表
 * */
static void file_stat_has_zero_file_area_manage(struct hot_cold_file_global *p_hot_cold_file_global)
{
    struct file_stat * p_file_stat,*p_file_stat_temp;
    unsigned int scan_file_stat_max = 128,scan_file_stat_count = 0;
    unsigned int del_file_stat_count = 0;
    /*由于get_file_area_from_file_stat_list()向global file_stat_zero_file_area_head链表添加成员，这里遍历file_stat_zero_file_area_head链表成员，都是在
     * 异步内存回收线程进行的，不用spin_lock(&p_hot_cold_file_global->global_lock)加锁。除非要把file_stat_zero_file_area_head链表上的file_stat
     * 移动到 gloabl file_stat_temp_head、file_stat_temp_large_file_head、file_stat_hot_head链表。*/
    //向global  file_stat_zero_file_area_head添加成员是向链表头添加的，遍历则从链表尾巴开始遍历
    list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_zero_file_area_head,hot_cold_file_list){
	if(!file_stat_in_zero_file_area_list(p_file_stat))
	    panic("%s file_stat:0x%llx not in_zero_file_area_list status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
      
      if(scan_file_stat_count++ > scan_file_stat_max)
	  break;

      //如果file_stat对应文件长时间不被访问杂释放掉file_stat结构，这个过程不用spin_lock(&p_hot_cold_file_global->global_lock)加锁
      if(p_file_stat->file_area_count == 0 && p_hot_cold_file_global->global_age - p_file_stat->max_file_area_age > FILE_STAT_DELETE_AGE_DX){
	  cold_file_stat_delete(p_hot_cold_file_global,p_file_stat);
	  del_file_stat_count ++;
	  //0个file_area的file_stat个数减1
	  p_hot_cold_file_global->file_stat_count_zero_file_area --;
      }
      //如果p_file_stat->file_area_count大于0，说明最近被访问了，则把file_stat移动回 gloabl file_stat_temp_head、file_stat_temp_large_file_head、file_stat_hot_head链表
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
int walk_throuth_all_file_area(struct hot_cold_file_global *p_hot_cold_file_global)
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

    memset(&p_hot_cold_file_global->hot_cold_file_shrink_counter,0,sizeof(struct hot_cold_file_shrink_counter));

    scan_file_stat_max = 10;
    scan_file_area_max = 1024;
    //遍历hot_cold_file_global->file_stat_temp_large_file_head链表尾巴上边的大文件file_stat，然后遍历这些大文件file_stat的file_stat->file_area_temp链表尾巴上的file_area，被判定是冷的
    //file_area则移动到file_stat->file_area_free_temp链表。把有冷file_area的file_stat移动到file_stat_free_list_from_head_temp_large临时链表。返回值是遍历到的冷file_area个数
    scan_cold_file_area_count += get_file_area_from_file_stat_list(p_hot_cold_file_global,scan_file_area_max,scan_file_stat_max, 
	                               &p_hot_cold_file_global->file_stat_temp_large_file_head,&file_stat_free_list_from_head_temp_large);
    //需要调度的话休眠一下
    cond_resched();
    scan_file_stat_max = 64;
    scan_file_area_max = 1024;
    //遍历hot_cold_file_global->file_stat_temp_head链表尾巴上边的小文件file_stat，然后遍历这些小文件file_stat的file_stat->file_area_temp链表尾巴上的file_area，被判定是冷的
    //file_area则移动到file_stat->file_area_free_temp链表。把有冷file_area的file_stat移动到file_stat_free_list_from_head_temp临时链表。返回值是遍历到的冷file_area个数
    scan_cold_file_area_count += get_file_area_from_file_stat_list(p_hot_cold_file_global,scan_file_area_max,scan_file_stat_max, 
	                               &p_hot_cold_file_global->file_stat_temp_head,&file_stat_free_list_from_head_temp);

    /*该函数主要有5个作用
 * 1：释放file_stat_free_list_from_head_temp_large链表上的file_stat的file_area_free_temp链表上冷file_area的page。释放这些page后，把这些file_area移动到file_stat->file_area_free链表头
 * 2：遍历file_stat_free_list_from_head_temp_large的file_area_hot链表尾上的热file_area，如果长时间没有被访问，说明变成冷file_area了，则移动到file_stat->file_area_temp链表头
 * 3：遍历file_stat_free_list_from_head_temp_large链表上的file_stat的file_area_free链表尾上的file_area，如果还是长时间没有被访问，则释放掉这些file_area结构
 * 4: 遍历file_stat_free_list_from_head_temp_large链表上的file_stat的file_area_refault链表尾巴的file_area，如果长时间没有被访问，则移动到file_stat->file_area_temp链表头
 * 5: 把file_stat_free_list_from_head_temp_large链表上的file_stat再移动回file_stat_temp_head链表(即global file_stat_temp_head或file_stat_temp_large_file_head)头，这样下轮walk_throuth_all_file_area()再扫描，从global file_stat_temp_head或file_stat_temp_large_file_head链表尾巴扫到的file_stat都是最近没有被扫描过的，避免重复扫描
 */
    nr_reclaimed =  free_page_from_file_area(p_hot_cold_file_global,&file_stat_free_list_from_head_temp_large,&p_hot_cold_file_global->file_stat_temp_large_file_head); 
    nr_reclaimed += free_page_from_file_area(p_hot_cold_file_global,&file_stat_free_list_from_head_temp,&p_hot_cold_file_global->file_stat_temp_head); 

    //遍历hot_cold_file_global->file_stat_hot_head链表上的热文件file_stat，如果哪些file_stat不再是热文件，再要把file_stat移动回global->file_stat_temp_head或file_stat_temp_large_file_head链表
    list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_hot_head,hot_cold_file_list){
	if(!file_stat_in_file_stat_hot_head_list(p_file_stat))
	    panic("%s file_stat:0x%llx not int file_stat_hot_head_list status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
    
	cold_file_area_count = 0;
	//遍历global->file_stat_hot_head上的热文件file_stat的file_area_hot链表上的热file_area，如果哪些file_area不再被访问了，则要把file_area移动回file_stat->file_area_temp链表。
	//同时令改文件的热file_area个数file_stat->file_area_hot_count减1
        list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat->file_area_hot,file_area_list){
	    //file_stat->file_area_hot尾巴上长时间未被访问的file_area再降级移动回file_stat->file_area_temp链表头
            if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > GOLD_FILE_AREA_LEVAL + 3){
		cold_file_area_count = 0;
	        if(!file_area_in_hot_list(p_file_area))
		    panic("%s file_area:0x%llx status:%d not in file_area_hot\n",__func__,(u64)p_file_area,p_file_area->file_area_state);
	        //if(open_shrink_printk)
	        //    printk("2:%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%x p_file_area:0x%llx status:0x%x in file_stat->file_area_hot\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status,(u64)p_file_area,p_file_area->file_area_state);

		file_area_hot_to_temp_list_count ++;
                //每遍历到一个就加一次锁，浪费性能，可以先移动到一个临时链表上，循环结束后加一次锁，然后把这些file_area或file_stat移动到目标链表??????????????
	        spin_lock(&p_file_stat->file_stat_lock);
		p_file_stat->file_area_hot_count --;
		clear_file_area_in_hot_list(p_file_area);
		set_file_area_in_temp_list(p_file_area);
	        list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
                spin_unlock(&p_file_stat->file_stat_lock);	    
	    }else{//到这里，file_area被判定还是热file_area，还是继续存在file_stat->file_area_hot链表

	//如果file_stat->file_area_hot尾巴上连续出现2个file_area还是热file_area，则说明file_stat->file_area_hot链表尾巴上的冷file_area都遍历完了,遇到链表头的热
	//file_area了，则停止遍历。file_stat->file_area_hot链表头到链表尾，file_area是由热到冷顺序排布的。之所以要限制连续碰到两个热file_area再break，是因为file_stat->
	//file_area_hot尾巴上的冷file_area可能此时hot_file_update_file_status()中并发被频繁访问，变成热file_area，但还没来得及移动到file_stat->file_area_hot链表头
	        if(cold_file_area_count ++ > 1)
		    break;
	    }
	}
	if(open_shrink_printk)
	    printk("2:%s %s %d p_hot_cold_file_global:0x%llx p_file_stat:0x%llx status:0x%lx file_area_hot_count:%d file_area_count:%d file_area_hot_to_temp_list_count:%d\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,(u64)p_file_stat,p_file_stat->file_stat_status,p_file_stat->file_area_hot_count,p_file_stat->file_area_count,file_area_hot_to_temp_list_count);

	//该文件file_stat的热file_area个数file_stat->file_area_hot_count小于阀值，则被判定不再是热文件
	//然后file_stat就要移动回hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head链表
	if(!is_file_stat_hot_file(p_hot_cold_file_global,p_file_stat)){

            spin_lock(&p_hot_cold_file_global->global_lock);
	    hot_cold_file_global_info.file_stat_hot_count --;//热文件数减1
	    clear_file_stat_in_file_stat_hot_head_list(p_file_stat);
	    set_file_stat_in_file_stat_temp_head_list(p_file_stat);//设置file_stat状态为in_head_temp_list
	    if(file_stat_in_large_file(p_file_stat))
		list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_large_file_head);
	    else
		list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);
            spin_unlock(&p_hot_cold_file_global->global_lock);
	}
    }

    //遍历global file_stat_delete_head链表上已经被删除的文件的file_stat，
    //一次不能删除太多的file_stat对应的file_area，会长时间占有cpu，后期需要调优一下
    list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_delete_head,hot_cold_file_list){
	if(!file_stat_in_delete(p_file_stat))
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

    //打印所有file_stat的file_area个数和page个数
    hot_cold_file_print_all_file_stat(p_hot_cold_file_global);
    //打印内存回收时统计的各个参数
    printk_shrink_param(p_hot_cold_file_global);

    printk(">>>>>0x%llx global_age:%ld file_stat_count:%d file_stat_hot_count:%d file_stat_count_zero_file_area:%d free_pages:%ld<<<<<<\n",(u64)p_hot_cold_file_global,p_hot_cold_file_global->global_age,p_hot_cold_file_global->file_stat_count,p_hot_cold_file_global->file_stat_hot_count,p_hot_cold_file_global->file_stat_count_zero_file_area,nr_reclaimed);

    return 0;
}
//卸载该驱动时，先file_area_shrink_page_enable=0，确保所有的file_stat和file_area不再被进程访问后。就会执行该函数删除掉所有文件对应的file_stat，同时要把file_stat->mapping->rh_reserved1清0，
//否则等下次加载驱动，因为mapping->rh_reserved1非0，则直接把file_area添加到这个file_stat，但这个file_stat已经delete了，将发生crash
void cold_file_disable_file_stat_mapping(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat)
{
    //如果在对mapping->rh_reserved1赋值NULL时，这个文件inode被删除了，此时该文件inode的mapping将指向一片非法内存，因为mapp是inode的一个成员(struct address_space i_data)。
    //这个时间对mapping->rh_reserved1赋值将会导致对非法内存赋值呀!!!!!!!!!!!!怎么解决这个问题，与释放inode时执行的__destroy_inode_handler_post()函数进行并发处理。
    //该函数和__destroy_inode_handler_post()都会对p_file_stat->mapping->rh_reserved1清0

    /*这里有个并发操作很大的难题，释放inode时执行的__destroy_inode_handler_post()函数中在对mapping->rh_reserved1清0后，要 set_file_stat_in_delete(p_file_stat)设置p_file_stat的状态，
     * 但是如果此时cold_file_disable_file_stat_mapping()函数执行后，把p_file_stat释放了，__destroy_inode_handler_post()函数中执行set_file_stat_in_delete(p_file_stat)就会因p_file_stat无效
     * 而crash。同样的，__destroy_inode_handler_post()函数执行后，就会把inode给释放了，此时mapping就是无效的，如果此时cold_file_disable_file_stat_mapping()函数执行p_file_stat->mapping->rh_reserved1 = 0
     * 就会因mapping已经释放而对无效内存赋值，crash或者内存踩踏。要解决这种并发问题，用spin lock最简单，但是太影响性能。多加内存屏障smp_wmb()防护感觉逻辑有太乱。最后想了一个简单的方法。
     * cold_file_disable_file_stat_mapping()的执行时机是卸载驱动，卸载驱动时先file_area_shrink_page_enable = 0,然后smp_wmb()。然后__destroy_inode_handler_post()函数中，先smp_rmb()获取最新的
     * file_area_shrink_page_enable值，如果file_area_shrink_page_enable=0，则不再执行set_file_stat_in_delete(p_file_stat)。但是把inode释放后，再执行cold_file_disable_file_stat_mapping()
     * 还是会执行p_file_stat->mapping->rh_reserved1 = 0，此时还是会对mapping无效内存赋值，还是有问题。
     * 
     * */

    spin_lock(&p_hot_cold_file_global->global_lock);
    //if(p_file_stat->mapping->rh_reserved1) 不能通过p_file_stat->mapping->rh_reserved1是否0来判断file_stat的文件inode是否释放了，因为之后inode和mapping都是无效的
    if(p_file_stat->mapping){
        p_file_stat->mapping->rh_reserved1 = 0;
	//把最新的rh_reserved1赋值同步给其他cpu，主要设置同时给执行__destroy_inode_handler_post()函数的进程，告诉它p_file_stat->mapping->rh_reserved1已经清0了
	//smp_wmb();
    }
    spin_unlock(&p_hot_cold_file_global->global_lock);
}

//删除所有的file_stat和file_area，这个过程不加锁，因为提前保证了不再有进程访问file_stat和file_area
int cold_file_delete_all_file_stat(struct hot_cold_file_global *p_hot_cold_file_global)
{
    unsigned int del_file_area_count = 0,del_file_stat_count = 0;
    struct file_stat * p_file_stat,*p_file_stat_temp;


    //hot_cold_file_global->file_stat_delete_head链表
    list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->file_stat_delete_head,hot_cold_file_list){
	//标记 p_file_stat->mapping->rh_reserved1=0，表示该文件的file_stat已经释放了。否则，mapping->rh_reserved1保存的file_stat指针一直存在，等下次该文件
	//再被访问执行hot_file_update_file_status(),就会因为mapping->rh_reserved1非0，导致错误以为改文件的file_stat已经分配了，然后使用这个file_stat无效的导致crash
	cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
        del_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
	del_file_stat_count ++;
    }
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

    printk("hot_cold_file_global->cold_file_head del_file_area_count:%d del_file_stat_count:%d\n",del_file_area_count,del_file_stat_count);

    return 0;
}


static int hot_cold_file_thread(void *p){
    struct hot_cold_file_global *p_hot_cold_file_global = (struct hot_cold_file_global *)p;
    int sleep_count = 0;

    while(1){
	sleep_count = 0;
        while(sleep_count ++ < 10)
            msleep(1000);

	walk_throuth_all_file_area(p_hot_cold_file_global);
	if (kthread_should_stop())
	    break;
    }
    return 0;
}

int hot_cold_file_init(void)
{
    int node_count,i,ret;
    //hot_cold_file_global_info.file_stat_cachep = KMEM_CACHE(file_stat,0);
    hot_cold_file_global_info.file_stat_cachep = kmem_cache_create("file_stat",sizeof(struct file_stat),0,0,NULL);
    hot_cold_file_global_info.file_area_cachep = kmem_cache_create("file_area",sizeof(struct file_area),0,0,NULL);
    hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep = kmem_cache_create("hot_cold_file_area_tree_node",sizeof(struct hot_cold_file_area_tree_node),0,0,NULL);

    INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_hot_head);
    INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_temp_head);
    INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_temp_large_file_head);

    INIT_LIST_HEAD(&hot_cold_file_global_info.cold_file_head);
    INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_delete_head);
    INIT_LIST_HEAD(&hot_cold_file_global_info.file_stat_zero_file_area_head);
    spin_lock_init(&hot_cold_file_global_info.global_lock);

    atomic_set(&hot_cold_file_global_info.ref_count,0);
    atomic_set(&hot_cold_file_global_info.inode_del_count,0);

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
//在执行__destroy_inode_handler_post()能否休眠，万一上层调用者使用spin_lock锁咋办？得看看__destroy_inode()的上层调用者的代码
static void __destroy_inode_handler_post(struct kprobe *p, struct pt_regs *regs,
	                unsigned long flags)
{
    struct inode *inode = (struct inode *)(regs->di);
    if(inode && inode->i_mapping && inode->i_mapping->rh_reserved1){
        struct file_stat *p_file_stat = NULL;

	//如果驱动没有卸载
        if(test_bit(0,&file_area_shrink_page_enable))
	{
	    atomic_inc(&hot_cold_file_global_info.inode_del_count);

	    //如果该inode被地方后，不用立即把inode->mapping对应的file_stat立即加锁释放掉。因为即便这个inode被释放后立即又被其他进程分配，
	    //但分配后会先对inode清0，inode->mapping 和 inode->mapping->rh_reserved1 全是0，不会受inode->mapping->rh_reserved1指向的老file_stat结构的影响。只用异步内存回收线程
	    //里这个file_stat对应的hot file tree中的节点hot_cold_file_area_tree_node结构和该文件的所有file_area结构。
	    //smp_rmb();
	    //到这里时，可能cold_file_disable_file_stat_mapping()函数中已经把inode->i_mapping->rh_reserved1清0，因此需要smp_rmb()后再获取最新的inode->i_mapping->rh_reserved1值，判断是不是0
	    if(test_bit(0,&file_area_shrink_page_enable) && inode->i_mapping->rh_reserved1){
    
	       /*差点就犯的超隐藏错误!!!!!!!!!!!!!!!!!!cold_file_stat_delete()把file_stat从hot_cold_file_global的链表剔除，然后file_stat释放后，
	       //p_file_stat_del->hot_cold_file_list的next和prev就设置成LIST_POISON1/LIST_POISON2.之后能通过下边的if判断判定file_stat是否已经从
	       //hot_cold_file_global的链表剔除了吗？第一印象可以，但实际p_file_stat_del->hot_cold_file_list.next就会非法内存访问而crash，因为此时这file_stat结构体
	       //已经释放了，p_file_stat_del->hot_cold_file_list指向的这个结构体内存已经释放了，是无效内存!!!!!解决方法是，cold_file_stat_delete()释放file_stat前
	       //先把inode->i_mapping->rh_reserved1清0，然后这里看到inode->i_mapping->rh_reserved1是0就不再使用file_stat了*/
	     #if 0	
		//如果异步内存回收线程执行cold_file_stat_delete()已经把file_stat释放了，此时也会把file_stat从hot_cold_file_global的链表中剔除，该if成立，直接return
                if((p_file_stat_del->hot_cold_file_list.next == LIST_POISON1) || (p_file_stat_del->hot_cold_file_list.prev == LIST_POISON2)){
		    unlock_file_stat(p_file_stat);
		    return;
		}
            #else
		smp_rmb();
		//如果file_stat在cold_file_stat_delete()中被释放了，会把inode->i_mapping->rh_reserved1清0，这里不再使用file_stat
		if(0 == inode->i_mapping->rh_reserved1){
		    //p_file_stat->mapping = NULL;
		    //unlock_file_stat(p_file_stat);
		    return;
		}
            #endif		
	        p_file_stat = (struct file_stat *)(inode->i_mapping->rh_reserved1);
		//如果
                if(inode->i_mapping != p_file_stat->mapping){
		    unlock_file_stat(p_file_stat);
		    return;
		}

                /*把p_file_stat->mapping = NULL放到file_stat加锁前边，当该函数因cold_file_isolate_lru_pages()隔离page时先对file_stat加锁，导致这里加锁失败而休眠。
		但是先p_file_stat->mapping = NULL了，这样cold_file_isolate_lru_pages()见到p_file_stat->mapping是NULL，立即释放file_stat锁。但是想想又不对，
		p_file_stat->mapping=NULL和inode->i_mapping->rh_reserved1=0都放到加锁里,一起清0.p_file_stat->mapping是NULL才能代表
		inode->i_mapping->rh_reserved1是0。不仅有这个问题，如果p_file_stat->mapping = NULL赋值放到lock_file_stat加锁外边，可能cold_file_stat_delete()
		中，if(p_file_stat->mapping) p_file_stat->mapping->rh_reserved1 = 0,if因当前cpu还未获取p_file_stat->mapping最新值NULL而if成立，然后
		p_file_stat->mapping->rh_reserved1 = 0赋值时，p_file_stat->mapping是NULL生效了，此时就要crash*/
		//p_file_stat->mapping = NULL;
		
		//对file_stat加锁，此时异步内存回收线程会执行cold_file_stat_delete()释放file_stat结构，然后这里再使用file_stat就会crash了。必须等cold_file_stat_delete()
		//里释放完file_stat，然后把inode->i_mapping->rh_reserved1清0，释放file_stat锁后。这里才能继续运行，然后因为inode->i_mapping->rh_reserved1是0直接return
		lock_file_stat(p_file_stat);
               
		//xfs文件系统不会对新分配的inode清0，因此要主动对inode->i_mapping->rh_reserved1清0，防止该file_stat和inode被释放后。立即被其他进程分配了这个inode，但是没有对
		//inode清0，导致inode->i_mapping->rh_reserved1还保存着老的已经释放的file_stat，因为inode->i_mapping->rh_reserved1不是0，不对这个file_stat初始化，
		//然后把file_area添加到这个无效file_stat，就要crash。但是要把inode->i_mapping->rh_reserved1 = 0放到set_file_stat_in_delete(p_file_stat)
		//前边。否则的话，set_file_stat_in_delete(p_file_stat)标记file_stat的delete标记位后，file_stat不能再被用到，但是inode->i_mapping->rh_reserved1还不是0，
		//这样可能inode->i_mapping->rh_reserved1指向的file_stat还会被添加file_area，会出问题的，导致crash都有可能!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		inode->i_mapping->rh_reserved1 = 0;
		p_file_stat->mapping = NULL;
		//这里有个很大的隐患，此时file_stat可能处于global file_stat_hot_head、file_stat_temp_head、file_stat_temp_large_file_head 3个链表，这里突然设置set_file_stat_in_delete，
		//将来这些global 链表遍历这个file_stat，发现没有 file_stat_in_file_stat_hot_head等标记，会主动触发panic()。不对，set_file_stat_in_delete并不会清理原有的
		//file_stat_in_file_stat_hot_head等标记，杞人忧天了。
		set_file_stat_in_delete(p_file_stat);
		smp_wmb(); 

		unlock_file_stat(p_file_stat);
		printk("%s file_stat:0x%llx delete !!!!!!!!!!!!!!!!\n",__func__,(u64)p_file_stat);
	    }
	    else
	    {//到这个分支说明file_area_shrink_page_enable已经被驱动卸载并发清0了，那就goto file_stat_delete分支，择机把inode->i_mapping->rh_reserved1清0，保证这个inode被新的进程读写文件
	     //分配后，因文件访问执行hot_file_update_file_status()时，inode->i_mapping->rh_reserved1是0，则重新分配一个新的file_stat，否则会使用inode->i_mapping->rh_reserved1指向的老的已经释放的file_stat
	        atomic_dec(&hot_cold_file_global_info.inode_del_count);
	        goto file_stat_delete;
	    }
	    atomic_dec(&hot_cold_file_global_info.inode_del_count);
        }
	else
	//走这个分支，说明现在驱动在卸载。驱动卸载后时可能释放了file_stat结构，此时__destroy_inode_handler_post()就不能再使用了file_stat了，
	//比如"set_file_stat_in_delete(p_file_stat)"执行时就会导致crash。于是两个流程都spin_lock加锁防护并发操作
	{
file_stat_delete:

	    //这里不用再对file_stat加锁，因为cold_file_stat_delete()里把inode->i_mapping->rh_reserved1清0放到了spin lock加锁了，已经可以防止并发释放/使用 file_stat
	    //lock_file_stat(p_file_stat);

	    //在这个分支不用再 lock_file_stat加锁了，因为到这里，驱动开始卸载，异步内存回收线程不再运行，同时hot_cold_file_print_all_file_stat()禁止执行使用file_stat打印信息
	    //这个spin lock加锁是防止此时驱动卸载并发执行cold_file_stat_delete()释放file_stat结构，此时这里再使用file_stat就会crash
	    spin_lock(&hot_cold_file_global_info.global_lock);
	    //inode->i_mapping->rh_reserved1是0说明驱动卸载流程执行cold_file_stat_delete()释放了file_stat，把inode->i_mapping->rh_reserved1清0，这里不能再使用file_stat
	    if(0 == inode->i_mapping->rh_reserved1){
	        spin_unlock(&hot_cold_file_global_info.global_lock);
		return;
	    }
	    p_file_stat = (struct file_stat *)(inode->i_mapping->rh_reserved1);
	    if(inode->i_mapping->rh_reserved1 && inode->i_mapping == p_file_stat->mapping){

	        p_file_stat->mapping->rh_reserved1 = 0;
                //驱动卸载，释放file_stat时，遇到p_file_stat->mapping是NULL，就不再执行"p_file_stat->mapping->rh_reserved1 = 0"了，会crash
	        p_file_stat->mapping = NULL;
	        set_file_stat_in_delete(p_file_stat);
	    }
	    spin_unlock(&hot_cold_file_global_info.global_lock);
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
    ret = hot_cold_file_init();
    if(ret < 0){
        goto err;
    }
    return 0;
err:
    if(kp_mark_page_accessed.post_handler)
	unregister_kprobe(&kp_mark_page_accessed);

    if(kp__destroy_inode.post_handler)
	unregister_kprobe(&kp__destroy_inode);

    if(hot_cold_file_global_info.hot_cold_file_thead)
	kthread_stop(hot_cold_file_global_info.hot_cold_file_thead);

   return ret;
}
static void __exit async_memory_reclaime_for_cold_file_area_exit(void)
{ 
    //这里是重点，先等异步内存回收线程结束运行，就不会再使用任何的file_stat了，此时可以放心执行下边的cold_file_delete_all_file_stat()释放所有文件的file_stat
    kthread_stop(hot_cold_file_global_info.hot_cold_file_thead);

    //file_area_shrink_page_enable = 0;------改为使用 clear_bit()把file_area_shrink_page_enable清0，这样使用file_area_shrink_page_enable的地方不用再smp_rmb获取最新的file_area_shrink_page_enable值0
    //smp_wmb();
    clear_bit(0, &file_area_shrink_page_enable);//驱动卸载，把file_area_shrink_page_enable清0

    //如果还有进程在访问file_stat和file_area，p_hot_cold_file_global->ref_count大于0，则先休眠
    while(atomic_read(&hot_cold_file_global_info.ref_count)){
        msleep(10);
    }
    //如果有进程正在因inode删除而执行__destroy_inode_handler_post()里"set_file_stat_in_delete(p_file_stat)"的操作file_stat的代码，导致inode_del_count大于0，则等待退出
    while(atomic_read(&hot_cold_file_global_info.inode_del_count)){
        msleep(10);
    }

    cold_file_delete_all_file_stat(&hot_cold_file_global_info);
    unregister_kprobe(&kp_mark_page_accessed);
    unregister_kprobe(&kp__destroy_inode);
}
module_init(async_memory_reclaime_for_cold_file_area_init);
module_exit(async_memory_reclaime_for_cold_file_area_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hujunpeng : dongzhiyan_linux@163.com");
