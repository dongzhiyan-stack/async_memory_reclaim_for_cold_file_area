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


int open_shrink_printk = 1;
int open_shrink_printk1 = 0;
int hot_file_shrink_enable = 0;
void inline update_async_shrink_page(struct page *page);
int hot_file_init(void);
int hot_file_thread_enable = 0;
/***************************************************************/
struct scan_control_async {
	/* How many pages shrink_list() should reclaim */
	unsigned long nr_to_reclaim;

	/* This context's GFP mask */
	gfp_t gfp_mask;

	/* Allocation order */
	int order;

	/*
	 * Nodemask of nodes allowed by the caller. If NULL, all nodes
	 * are scanned.
	 */
	nodemask_t	*nodemask;

	/*
	 * The memory cgroup that hit its limit and as a result is the
	 * primary target of this reclaim invocation.
	 */
	struct mem_cgroup *target_mem_cgroup;

	/* Scan (total_size >> priority) pages at once */
	int priority;

	/* The highest zone to isolate pages for reclaim from */
	enum zone_type reclaim_idx;

	/* Writepage batching in laptop mode; RECLAIM_WRITE */
	unsigned int may_writepage:1;

	/* Can mapped pages be reclaimed? */
	unsigned int may_unmap:1;

	/* Can pages be swapped as part of reclaim? */
	unsigned int may_swap:1;

	/*
	 * Cgroups are not reclaimed below their configured memory.low,
	 * unless we threaten to OOM. If any cgroups are skipped due to
	 * memory.low and nothing was reclaimed, go back for memory.low.
	 */
	unsigned int memcg_low_reclaim:1;
	unsigned int memcg_low_skipped:1;

	unsigned int hibernation_mode:1;

	/* One of the zones is ready for compaction */
	unsigned int compaction_ready:1;

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
};
static int page_evictable(struct page *page)
{
	int ret;

	/* Prevent address_space of inode and swap cache from being freed */
	rcu_read_lock();
	ret = !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
	rcu_read_unlock();
	return ret;
}
static int __isolate_lru_page(struct page *page, isolate_mode_t mode)
{
	int ret = -EINVAL;

	/* Only take pages on the LRU. */
	if (!PageLRU(page))
		return ret;

	/* Compaction should not handle unevictable pages but CMA can do so */
	if (PageUnevictable(page) && !(mode & ISOLATE_UNEVICTABLE))
		return ret;

	ret = -EBUSY;

	/*
	 * To minimise LRU disruption, the caller can indicate that it only
	 * wants to isolate pages it will be able to operate on without
	 * blocking - clean pages for the most part.
	 *
	 * ISOLATE_ASYNC_MIGRATE is used to indicate that it only wants to pages
	 * that it is possible to migrate without blocking
	 */
	if (mode & ISOLATE_ASYNC_MIGRATE) {
		/* All the caller can do on PageWriteback is block */
		if (PageWriteback(page))
			return ret;

		if (PageDirty(page)) {
			struct address_space *mapping;
			bool migrate_dirty;

			/*
			 * Only pages without mappings or that have a
			 * ->migratepage callback are possible to migrate
			 * without blocking. However, we can be racing with
			 * truncation so it's necessary to lock the page
			 * to stabilise the mapping as truncation holds
			 * the page lock until after the page is removed
			 * from the page cache.
			 */
			if (!trylock_page(page))
				return ret;

			mapping = page_mapping(page);
			migrate_dirty = !mapping || mapping->a_ops->migratepage;
			unlock_page(page);
			if (!migrate_dirty)
				return ret;
		}
	}

	if ((mode & ISOLATE_UNMAPPED) && page_mapped(page))
		return ret;

	if (likely(get_page_unless_zero(page))) {
		/*
		 * Be careful not to clear PageLRU until after we're
		 * sure the page is not being freed elsewhere -- the
		 * page release code relies on it.
		 */
		ClearPageLRU(page);
		ret = 0;
	}

	return ret;
}


//这个函数直接从 __remove_mapping()复制过来
static int __remove_mapping(struct address_space *mapping, struct page *page,
			    bool reclaimed)
{
	unsigned long flags;
	int refcount;

	BUG_ON(!PageLocked(page));
	BUG_ON(mapping != page_mapping(page));

	xa_lock_irqsave(&mapping->i_pages, flags);
	/*
	 * The non racy check for a busy page.
	 *
	 * Must be careful with the order of the tests. When someone has
	 * a ref to the page, it may be possible that they dirty it then
	 * drop the reference. So if PageDirty is tested before page_count
	 * here, then the following race may occur:
	 *
	 * get_user_pages(&page);
	 * [user mapping goes away]
	 * write_to(page);
	 *				!PageDirty(page)    [good]
	 * SetPageDirty(page);
	 * put_page(page);
	 *				!page_count(page)   [good, discard it]
	 *
	 * [oops, our write_to data is lost]
	 *
	 * Reversing the order of the tests ensures such a situation cannot
	 * escape unnoticed. The smp_rmb is needed to ensure the page->flags
	 * load is not satisfied before that of page->_refcount.
	 *
	 * Note that if SetPageDirty is always performed via set_page_dirty,
	 * and thus under the i_pages lock, then this ordering is not required.
	 */
	if (unlikely(PageTransHuge(page)) && PageSwapCache(page))
		refcount = 1 + HPAGE_PMD_NR;
	else
		refcount = 2;
	if (!page_ref_freeze(page, refcount))
		goto cannot_free;
	/* note: atomic_cmpxchg in page_freeze_refs provides the smp_rmb */
	if (unlikely(PageDirty(page))) {
		page_ref_unfreeze(page, refcount);
		goto cannot_free;
	}
    #if 0 //本次内存回收只针对pagecache，不针对swap
	if (PageSwapCache(page)) {
		swp_entry_t swap = { .val = page_private(page) };
		mem_cgroup_swapout(page, swap);
		__delete_from_swap_cache(page);
		xa_unlock_irqrestore(&mapping->i_pages, flags);
		put_swap_page(page, swap);
	} else 
    #endif
	{
		void (*freepage)(struct page *);
		void *shadow = NULL;

		freepage = mapping->a_ops->freepage;
		/*
		 * Remember a shadow entry for reclaimed file cache in
		 * order to detect refaults, thus thrashing, later on.
		 *
		 * But don't store shadows in an address space that is
		 * already exiting.  This is not just an optizimation,
		 * inode reclaim needs to empty out the radix tree or
		 * the nodes are lost.  Don't plant shadows behind its
		 * back.
		 *
		 * We also don't store shadows for DAX mappings because the
		 * only page cache pages found in these are zero pages
		 * covering holes, and because we don't want to mix DAX
		 * exceptional entries and shadow exceptional entries in the
		 * same address_space.
		 */
		if (reclaimed && page_is_file_cache(page) &&
		    !mapping_exiting(mapping) && !dax_mapping(mapping))
			shadow = workingset_eviction(mapping, page);
		__delete_from_page_cache(page, shadow);
		xa_unlock_irqrestore(&mapping->i_pages, flags);

		if (freepage != NULL)
			freepage(page);
	}

	return 1;

cannot_free:
	xa_unlock_irqrestore(&mapping->i_pages, flags);
	return 0;
}

/*****************************************************************************************/
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
	    if(PageReclaim(page)){
	        nr_immediate++;
	    }
	    else{
	        SetPageReclaim(page);
	        nr_writeback++;
	    }
		if(open_shrink_printk)
		    printk("1:%s %s %d page:0x%llx page->flags:0x%lx PageWriteback;%d\n",__func__,current->comm,current->pid,(u64)page,page->flags,PageWriteback(page));
	    goto activate_locked;
	}

	/****page是脏页*********************/
	if (PageDirty(page)) {
		if(open_shrink_printk)
		    printk("9:%s %s %d page:0x%llx page->flags:0x%lx PageDirty;%d\n",__func__,current->comm,current->pid,(u64)page,page->flags,PageDirty(page));
                nr_dirty++;
	       
                //这个if成立禁止内存回收时刷脏页
	        /*if (page_is_file_cache(page) &&
		    (!current_is_kswapd() || !PageReclaim(page) ||
		     !test_bit(PGDAT_DIRTY, &pgdat->flags))) {

		     if(open_shrink_printk)
			    printk("10:%s %s %d page:0x%llx page->flags:0x%lx PageDirty ->activate_locked\n",__func__,current->comm,current->pid,(u64)page,page->flags);
			inc_node_page_state(page, NR_VMSCAN_IMMEDIATE);
			SetPageReclaim(page);

			goto activate_locked;
		}*/

		//if (references == PAGEREF_RECLAIM_CLEAN)
		//	goto keep_locked;
		if (!may_enter_fs)
			goto keep_locked;
		//if (!sc->may_writepage)
		//	goto keep_locked;

	
	 //这里是pageout()刷脏页，不同内核版本操作有差异，故先考虑注释掉，后续有需要再考虑吧，反正很快就会被脏页回写进程刷脏页
         #if 0
		switch (pageout(page, mapping, sc)) {
		case PAGE_KEEP:
			if(open_shrink_printk)
			    printk("12:%s %s %d page:0x%llx page->flags:0x%lx PageDirty ->keep_locked\n",__func__,current->comm,current->pid,(u64)page,page->flags);
			goto keep_locked;
		case PAGE_ACTIVATE:
			if(open_shrink_printk)
			    printk("13:%s %s %d page:0x%llx page->flags:0x%lx PageDirty ->activate_locked\n",__func__,current->comm,current->pid,(u64)page,page->flags);
			goto activate_locked;
		case PAGE_SUCCESS:
			if(open_shrink_printk)
			    printk("14:%s %s %d page:0x%llx page->flags:0x%lx PageDirty PageWriteback:%d PageDirty:%d PG_locked:%d\n",__func__,current->comm,current->pid,(u64)page,page->flags,PageWriteback(page),PageDirty(page),PageLocked(page));
			if (PageWriteback(page))
				goto keep;
			if (PageDirty(page))
				goto keep;

			if (!trylock_page(page))
				goto keep;
			if (PageDirty(page) || PageWriteback(page))
				goto keep_locked;
			mapping = page_mapping(page);
			if(open_shrink_printk)
			    printk("15:%s %s %d page:0x%llx page->flags:0x%lx \n",__func__,current->comm,current->pid,(u64)page,page->flags);
		case PAGE_CLEAN:
			if(open_shrink_printk)
			    printk("16:%s %s %d page:0x%llx page->flags:0x%lx PageDirty PAGE_CLEAN\n",__func__,current->comm,current->pid,(u64)page,page->flags);
			; /* try to free the page below */
		}

	   #endif	
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
        if (!mapping || !__remove_mapping(mapping, page, true)){
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
	     count_memcg_page_event(page, PGACTIVATE);
	}
keep_locked:
	unlock_page(page);
keep:
        list_add(&page->lru, &ret_pages);
    }
    mem_cgroup_uncharge_list(&free_pages);

    //这个try_to_unmap_flush()操作与页表页目录刷tlb有关，这里只会回收pagecache，故注释掉。主要是因为这个函数在 /mm/internal.h ,引用过来很兼容性不好 ########################
#if 0    
    try_to_unmap_flush();
#endif

    free_unref_page_list(&free_pages);

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
#if 0
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
int async_shirnk_update_file_status(struct *page){
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

#else
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
    //在cold_fiLe_head链表的file_stat个数
    //unsigned int file_stat_count_in_cold_list;
    unsigned int hot_file_count;
    unsigned int cold_file_count;
    unsigned long global_age;//每个周期加1
    struct kmem_cache *hot_file_stat_cachep;
    struct kmem_cache *hot_file_area_cachep;
    struct kmem_cache *hot_file_area_tree_node_cachep;
    spinlock_t hot_file_lock;
    struct hot_file_node_pgdat *p_hot_file_node_pgdat;
    struct task_struct *hot_file_thead;
    int node_count;
};
struct hot_file_global hot_file_global_info;
#endif

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
    if(p_hot_file_area_tree_node->slots[slot_number] != p_hot_file_area)
        panic("%s p_hot_file_area_tree_node->slots[%d]:0x%llx != p_hot_file_area:0x%llx\n",__func__,slot_number,(u64)p_hot_file_area_tree_node->slots[slot_number],(u64)p_hot_file_area);

    //从hot_file_area tree释放hot_file_area结构，同时也要从hot_file_area_list链表剔除，这个过程还要p_hot_file_stat->hot_file_stat_lock加锁
    list_del(&p_hot_file_area->hot_file_area_list);
    kmem_cache_free(p_hot_file_global->hot_file_area_cachep,p_hot_file_area);

    p_hot_file_area_tree_node->slots[slot_number] = NULL;
    p_hot_file_area_tree_node->count --;//父节点的子成员数减1

    //如果 p_hot_file_area_tree_node没有成员了，则释放p_hot_file_area_tree_node节点，并且向上逐层没有成员的hot_file_area_tree_node父节点
    while(p_hot_file_area_tree_node->count == 0){
        kmem_cache_free(p_hot_file_global->hot_file_area_tree_node_cachep,p_hot_file_area_tree_node);
        p_hot_file_area_tree_node = p_hot_file_area_tree_node->parent;
    }
    spin_unlock_irq(&p_hot_file_stat->hot_file_stat_lock);

    return 0;
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
    int ret = 0;
    struct hot_file_stat * p_hot_file_stat = NULL;
    struct hot_file_area *p_hot_file_area = NULL; 

    //mapping = page_mapping(page);-----这个针对swapcache也是返回非NULL，不能用
    mapping = hot_file_page_mapping(page);
    if(hot_file_shrink_enable && mapping && mapping->host && (hot_file_shrink_enable == mapping->host->i_sb->s_dev || hot_file_shrink_enable == mapping->host->i_sb->s_dev >> 20)){
        void **page_slot_in_tree = NULL;
	//page所在的hot_file_area的索引
	unsigned int area_index_for_page;
        struct hot_file_area_tree_node *parent_node;

	//如果两个进程同时访问同一个文件的page0和page1，这就就有问题了，因为这个if会同时成立。然后下边针对
	if(mapping->rh_reserved1 != 0){

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
		if(is_file_stat_hot_file(&hot_file_global_info,p_hot_file_stat)){
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
	            list_move(&p_hot_file_stat->hot_file_list,&hot_file_global_info.hot_file_head_temp_large);
                    spin_unlock(&hot_file_global_info.hot_file_lock);
		}
	    }
	     
	    if(open_shrink_printk && p_hot_file_area->area_access_count <= 3)
	        printk("%s %s %d p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x hot_file_area->area_access_count:%d hot_file_area->file_area_age:%lu page:0x%llx page->index:%ld file_area_hot_count:%d file_area_count:%d shrink_time:%d start_index:%ld page_slot_in_tree:0x%llx tree-height:%d parent_node->count:0x%llx\n",__func__,current->comm,current->pid,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state,p_hot_file_area->area_access_count,p_hot_file_area->file_area_age,(u64)page,page->index,p_hot_file_stat->file_area_hot_count,p_hot_file_stat->file_area_count,p_hot_file_area->shrink_time,p_hot_file_area->start_index,(u64)page_slot_in_tree,p_hot_file_stat->hot_file_area_tree_root_node.height,(u64)parent_node);
	   
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
    }

    return 0;

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
EXPORT_SYMBOL(hot_file_update_file_status);
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

    lruvec = mem_cgroup_lruvec(page->mem_cgroup, pgdat);
    lru = page_lru_base_type(page);

    /*__isolate_lru_page里清除page的PageLRU属性，因为要把page从lru链表剔除了，并且令page的引用计数加1*/
    switch (__isolate_lru_page(page, mode)) {
    case 0:
	    //nr_pages = hpage_nr_pages(page);
	    //nr_taken += nr_pages;
	    //nr_zone_taken[page_zonenum(page)] += nr_pages;
	    //page原本在lru链表，现在要移动到其他链表，要把page在链表的上一个page保存到async_shrink_page
	    //update_async_shrink_page(page);
	    //list_move(&page->lru, dst);

	    //把page从lru链表剔除，并减少page所属lru链表的page数
	    del_page_from_lru_list(page, lruvec, lru + PageActive(page));
	    //再把page添加到dst临时链表
	    list_add(&page->lru,dst);
	    return 0;

    case -EBUSY:
	    if(open_shrink_printk)
		printk("2:%s %s %d page:0x%llx page->flags:0x%lx EBUSY\n",__func__,current->comm,current->pid,(u64)page,page->flags);
	    break;

    default:
	if(open_shrink_printk)
	    printk("3:%s %s %d PageUnevictable:%d PageLRU:%d\n",__func__,current->comm,current->pid,PageUnevictable(page),PageLRU(page));

	    BUG();
    }
    
    /*更新 acitve/inactive file 链入链表的page数，减少nr_taken个，因为page将要从lru链表移除*/
    //update_lru_sizes(lruvec, lru, nr_zone_taken);------
    return -1;
}
//遍历p_hot_file_stat对应文件的hot_file_area_free链表上的hot_file_area结构，找到这些hot_file_area结构对应的page，这些page被判定是冷页，可以回收
static unsigned long hot_file_isolate_lru_pages(struct hot_file_global *p_hot_file_global,struct hot_file_stat * p_hot_file_stat,
	                               struct list_head *hot_file_area_free)
{
    struct hot_file_area *p_hot_file_area,*tmp_hot_file_area;
    int i;
    struct address_space *mapping = p_hot_file_stat->mapping;
    //unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
    isolate_mode_t mode = 0;
    pg_data_t *pgdat = NULL;
    struct page *page;
    unsigned int isolate_pages = 0;
    struct list_head *dst;
    
    list_for_each_entry_safe(p_hot_file_area,tmp_hot_file_area,hot_file_area_free,hot_file_area_list){
        if(open_shrink_printk)
	    printk("%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

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
    }
//err:    
    if(pgdat)
	spin_unlock_irq(&pgdat->lru_lock);

    return isolate_pages;
}
//static void putback_inactive_pages(struct lruvec *lruvec, struct list_head *page_list)
static void hot_file_putback_inactive_pages(struct pglist_data *pgdat, struct list_head *page_list)
{
	//struct pglist_data *pgdat = lruvec_pgdat(lruvec);
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
		if (unlikely(!page_evictable(page))) {
            //putback_lru_page()是mm/vmscan.c特有的函数，这里应用很麻烦。并且现在内存回收针对的是pagecache，这个if不会成立，故把这段代码注释掉####################
	    #if  0
			spin_unlock_irq(&pgdat->lru_lock);
			putback_lru_page(page);
			spin_lock_irq(&pgdat->lru_lock);
			continue;
	   #endif
		    panic("%s page:0x%llx not page_evictable:0x%lx\n",__func__,(u64)page,page->flags); 
		}
                /*怎么保证这些内存释放失败的page添加会原有的lru链表呢？page->mem_cgroup 是page锁绑定的memcg，再有memcg找到它的lruvec，完美*/
		lruvec = mem_cgroup_page_lruvec(page, pgdat);

		SetPageLRU(page);
		lru = page_lru(page);
		add_page_to_lru_list(page, lruvec, lru);

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
			del_page_from_lru_list(page, lruvec, lru);

			if (unlikely(PageCompound(page))) {
		            panic("%s page:0x%llx PageCompound:0x%lx\n",__func__,(u64)page,page->flags); 
			//get_compound_page_dtor()在ko里无法用，并且不回收PageCompound类型
			//page，因此这里的代码注释掉######################
                        #if 0
				spin_unlock_irq(&pgdat->lru_lock);
				mem_cgroup_uncharge(page);
				(*get_compound_page_dtor(page))(page);
				spin_lock_irq(&pgdat->lru_lock);
			#endif
			} else
				list_add(&page->lru, &pages_to_free);
		}
	}
        spin_unlock_irq(&pgdat->lru_lock);
	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	list_splice(&pages_to_free, page_list);
}

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
	.reclaim_idx = MAX_NR_ZONES - 1
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
	    mem_cgroup_uncharge_list(p_pgdat_page_list);
	    free_unref_page_list(p_pgdat_page_list);
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
                
		//把有冷hot_file_area的hot_file_stat移动到file_stat_free_list临时链表.此时的file_sata已经不在hot_file_head_temp链表，上边已经清理掉
		if(cold_file_area_for_file_stat == 0){
		    //是否会存在并发设置p_hot_file_stat->file_stat_status的情况??????????????? 这里没有加锁，需要考虑这点???????????????
		    //set_file_stat_in_head_temp_list(p_hot_file_stat);
		    //这里不用加锁，此时p_hot_file_stat是在 global_hot_file_head_temp_list临时链表，并且把p_hot_file_stat移动到
		    //global cold_file_head链表，只在walk_throuth_all_hot_file_area()函数单线程操作，不存在并发
		    //list_move(&p_hot_file_stat->hot_file_list,&p_hot_file_global->cold_file_head);

		    list_move(&p_hot_file_stat->hot_file_list,file_stat_free_list);
		    //本轮扫描移动到global cold_file_head链表头的file_stat个数
		    file_stat_count_in_cold_list ++;
		}

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
    unsigned int dec_hot_file_area = 0;

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
	        if(open_shrink_printk)
	            printk("2:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x in file_stat->hot_file_area_hot\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

		dec_hot_file_area ++;
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
	    if(!file_area_in_free_list(p_hot_file_area))
		panic("%s hot_file_area:0x%llx status:%d not in hot_file_area_free\n",__func__,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

	    //如果hot_file_stat->hot_file_area_free链表上的file_area长时间没有被访问则释放掉file_area结构
            if(p_hot_file_global->global_age - p_hot_file_area->file_area_age > GOLD_FILE_AREA_LEVAL + 5){

	        if(open_shrink_printk)
	            printk("3:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x in hot_file_stat->hot_file_area_free\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);
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
	        if(open_shrink_printk)
	            printk("4:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x p_hot_file_area:0x%llx status:0x%x in file_stat->hot_file_area_refault\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,(u64)p_hot_file_area,p_hot_file_area->file_area_state);

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
	spin_unlock_irq(&p_hot_file_global->hot_file_lock);
    }

    if(open_shrink_printk)
    	printk("5:%s %s %d p_hot_file_global:0x%llx free_pages:%d isolate_lru_pages:%d hot_file_head_temp:0x%llx  dec_hot_file_area:%d\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,free_pages,isolate_lru_pages,(u64)hot_file_head_temp,dec_hot_file_area);
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
    unsigned int dec_hot_file_area = 0;

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

		dec_hot_file_area ++;
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
	    printk("2:%s %s %d p_hot_file_global:0x%llx p_hot_file_stat:0x%llx status:0x%x file_area_hot_count:%d file_area_count:%d\n",__func__,current->comm,current->pid,(u64)p_hot_file_global,(u64)p_hot_file_stat,p_hot_file_stat->file_stat_status,p_hot_file_stat->file_area_hot_count,p_hot_file_stat->file_area_count);

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
    int node_count,i;
    //hot_file_global_info.hot_file_stat_cachep = KMEM_CACHE(hot_file_stat,0);
    hot_file_global_info.hot_file_stat_cachep = kmem_cache_create("hot_file_stat",sizeof(struct hot_file_stat),0,0,NULL);
    hot_file_global_info.hot_file_area_cachep = kmem_cache_create("hot_file_area",sizeof(struct hot_file_area),0,0,NULL);
    hot_file_global_info.hot_file_area_tree_node_cachep = kmem_cache_create("hot_file_area_tree_node",sizeof(struct hot_file_area_tree_node),0,0,NULL);

    INIT_LIST_HEAD(&hot_file_global_info.hot_file_head);
    INIT_LIST_HEAD(&hot_file_global_info.hot_file_head_temp);
    INIT_LIST_HEAD(&hot_file_global_info.hot_file_head_temp_large);

    INIT_LIST_HEAD(&hot_file_global_info.cold_file_head);
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
	pr_err("Failed to start  hot_file_thead\n");
	return -1;
    }
    return 0;
}
/*****************************************************************************************/
static struct kprobe kp_mark_page_accessed = {
    .symbol_name    = "mark_page_accessed",
};
static struct kprobe kp__destroy_inode = {
    .symbol_name    = "__destroy_inode",
};
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
    if(inode)
        printk("inode->i_ino:%ld\n",inode->i_ino);
}
static int __init async_memory_reclaime_for_cold_file_area_init(void)
{
    int ret;
    kp_mark_page_accessed.post_handler = mark_page_accessed_handler_post;
    kp__destroy_inode.post_handler = __destroy_inode_handler_post;

    
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
   return ret;
}
static void __exit async_memory_reclaime_for_cold_file_area_exit(void)
{ 
    unregister_kprobe(&kp_mark_page_accessed);
    unregister_kprobe(&kp__destroy_inode);
}
module_init(async_memory_reclaime_for_cold_file_area_init);
module_exit(async_memory_reclaime_for_cold_file_area_exit);
MODULE_LICENSE("GPL");
