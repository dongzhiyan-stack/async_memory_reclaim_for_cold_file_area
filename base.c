#include "base.h"
static struct kprobe kp_kallsyms_lookup_name = {
	.symbol_name    = "kallsyms_lookup_name",
};
static void kallsyms_lookup_name_handler_post(struct kprobe *p, struct pt_regs *regs,
		unsigned long flags)
{
}

struct hot_cold_file_global hot_cold_file_global_info;
//置1会把内存回收信息详细打印出来
int shrink_page_printk_open1 = 0;
//不怎么关键的调试信息
int shrink_page_printk_open = 0;
unsigned long async_memory_reclaim_status = 0;

static void iterate_supers_async(void);
/*************以下代码不同内核版本有差异******************************************************************************************/

/*******以下是红帽8.3 4.18.0-240内核针对内核原生内存回收函数在本ko驱动的适配********************************************/
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static int (*__isolate_lru_page_async)(struct page *page, isolate_mode_t mode);
static int (*page_evictable_async)(struct page *page);
static int (*__remove_mapping_async)(struct address_space *mapping, struct page *page,bool reclaimed);
static void (*mem_cgroup_update_lru_size_async)(struct lruvec *lruvec, enum lru_list lru,int zid, int nr_pages);
static struct lruvec *(*mem_cgroup_page_lruvec_async)(struct page *page, struct pglist_data *pgdat);
static void (*__mod_lruvec_state_async)(struct lruvec *lruvec, enum node_stat_item idx,int val);
void (*free_unref_page_list_async)(struct list_head *list);
void (*mem_cgroup_uncharge_list_async)(struct list_head *page_list);
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
static bool (*try_to_unmap_async)(struct page *page, enum ttu_flags flags);
int (*page_referenced_async)(struct page *page,int is_locked,struct mem_cgroup *memcg,unsigned long *vm_flags);

#ifdef USE_KERNEL_SHRINK_INACTIVE_LIST
static unsigned long (*shrink_page_list_async)(struct list_head *page_list,struct pglist_data *pgdat,struct scan_control_async *sc,enum ttu_flags ttu_flags,struct reclaim_stat *stat,bool force_reclaim);
static void (*putback_inactive_pages_async)(struct lruvec *lruvec, struct list_head *page_list);
#endif
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
static __always_inline void add_page_to_lru_list_tail_async(struct page *page,
		struct lruvec *lruvec, enum lru_list lru)
{
	update_lru_size_async(lruvec, lru, page_zonenum(page), hpage_nr_pages(page));
	list_add_tail(&page->lru, &lruvec->lists[lru]);
}
#ifndef USE_KERNEL_SHRINK_INACTIVE_LIST
//源码来自内核shrink_page_list()，但是针对pagecache内存回收简化很多,执行该函数回收内存的page大部分都是长时间未访问的clean pagecache
unsigned int async_shrink_free_page(struct pglist_data *pgdat,struct lruvec *lruvec,struct list_head *page_list,
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
			goto activate_locked;
		}
        
		/****page是mmap页*********************/
		if (page_mapped(page)){
			enum ttu_flags flags = TTU_BATCH_FLUSH;
			if (!try_to_unmap_async(page, flags)) {
				nr_unmap_fail++;
				goto activate_locked;
			}
		}
		//为了保证内存回收绝对准确，一定得做一些可能发生的异常限制
		if (PageTransHuge(page) || PageAnon(page) || PageSwapBacked(page))
			panic("%s page:0x%llx page->flags:0x%lx",__func__,(u64)page,page->flags);

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
	hot_cold_file_global_info.hot_cold_file_shrink_counter.nr_unmap_fail += nr_unmap_fail;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.writeback_count += writeback_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.dirty_count += dirty_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.page_has_private_count += page_has_private_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.mapping_count += mapping_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_count += nr_reclaimed;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_fail_count += free_pages_fail_count;

	return nr_reclaimed;
}
int __hot_cold_file_isolate_lru_pages(pg_data_t *pgdat,struct page * page,struct list_head *dst,isolate_mode_t mode)
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
unsigned int hot_cold_file_putback_inactive_pages(struct pglist_data *pgdat, struct list_head *page_list)
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

#else
/*以下代码是使用内核原生的内存回收源码，不再使用我自己写的，稳定为主*/

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
/*以下代码直接从内核复制过来*/
#ifdef ARCH_HAS_PREFETCHW
#define prefetchw_prev_lru_page(_page, _base, _field)			\
	do {								\
		if ((_page)->lru.prev != _base) {			\
			struct page *prev;				\
									\
			prev = lru_to_page(&(_page->lru));		\
			prefetchw(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetchw_prev_lru_page(_page, _base, _field) do { } while (0)
#endif
static __always_inline void update_lru_sizes_async(struct lruvec *lruvec,
			enum lru_list lru, unsigned long *nr_zone_taken)
{
	int zid;

	for (zid = 0; zid < MAX_NR_ZONES; zid++) {
		if (!nr_zone_taken[zid])
			continue;

		__update_lru_size_async(lruvec, lru, zid, -nr_zone_taken[zid]);
#ifdef CONFIG_MEMCG
		mem_cgroup_update_lru_size_async(lruvec, lru, zid, -nr_zone_taken[zid]);
#endif
	}

}
static unsigned long isolate_lru_pages_async(unsigned long nr_to_scan,
		struct lruvec *lruvec, struct list_head *dst,
		unsigned long *nr_scanned, struct scan_control_async *sc,
		isolate_mode_t mode, enum lru_list lru)
{
	struct list_head *src = &lruvec->lists[lru];
	unsigned long nr_taken = 0;
	unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
	unsigned long nr_skipped[MAX_NR_ZONES] = { 0, };
	unsigned long skipped = 0;
	unsigned long scan, total_scan, nr_pages;
	LIST_HEAD(pages_skipped);

	scan = 0;
	for (total_scan = 0;
	     scan < nr_to_scan && nr_taken < nr_to_scan && !list_empty(src);
	     total_scan++) {
		struct page *page;

		page = lru_to_page(src);
		prefetchw_prev_lru_page(page, src, flags);

		VM_BUG_ON_PAGE(!PageLRU(page), page);

		if (page_zonenum(page) > sc->reclaim_idx) {
			list_move(&page->lru, &pages_skipped);
			nr_skipped[page_zonenum(page)]++;
			continue;
		}

		/*
		 * Do not count skipped pages because that makes the function
		 * return with no isolated pages if the LRU mostly contains
		 * ineligible pages.  This causes the VM to not reclaim any
		 * pages, triggering a premature OOM.
		 */
		scan++;
		switch (__isolate_lru_page_async(page, mode)) {
		case 0:
			nr_pages = hpage_nr_pages(page);
			nr_taken += nr_pages;
			nr_zone_taken[page_zonenum(page)] += nr_pages;
			list_move(&page->lru, dst);
			break;

		case -EBUSY:
			/* else it is being freed elsewhere */
			list_move(&page->lru, src);
			continue;

		default:
			BUG();
		}
	}

	/*
	 * Splice any skipped pages to the start of the LRU list. Note that
	 * this disrupts the LRU order when reclaiming for lower zones but
	 * we cannot splice to the tail. If we did then the SWAP_CLUSTER_MAX
	 * scanning would soon rescan the same pages to skip and put the
	 * system at risk of premature OOM.
	 */
	if (!list_empty(&pages_skipped)) {
		int zid;

		list_splice(&pages_skipped, src);
		for (zid = 0; zid < MAX_NR_ZONES; zid++) {
			if (!nr_skipped[zid])
				continue;

			__count_zid_vm_events(PGSCAN_SKIP, zid, nr_skipped[zid]);
			skipped += nr_skipped[zid];
		}
	}
	*nr_scanned = total_scan;
#if 0	
	trace_mm_vmscan_lru_isolate(sc->reclaim_idx, sc->order, nr_to_scan,
				    total_scan, skipped, nr_taken, mode, lru);
#endif	
	update_lru_sizes_async(lruvec, lru, nr_zone_taken);
	return nr_taken;
}

/*现在对内存回收代码做了很大改进，就是使用内核原生内存回收函数isolate_lru_pages、shrink_page_list、putback_inactive_pages，不再使用自己编写的。
 *主要是出于稳定性考虑，毕竟使用内核原生的更稳定。这里主要有几点说下
  1:现在file_area内存回收以memory cgroup为主，参与内存回收的page都保证是一个lruvec的，因此可以直接使用内核内存回收原生的
    isolate_lru_pages、shrink_page_list、putback_inactive_pages函数了，不用再使用我编写的代码了
  2:可以直接kprobe内核shrink_inactive_list函数进行内存回收，这样就不用使用复制使用内核原生代码了。但是，shrink_inactive_list里的
    too_many_isolated()和lru_add_drain()函数就会执行到，影响到内存回收。还有很多冗余的统计代码。都要考虑
  3:最后，还有一个隐藏很深的知识点。首先cold_file_isolate_lru_pages_and_shrink函数里，把同一个lruvec的32个page移动到inactive lru链表尾，然后
    里边执行shrink_inactive_list_async函数隔离并释放掉刚才移动到lruvec的inactive lru链表尾的32个page。这里就有个问题，如果隔离这32个page前，
	其他进程把page移动到lruvec的inactive lru链表尾怎么办？完全有可能，这样的话，这里释放掉的32个page就不是同一个文件的文件页了，有了干扰page。
	但是情况没那么严重，因为 新的page添加到lru链表时，是添加到inactive lru链表头。active lru链表的page也是移动到inactive lru链表尾。只有
	有racliam标记的page在writeback完成后，才会移动到inactive lru链表尾。这种page本来就应该释放掉，只不过会被我的异步内存回收线程释放掉而已。
 */
static noinline_for_stack unsigned long
shrink_inactive_list_async(unsigned long nr_to_scan, struct lruvec *lruvec,
		     struct scan_control_async *sc, enum lru_list lru)
{
	LIST_HEAD(page_list);
	unsigned long nr_scanned;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_taken;
	struct reclaim_stat stat = {};
	isolate_mode_t isolate_mode = 0;
	int file = is_file_lru(lru);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
#if 0	
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	bool stalled = false;

	while (unlikely(too_many_isolated(pgdat, file, sc))) {
		if (stalled)
			return 0;

		/* wait a bit for the reclaimer. */
		msleep(100);
		stalled = true;

		/* We are about to die and free our memory. Return now. */
		if (fatal_signal_pending(current))
			return SWAP_CLUSTER_MAX;
	}

	lru_add_drain();
#endif
	if (!sc->may_unmap)
		isolate_mode |= ISOLATE_UNMAPPED;

	spin_lock_irq(&pgdat->lru_lock);

	nr_taken = isolate_lru_pages_async(nr_to_scan, lruvec, &page_list,
				     &nr_scanned, sc, isolate_mode, lru);
#if 0
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	reclaim_stat->recent_scanned[file] += nr_taken;

	if (current_is_kswapd()) {
		if (global_reclaim(sc))
			__count_vm_events(PGSCAN_KSWAPD, nr_scanned);
		count_memcg_events(lruvec_memcg(lruvec), PGSCAN_KSWAPD,
				   nr_scanned);
	} else {
		if (global_reclaim(sc))
			__count_vm_events(PGSCAN_DIRECT, nr_scanned);
		count_memcg_events(lruvec_memcg(lruvec), PGSCAN_DIRECT,
				   nr_scanned);
	}
#endif	
	spin_unlock_irq(&pgdat->lru_lock);

	if (nr_taken == 0)
		return 0;

	nr_reclaimed = shrink_page_list_async(&page_list, pgdat, sc, 0,
			    &stat, true);

	spin_lock_irq(&pgdat->lru_lock);
#if 0
	if (current_is_kswapd()) {
		if (global_reclaim(sc))
			__count_vm_events(PGSTEAL_KSWAPD, nr_reclaimed);
		count_memcg_events(lruvec_memcg(lruvec), PGSTEAL_KSWAPD,
				   nr_reclaimed);
	} else {
		if (global_reclaim(sc))
			__count_vm_events(PGSTEAL_DIRECT, nr_reclaimed);
		count_memcg_events(lruvec_memcg(lruvec), PGSTEAL_DIRECT,
				   nr_reclaimed);
	}
#endif	
	putback_inactive_pages_async(lruvec, &page_list);
#if 0
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
#endif
	spin_unlock_irq(&pgdat->lru_lock);

	mem_cgroup_uncharge_list_async(&page_list);
	free_unref_page_list_async(&page_list);
#if 0
	/*
	 * If dirty pages are scanned that are not queued for IO, it
	 * implies that flushers are not doing their job. This can
	 * happen when memory pressure pushes dirty pages to the end of
	 * the LRU before the dirty limits are breached and the dirty
	 * data has expired. It can also happen when the proportion of
	 * dirty pages grows not through writes but through memory
	 * pressure reclaiming all the clean cache. And in some cases,
	 * the flushers simply cannot keep up with the allocation
	 * rate. Nudge the flusher threads in case they are asleep.
	 */
	if (stat.nr_unqueued_dirty == nr_taken)
		wakeup_flusher_threads(WB_REASON_VMSCAN);
#endif
	sc->nr.dirty += stat.nr_dirty;
	sc->nr.congested += stat.nr_congested;
	sc->nr.unqueued_dirty += stat.nr_unqueued_dirty;
	sc->nr.writeback += stat.nr_writeback;
	sc->nr.immediate += stat.nr_immediate;
	sc->nr.taken += nr_taken;
	if (file)
		sc->nr.file_taken += nr_taken;
#if 0       
	trace_mm_vmscan_lru_shrink_inactive(pgdat->node_id,
			nr_scanned, nr_reclaimed, &stat, sc->priority, file);
#endif	
	return nr_reclaimed;
}
#else

#endif

#endif
/*******以下是红帽9.2 5.14.0-284.11.1内核针对内核原生内存回收函数在本ko驱动的适配********************************************/
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(5,14,0)
#ifdef USE_KERNEL_SHRINK_INACTIVE_LIST
static unsigned long (*isolate_lru_pages_async)(unsigned long nr_to_scan,struct lruvec *lruvec, struct list_head *dst,unsigned long *nr_scanned, struct scan_control_async *sc,enum lru_list lru);
static unsigned int (*shrink_page_list_async)(struct list_head *page_list,struct pglist_data *pgdat,struct scan_control_async *sc,struct reclaim_stat *stat,bool ignore_references);
static unsigned int (*move_pages_to_lru_async)(struct lruvec *lruvec,struct list_head *list);
#endif
static int(* __remove_mapping_async)(struct address_space *mapping, struct folio *folio,bool reclaimed, struct mem_cgroup *target_memcg);
static void (*mem_cgroup_update_lru_size_async)(struct lruvec *lruvec, enum lru_list lru,int zid, int nr_pages);
void (*free_unref_page_list_async)(struct list_head *list);
void mem_cgroup_uncharge_list_async(struct list_head *page_list);
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
void (*cache_random_seq_destroy_async)(struct kmem_cache *cachep);
static void (*try_to_unmap_async)(struct folio *folio, enum ttu_flags flags);
int (*page_referenced_async)(struct folio *folio, int is_locked,struct mem_cgroup *memcg, unsigned long *vm_flags);

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
void mem_cgroup_uncharge_list_async(struct list_head *page_list)
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
static __always_inline
void lruvec_add_folio_tail_async(struct lruvec *lruvec, struct folio *folio)
{
     enum lru_list lru = folio_lru_list(folio);

    update_lru_size_async(lruvec, lru, folio_zonenum(folio),folio_nr_pages(folio));
    /* This is not expected to be used on LRU_UNEVICTABLE */
    list_add_tail(&folio->lru, &lruvec->lists[lru]);
}
static __always_inline void add_page_to_lru_list_tail_async(struct page *page,
						struct lruvec *lruvec)
{
    lruvec_add_folio_tail_async(lruvec, page_folio(page));
}
struct lruvec *mem_cgroup_lruvec_async(struct mem_cgroup *memcg,
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

#ifndef USE_KERNEL_SHRINK_INACTIVE_LIST
static inline bool page_evictable_async(struct page *page)
{
	bool ret;
	rcu_read_lock();
	ret = !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
	rcu_read_unlock();
	return ret;
}
unsigned int async_shrink_free_page(struct pglist_data *pgdat,struct lruvec *lruvec,struct list_head *page_list,
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
	unsigned int nr_unmap_fail = 0;

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
#if 0	
		//强制不回收mmap的page
		if (/*!sc->may_unmap &&*/ page_mapped(page))
			goto keep_locked;
#endif
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
		
		/****page是mmap页*********************/
		if (page_mapped(page)){
			enum ttu_flags flags = TTU_BATCH_FLUSH;
			try_to_unmap_async(folio, flags);
			if (page_mapped(page)) {
				nr_unmap_fail++;
				goto activate_locked;
			}
		}
		//为了保证内存回收绝对准确，一定得做一些可能发生的异常限制
		if (PageTransHuge(page) || PageAnon(page) || PageSwapBacked(page))
			panic("%s page:0x%llx page->flags:0x%lx",__func__,(u64)page,page->flags);

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
	hot_cold_file_global_info.hot_cold_file_shrink_counter.nr_unmap_fail += nr_unmap_fail;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.writeback_count += writeback_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.dirty_count += dirty_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.page_has_private_count += page_has_private_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.mapping_count += mapping_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_count += nr_reclaimed;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_fail_count += free_pages_fail_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.page_unevictable_count += page_unevictable_count;

	return nr_reclaimed;
}
unsigned int hot_cold_file_putback_inactive_pages(struct pglist_data *pgdat, struct list_head *page_list)
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
int  __hot_cold_file_isolate_lru_pages(pg_data_t *pgdat,struct page * page,struct list_head *dst,isolate_mode_t mode)
{
	struct lruvec *lruvec;
	//int lru;

	//prefetchw_prev_lru_page(page, src, flags); 不需要

	if (!PageLRU(page))
		return -1;
	//源头已经确保page不是mmap的，这里不用重复判断。但是想想还是加上吧，因为怕page中途被设置成mmap了。
#if 0
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
static unsigned long
shrink_inactive_list_async(unsigned long nr_to_scan, struct lruvec *lruvec,
		     struct scan_control_async *sc, enum lru_list lru)
{
	LIST_HEAD(page_list);
	unsigned long nr_scanned;
	unsigned int nr_reclaimed = 0;
	unsigned long nr_taken;
	struct reclaim_stat stat;
	bool file = is_file_lru(lru);
#if 0	
	enum vm_event_item item;
#endif	
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
#if 0
	bool stalled = false;
	while (unlikely(too_many_isolated(pgdat, file, sc))) {
		if (stalled)
			return 0;

		/* wait a bit for the reclaimer. */
		stalled = true;
		reclaim_throttle(pgdat, VMSCAN_THROTTLE_ISOLATED);

		/* We are about to die and free our memory. Return now. */
		if (fatal_signal_pending(current))
			return SWAP_CLUSTER_MAX;
	}

	lru_add_drain();
#endif
	spin_lock_irq(&lruvec->lru_lock);

	nr_taken = isolate_lru_pages_async(nr_to_scan, lruvec, &page_list,
				     &nr_scanned, sc, lru);
#if 0
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	item = current_is_kswapd() ? PGSCAN_KSWAPD : PGSCAN_DIRECT;
	if (!cgroup_reclaim(sc))
		__count_vm_events(item, nr_scanned);
	__count_memcg_events(lruvec_memcg(lruvec), item, nr_scanned);
	__count_vm_events(PGSCAN_ANON + file, nr_scanned);
#endif
	spin_unlock_irq(&lruvec->lru_lock);

	if (nr_taken == 0)
		return 0;

	nr_reclaimed = shrink_page_list_async(&page_list, pgdat, sc, &stat, false);

	spin_lock_irq(&lruvec->lru_lock);
	move_pages_to_lru_async(lruvec, &page_list);
#if 0
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	item = current_is_kswapd() ? PGSTEAL_KSWAPD : PGSTEAL_DIRECT;
	if (!cgroup_reclaim(sc))
		__count_vm_events(item, nr_reclaimed);
	__count_memcg_events(lruvec_memcg(lruvec), item, nr_reclaimed);
	__count_vm_events(PGSTEAL_ANON + file, nr_reclaimed);
#endif	
	spin_unlock_irq(&lruvec->lru_lock);
#if 0
	lru_note_cost(lruvec, file, stat.nr_pageout);
#endif	
	mem_cgroup_uncharge_list_async(&page_list);
	free_unref_page_list_async(&page_list);
#if 0
	/*
	 * If dirty pages are scanned that are not queued for IO, it
	 * implies that flushers are not doing their job. This can
	 * happen when memory pressure pushes dirty pages to the end of
	 * the LRU before the dirty limits are breached and the dirty
	 * data has expired. It can also happen when the proportion of
	 * dirty pages grows not through writes but through memory
	 * pressure reclaiming all the clean cache. And in some cases,
	 * the flushers simply cannot keep up with the allocation
	 * rate. Nudge the flusher threads in case they are asleep.
	 */
	if (stat.nr_unqueued_dirty == nr_taken)
		wakeup_flusher_threads(WB_REASON_VMSCAN);
#endif
	sc->nr.dirty += stat.nr_dirty;
	sc->nr.congested += stat.nr_congested;
	sc->nr.unqueued_dirty += stat.nr_unqueued_dirty;
	sc->nr.writeback += stat.nr_writeback;
	sc->nr.immediate += stat.nr_immediate;
	sc->nr.taken += nr_taken;
	if (file)
		sc->nr.file_taken += nr_taken;
#if 0
	trace_mm_vmscan_lru_shrink_inactive(pgdat->node_id,
			nr_scanned, nr_reclaimed, &stat, sc->priority, file);
#endif	
	return nr_reclaimed;
}
#endif

#else
# error Need LINUX_VERSION_CODE
#endif

//该函数把内存回收相关的没有EXPORT_SYMBAL的内核函数，通过kallsyms_lookup_name()找到这些函数的函数指针，然后本ko里就可以直接用这些函数了
int look_up_not_export_function(void)
{
    int ret;

	//利用kprobe计数获取内核kallsyms_lookup_name()函数的指针并保存到kallsyms_lookup_name_async，将来用它替代内核原生kallsyms_lookup_name函数
	kp_kallsyms_lookup_name.post_handler = kallsyms_lookup_name_handler_post;
	ret = register_kprobe(&kp_kallsyms_lookup_name);
	if (ret < 0) {
		pr_err("kallsyms_lookup_name register_kprobe failed, returned %d\n", ret);
		return -1;
	}
	kallsyms_lookup_name_async = (void *)(kp_kallsyms_lookup_name.addr);
	unregister_kprobe(&kp_kallsyms_lookup_name);

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
	__count_memcg_events_async = (void*)kallsyms_lookup_name_async("__count_memcg_events");
	putback_lru_page_async = (void *)kallsyms_lookup_name_async("putback_lru_page");
	mem_cgroup_uncharge_list_async = (void*)kallsyms_lookup_name_async("mem_cgroup_uncharge_list");
	free_unref_page_list_async = (void*)kallsyms_lookup_name_async("free_unref_page_list");
	//新加的
	try_to_unmap_flush_async = (void*)kallsyms_lookup_name_async("try_to_unmap_flush");
	mem_cgroup_uncharge_async = (void*)kallsyms_lookup_name_async("mem_cgroup_uncharge");
	compound_page_dtors_async= (compound_page_dtor *  (*)[])kallsyms_lookup_name_async("compound_page_dtors");

	//mmap文件的
	try_to_unmap_async = (void*)kallsyms_lookup_name_async("try_to_unmap");
	page_referenced_async = (void*)kallsyms_lookup_name_async("page_referenced");
#ifdef USE_KERNEL_SHRINK_INACTIVE_LIST
	//isolate_lru_pages_async = (void*)kallsyms_lookup_name_async("isolate_lru_pages");编译成inline了
	shrink_page_list_async = (void*)kallsyms_lookup_name_async("shrink_page_list");
	putback_inactive_pages_async = (void *)kallsyms_lookup_name_async("putback_inactive_pages");
	if(!shrink_page_list_async || !putback_inactive_pages_async){
		printk("!!!!!!!!!! error shrink_page_list_async:0x%llx putback_inactive_pages_async:0x%llx\n",(u64)shrink_page_list_async,(u64)putback_inactive_pages_async);
		return -1;
	}
#endif	

	if(!__isolate_lru_page_async || !page_evictable_async || !__remove_mapping_async || !mem_cgroup_update_lru_size_async || !mem_cgroup_page_lruvec_async || !__mod_lruvec_state_async || !__count_memcg_events_async || !try_to_unmap_flush_async || !compound_page_dtors_async || !mem_cgroup_uncharge_async){
		printk("!!!!!!!!!! error __isolate_lru_page_async:0x%llx page_evictable_async:0x%llx __remove_mapping_async:0x%llx mem_cgroup_update_lru_size:0x%llx mem_cgroup_page_lruvec:0x%llx __mod_lruvec_state:0x%llx__count_memcg_events:0x%llx try_to_unmap_flush_async:0x%llx compound_page_dtors_async:0x%llx mem_cgroup_uncharge_async:0x%llx\n",(u64)__isolate_lru_page_async,(u64)page_evictable_async,(u64)__remove_mapping_async,(u64)mem_cgroup_update_lru_size_async,(u64)mem_cgroup_page_lruvec_async,(u64)__mod_lruvec_state_async,(u64)__count_memcg_events_async,(u64)try_to_unmap_flush_async,(u64)compound_page_dtors_async,(u64)mem_cgroup_uncharge_async);
		return -1;
	}
    
	if(!try_to_unmap_async || !page_referenced_async || !mem_cgroup_uncharge_list_async || !free_unref_page_list_async || !putback_lru_page_async){
		printk("!!!!!!!!!! error try_to_unmap_async:0x%llx  page_referenced_async:0x%llxfree_unref_page_list:0x%llx putback_lru_page_async:0x%llx mem_cgroup_uncharge_list_async:0x%llx\n",(u64)try_to_unmap_async,(u64)page_referenced_async,(u64)free_unref_page_list_async,(u64)putback_lru_page_async,(u64)mem_cgroup_uncharge_list_async);
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
	//mmap文件的
	try_to_unmap_async = (void*)kallsyms_lookup_name_async("try_to_unmap");
	page_referenced_async = (void*)kallsyms_lookup_name_async("folio_referenced");

#ifdef USE_KERNEL_SHRINK_INACTIVE_LIST
	isolate_lru_pages_async = (void*)kallsyms_lookup_name_async("isolate_lru_pages");
	shrink_page_list_async = (void*)kallsyms_lookup_name_async("shrink_page_list");
	move_pages_to_lru_async = (void *)kallsyms_lookup_name_async("move_pages_to_lru");
	if(!shrink_page_list_async || !isolate_lru_pages_async || !move_pages_to_lru_async){
		printk("!!!!!!!!!! error shrink_page_list_async:0x%llx putback_inactive_pages_async:0x%llx move_pages_to_lru:0x%llx\n",(u64)shrink_page_list_async,(u64)isolate_lru_pages_async,(u64)move_pages_to_lru_async);
		return -1;
	}
#endif	

	if(!__remove_mapping_async || !mem_cgroup_update_lru_size_async  || !free_unref_page_list_async || !__count_memcg_events_async  || !mem_cgroup_disabled_async  || !__mod_memcg_lruvec_state_async  || !putback_lru_page_async  || !try_to_unmap_flush_async  || !root_mem_cgroup_async || !compound_page_dtors_async || !__mem_cgroup_uncharge_list_async || !cache_random_seq_destroy_async){
		printk("!!!!!!!!!! error __remove_mapping_async:0x%llx mem_cgroup_update_lru_size_async:0x%llx free_unref_page_list_async:0x%llx __count_memcg_events_async:0x%llx mem_cgroup_disabled_async:0x%llx __mod_memcg_lruvec_state_async:0x%llx putback_lru_page_async:0x%llx try_to_unmap_flush_async:0x%llx root_mem_cgroup_async:0x%llx compound_page_dtors_async:0x%llx __mem_cgroup_uncharge_list_async:0x%llx cache_random_seq_destroy_async:0x%llx",(u64)__remove_mapping_async,(u64)mem_cgroup_update_lru_size_async,(u64)free_unref_page_list_async ,(u64)__count_memcg_events_async ,(u64)mem_cgroup_disabled_async ,(u64)__mod_memcg_lruvec_state_async,(u64)putback_lru_page_async,(u64)try_to_unmap_flush_async ,(u64)root_mem_cgroup_async,(u64)compound_page_dtors_async,(u64)__mem_cgroup_uncharge_list_async,(u64)cache_random_seq_destroy_async);
		return -1;
	}

	if(!try_to_unmap_async || !page_referenced_async){
		printk("!!!!!!!!!! error try_to_unmap_async:0x%llx  page_referenced_async:0x%llx\n",(u64)try_to_unmap_async,(u64)page_referenced_async);
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
#ifndef  USE_KERNEL_SHRINK_INACTIVE_LIST
//遍历p_file_stat对应文件的file_area_free链表上的file_area结构，找到这些file_area结构对应的page，这些page被判定是冷页，可以回收
unsigned long cold_file_isolate_lru_pages(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,
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
			//使用pgdat->lru_lock锁，且有进程阻塞在这把锁上则强制休眠。还有，如果lru_lock持锁时间过长，也需要调度，否则会发生softlockups
			if(pgdat && (spin_is_contended(&pgdat->lru_lock) || need_resched())){
				spin_unlock_irq(&pgdat->lru_lock); 
				if(need_resched())
					schedule();
				else
					msleep(5);//其实这里改成schedule()也可以!!!!!!!!!!!!!

				spin_lock_irq(&pgdat->lru_lock);
				p_hot_cold_file_global->hot_cold_file_shrink_counter.lru_lock_contended_count ++;
			}
#else
			//使用 lruvec->lru_lock 锁，且有进程阻塞在这把锁上
			if(lruvec && (spin_is_contended(&lruvec->lru_lock) || need_resched())){
				spin_unlock_irq(&lruvec->lru_lock); 
				if(need_resched())
					schedule();
				else
					msleep(5);

				spin_lock_irq(&lruvec->lru_lock);
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
				/*如果page映射了也表页目录，这是异常的，要给出告警信息!!!!!!!!!!!!!!!!!!!*/
				if (page_mapped(page)){
					printk("%s file_stat:0x%llx file_area:0x%llx status:0x%x page_mapped error!!!!!!!!!\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state);
				    continue;
				}

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
						//多次开关锁次数加1
						p_hot_cold_file_global->lru_lock_count++;
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
						//多次开关锁次数加1
						p_hot_cold_file_global->lru_lock_count++;
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
unsigned int cold_mmap_file_isolate_lru_pages(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct file_area *p_file_area,struct page *page_buf[],int cold_page_count)
{
	unsigned int isolate_pages = 0;
	int i,traverse_page_count;
	struct page *page;
	struct list_head *dst;
	//isolate_mode_t mode = ISOLATE_UNMAPPED;
	isolate_mode_t mode = 0;
	pg_data_t *pgdat = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
	struct lruvec *lruvec = NULL,*lruvec_new = NULL;
#endif

	printk("1:%s file_stat:0x%llx cold_page_count:%d\n",__func__,(u64)p_file_stat,cold_page_count);
	traverse_page_count = 0;
	//对file_stat加锁
	lock_file_stat(p_file_stat,0);
	//如果文件inode和mapping已经释放了，则不能再使用mapping了，必须直接return
	if(file_stat_in_delete(p_file_stat) || (NULL == p_file_stat->mapping)){
		printk("2:%s file_stat:0x%llx %d_0x%llx\n",__func__,(u64)p_file_stat,file_stat_in_delete(p_file_stat),(u64)p_file_stat->mapping);
		//如果异常退出，也要对page unlock
		for(i = 0; i< cold_page_count;i ++)
		{
			page = page_buf[i];
			if(page)
				unlock_page(page);
			else
				panic("%s page error\n",__func__);
		}
		goto err;
	}
	/*read/write系统调用的pagecache的内存回收执行的cold_file_isolate_lru_pages()函数里里，对此时并发文件inode被delete做了严格防护，这里
	 * 对mamp的pagecache是否也需要防护并发inode被delete呢？突然觉得没有必要呀？因为文件还有文件页page没有被释放呀，就是这里正在回收的
	 * 文件页！这种情况文件inode可能会被delete吗？不会吧，必须得等文件的文件页全部被回收，才可能释放文件inode吧??????????????????*/
	for(i = 0; i< cold_page_count;i ++)
	{
		page = page_buf[i];
		printk("3:%s file_stat:0x%llx file_area:0x%llx page:0x%llx\n",__func__,(u64)p_file_stat,(u64)p_file_area,(u64)page);
		//此时page肯定是加锁状态，否则就主动触发crash
		if(!test_bit(PG_locked,&page->flags)){
			panic("%s page:0x%llx page->flags:0x%lx\n",__func__,(u64)page,page->flags);
		}

		if(traverse_page_count++ >= 32){
			traverse_page_count = 0;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
			//使用pgdat->lru_lock锁，且有进程阻塞在这把锁上则强制休眠。还有，如果lru_lock持锁时间过长，也需要调度，否则会发生softlockups
			if(pgdat && (spin_is_contended(&pgdat->lru_lock) || need_resched())){
				spin_unlock_irq(&pgdat->lru_lock); 
				if(need_resched())
					schedule();
				else
					msleep(5);//其实这里改成schedule()也可以!!!!!!!!!!!!!

				spin_lock_irq(&pgdat->lru_lock);
				//p_hot_cold_file_global->hot_cold_file_shrink_counter.lru_lock_contended_count ++;
			}
#else
			//使用 lruvec->lru_lock 锁，且有进程阻塞在这把锁上
			if(lruvec && (spin_is_contended(&lruvec->lru_lock) || need_resched())){
				spin_unlock_irq(&lruvec->lru_lock); 
				if(need_resched())
					schedule();
				else
					msleep(5);

				spin_lock_irq(&lruvec->lru_lock);
				//p_hot_cold_file_global->hot_cold_file_shrink_counter.lru_lock_contended_count ++;
			}
#endif
		}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
		if(unlikely(pgdat != page_pgdat(page)))
		{
			//第一次进入这个if，pgdat是NULL，此时不用spin unlock，只有后续的page才需要
			if(pgdat){
				//对之前page所属pgdat进行spin unlock
				spin_unlock_irq(&pgdat->lru_lock);
				//多次开关锁次数加1
				p_hot_cold_file_global->lru_lock_count++;
			}
			//pgdat最新的page所属node节点对应的pgdat
			pgdat = page_pgdat(page);
			if(pgdat != p_hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat)
				panic("pgdat not equal\n");
			//对新的page所属的pgdat进行spin lock。内核遍历lru链表都是关闭中断的，这里也关闭中断
			spin_lock_irq(&pgdat->lru_lock);
		}
#else
		//为了保持兼容，还是把每个内存节点的page都移动到对应hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat_page_list_mmap_file链表上
		if(pgdat != page_pgdat(page))
			pgdat = page_pgdat(page);

		lruvec_new = mem_cgroup_lruvec_async(page_memcg(page),pgdat);
		if(unlikely(lruvec != lruvec_new)){
			if(lruvec){
				spin_unlock_irq(&lruvec->lru_lock);
				//多次开关锁次数加1
				p_hot_cold_file_global->lru_lock_count++;
			}
			lruvec = lruvec_new;
			//对新的page所属的pgdat进行spin lock
			spin_lock_irq(&lruvec->lru_lock);
		}
#endif

		//解锁。其实也可以不用解锁，这样async_shrink_free_page()函数回收内存时，就不用再加锁lock_page了，后期再考虑优化吧?????????????????
		unlock_page(page);

		dst = &p_hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat_page_list_mmap_file;
		if(__hot_cold_file_isolate_lru_pages(pgdat,page,dst,mode) != 0){
			//goto err; 到这里说明page busy，不能直接goto err返回错误，继续遍历page，否则就中断了整个内存回收流程，完全没必要
			continue;
		}
		isolate_pages ++;
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

#else

/*以下代码是使用内核原生的内存回收函数，不再使用我自己写的*/

//遍历p_file_stat对应文件的file_area_free链表上的file_area结构，找到这些file_area结构对应的page，这些page被判定是冷页，可以回收
unsigned long cold_file_isolate_lru_pages_and_shrink(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,
		struct list_head *file_area_free)
{
	struct file_area *p_file_area,*tmp_file_area;
	int i;
	struct address_space *mapping = NULL;
	pg_data_t *pgdat = NULL;
	struct page *page;
	unsigned int isolate_pages = 0;
	int traverse_file_area_count = 0;  
	struct page *pages[PAGE_COUNT_IN_AREA];
	struct lruvec *lruvec = NULL,*lruvec_new = NULL;
	int move_page_count = 0,ret;
	unsigned long nr_reclaimed = 0;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
	unsigned long reclaim_stat_recent_rotated;
#endif	

	struct scan_control_async sc = {
		.gfp_mask = __GFP_RECLAIM,
		.order = 1,
		.priority = DEF_PRIORITY,
		.may_writepage = 0,
		.may_unmap = 0,
		.may_swap = 0,
		.reclaim_idx = MAX_NR_ZONES - 1,
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,18,0)
		.no_demotion = 1,//高版本内核多了一个no_demotion
#endif
	};


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
		if((traverse_file_area_count++ >= 16) && (move_page_count < SWAP_CLUSTER_MAX)){
			traverse_file_area_count = 0;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
			//使用pgdat->lru_lock锁，且有进程阻塞在这把锁上则强制休眠。还有，如果lru_lock持锁时间过长，也需要调度，否则会发生softlockups
			if(pgdat && (spin_is_contended(&pgdat->lru_lock) || need_resched())){
				spin_unlock_irq(&pgdat->lru_lock); 
				if(need_resched())
					schedule();
				else
					msleep(5);//其实这里改成schedule()也可以!!!!!!!!!!!!!

				spin_lock_irq(&pgdat->lru_lock);
				p_hot_cold_file_global->hot_cold_file_shrink_counter.lru_lock_contended_count ++;
			}
#else
			//使用 lruvec->lru_lock 锁，且有进程阻塞在这把锁上
			if(lruvec && (spin_is_contended(&lruvec->lru_lock) || need_resched())){
				spin_unlock_irq(&lruvec->lru_lock); 
				if(need_resched())
					schedule();
				else
					msleep(5);

				spin_lock_irq(&lruvec->lru_lock);
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

		//获取p_file_area对应的文件页page指针并保存到pages数组
		memset(pages,0,PAGE_COUNT_IN_AREA*sizeof(struct page *));
		ret = get_page_from_file_area(p_file_stat,p_file_area->start_index,pages);
		//printk("1:%s file_stat:0x%llx file_area:0x%llx get %d page\n",__func__,(u64)p_file_stat,(u64)p_file_area,ret);
		if(ret <= 0)
			goto err; 

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
		//得到file_area对应的page
		for(i = 0;i < PAGE_COUNT_IN_AREA;i ++){
			page = pages[i];
			if (page && !xa_is_value(page)) {
#if 0	
				/*如果page映射了也表页目录，这是异常的，要给出告警信息。并且这个判断要在page lock后，因为这段代码到page lock期间，该page可能被释放了
				 * 然后被新的进程分配，然后使用成mmap页!!!!!!!!!!!!!!!!!!! 这是完全有可能的，这点也非常关键!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
				if (page_mapped(page)){
					printk("%s file_stat:0x%llx file_area:0x%llx status:0x%x page_mapped error!!!!!!!!!\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state);
					continue;
				}
#endif
				/*对page加锁,lock_page执行后只能有两种情况,1:page被其他进程内存回收了,于是这里lock_page后,if(page->mapping!=mapping)不成立,
				 *就可以过滤掉这个page  2:page没有被其他进程回收，但是一直到lru_lock锁成功后,再unlock_page.这样就可以防止 
				 *这段时间page被其他进程释放了,也不用担心page memcg没有一个page了而释放掉memcg和lruvec.因为至少还有这1个page因为lock_page了,
				 *释放不了,那就释放不了memcg和lruvec。之后因为已经lru_lock加锁成功，更不用担心page被其他进程释放了。
				 */
				if (!trylock_page(page)){
					continue;
				}

				/*如果page映射了也表页目录，这是异常的，要给出告警信息!!!!!!!!!!!!!!!!!!!还有其他异常状态*/
				if (unlikely(PageAnon(page))|| unlikely(PageCompound(page)) || unlikely(PageSwapCache(page))){
					panic("%s file_stat:0x%llx file_area:0x%llx status:0x%x page:0x%llx flags:0x%lx error\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state,(u64)page,page->flags);
				}

				//如果page被其他进程回收了，这里不成立，直接过滤掉page。同时，cache文件也不能回收mmaped文件页
				if(unlikely(page->mapping != mapping) || unlikely(page_mapped(page))){
					unlock_page(page);
					printk("%s file_stat:0x%llx file_area:0x%llx status:0x%x page:0x%llx flags:0x%lx page->mapping:0x%llx mapping:0x%llx\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state,(u64)page,page->flags,(u64)page->mapping,(u64)mapping);
					continue;
				}

				//第一次循环，pgdat是NULL，则先加锁。并对 pgdat 和 lruvec 赋值，这样下边的if才不会成立，然后误触发内存回收，此时还没有move page到inactive lru链表
				if(NULL == pgdat){
					pgdat = page_pgdat(page);
					lruvec_new = mem_cgroup_lruvec(page_memcg(page),pgdat);
					lruvec = lruvec_new;
					spin_lock_irq(&pgdat->lru_lock);
				}else{
					lruvec_new = mem_cgroup_lruvec(page_memcg(page),pgdat);
				}

				//if成立条件如果前后的两个page的lruvec或所属node节点(pgdat)不一样 或者 遍历的page数达到32，强制进行一次内存回收

				/*正常情况每个文件的page cache的page都应该属于同一个node,进行一次spin_lock(&pgdat->lru_lock)就行,但是也有可能属于不同的内存节点node，
				  那就需要每次出现新的page所属的内存节点node的pgdat=page_pgdat(page)时,那就把老的pgdat=page_pgdat(page)解锁，对新的pgdat=page_pgdat(page)加
				  锁pgdat != page_pgdat(page)成立说明前后两个page所属node不一样,那就要把前一个page所属pgdat spin unlock,然后对新的page所属pgdat spin lock*/
				if( (move_page_count >= SWAP_CLUSTER_MAX) ||
						unlikely(lruvec != lruvec_new) ||
						unlikely(pgdat != page_pgdat(page)))
				{
					if(0 == move_page_count)
						panic("%s scan_page_count == 0 error pgdat:0x%llx lruvec:0x%llx lruvec_new:0x%llx\n",__func__,(u64)pgdat,(u64)lruvec,(u64)lruvec_new);

					//第一次进入这个if，pgdat是NULL，此时不用spin unlock，只有后续的page才需要
					if(unlikely(lruvec != lruvec_new)|| unlikely(pgdat != page_pgdat(page))){
						//多次开关锁次数加1
						p_hot_cold_file_global->lru_lock_count++;
					}
					spin_unlock_irq(&pgdat->lru_lock);

					/*因为在shrink_inactive_list_async->putback_inactive_pages函数里，内存回收失败的page移动回lru链表前，这些page会统计到
					 *lruvec->reclaim_stat->recent_rotated[1]，内存回收后强制恢复到原来的数据*/
					reclaim_stat_recent_rotated = lruvec->reclaim_stat.recent_rotated[1];
					//回收inactive lru链表尾的page，这些page刚才才移动到inactive lru链表尾
					nr_reclaimed += shrink_inactive_list_async(move_page_count,lruvec,&sc,LRU_INACTIVE_FILE);

					if(reclaim_stat_recent_rotated != lruvec->reclaim_stat.recent_rotated[1]){
						printk("%s %ld page recaim fail\n",__func__,lruvec->reclaim_stat.recent_rotated[1] - reclaim_stat_recent_rotated);
						lruvec->reclaim_stat.recent_rotated[1] = reclaim_stat_recent_rotated;
					}

					//回收后对move_page_count清0
					move_page_count = 0;
					//回收后对遍历的file_area个数清0
					traverse_file_area_count = 0;

					//lruvec赋值最新page所属的lruvec
					lruvec = lruvec_new;
					//pgdat最新的page所属node节点对应的pgdat
					pgdat = page_pgdat(page);
					//对新的page所属的pgdat进行spin lock。内核遍历lru链表都是关闭中断的，这里也关闭中断
					spin_lock_irq(&pgdat->lru_lock);
				}

				/*这里有个很重要的隐藏点，当执行到这里时，前后挨着的page所属的lruvec必须是同一个，这样才能
				 * list_move_tail到同一个lruvec inactive lru链表尾。否则就出乱子了，把不同lruvec的page移动到同一个。保险起见，
				 * 如果出现这种情况，强制panic*/
				if(lruvec != mem_cgroup_lruvec(page_memcg(page),pgdat))
					panic("%s lruvec not equal error pgdat:0x%llx lruvec:0x%llx lruvec_new:0x%llx\n",__func__,(u64)pgdat,(u64)lruvec,(u64)lruvec_new);

				/*把page移动到inactive lru链表尾，紧接着就从inactive lru链表尾回收这些page。移动前必须加pgdat或lruvec lru链表锁。但早期代码有个
				 * 重大bug!!!!!!!!!!!!!!!!!!!如果page在active lru链表，只是把page移动到inactive lru链表尾是不行的，还必须得令active lru链表长度
				 * 减1,同时还要令inacitve lru链表长度加1。否则会导致active lru链表长度大于该链表实际的page数，inactive lru长度小于该链表实际
				 * 的page数。这样会导致将来内存回收执行到isolate_lru_pages->update_lru_sizes->mem_cgroup_update_lru_size更新inactive lru长度时，
				 * 因为inactive lru长度时负数而报"mem_cgroup_update_lru_size(000000006166af5e, 2, -32): lru_size -29"，然后内核告警!!!!!!!!!
				 * 还要配置了内核告警立即触发内核crash，否则这个告警将会被繁多的内核日志掩盖。这个bug很有价值，真的体会到，只有你深度内核去修改
				 * 代码，实现一个新的功能，踩坑，才会真正长进，如果只是在内核局部小幅修改，踩不了坑，是无法真正成长的。*/
#if 0
				//如果page处于acitve lru链表，必须清理掉active 属性，这点很重要，然后再把page移动到inactive lru链表尾
				if(PageActive(page))
					ClearPageActive(page);
				list_move_tail(&page->lru,&lruvec->lists[LRU_INACTIVE_FILE]);
#else
				if(PageActive(page)){
					del_page_from_lru_list_async(page,lruvec,LRU_ACTIVE_FILE);
					//如果page在active lru链表，则清理active属性，把page从acitve链表移动到inactive链表，并令前者链表长度减1，后者链表长度加1
					ClearPageActive(page);
					add_page_to_lru_list_tail_async(page,lruvec,LRU_INACTIVE_FILE);
				}else{
					//否则，page只是在inactive链表里移动，直接list_move即可，不用更新链表长度
					list_move_tail(&page->lru,&lruvec->lists[LRU_INACTIVE_FILE]);
				}
#endif
				//移动到inactive lru链表尾的page数加1
				move_page_count ++;
				/*这里有个问题，如果上边的if成立，触发了内核回收，当前这个page就要一直lock page，到这里才能unlock，这样
				 * 是不是lock page时间有点长。但是为了保证这个page这段时间不会被其他进程释放掉，只能一直lock page。并且
				 * 上边if里只回收32个page，还是clean page，没有io，时间很短的。*/
				unlock_page(page);

			}
		}
#else
		/*这个5.14.0-284.11.1.el9_2 内核分支分支，把大部分注释都删掉了,详细注释都在前边的分支*/

                //得到file_area对应的page
		for(i = 0;i < PAGE_COUNT_IN_AREA;i ++){
			page = pages[i];
			if (page && !xa_is_value(page)) {
				if (!trylock_page(page)){
					continue;
				}

				/*如果page映射了也表页目录，这是异常的，要给出告警信息!!!!!!!!!!!!!!!!!!!还有其他异常状态*/
				if (unlikely(PageAnon(page))|| unlikely(PageCompound(page)) || unlikely(PageSwapCache(page))){
					panic("%s file_stat:0x%llx file_area:0x%llx status:0x%x page:0x%llx flags:0x%lx error\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state,(u64)page,page->flags);
				}

				//如果page被其他进程回收了，这里不成立，直接过滤掉page。同时，cache文件也不能回收mmaped文件页
				if(unlikely(page->mapping != mapping) || unlikely(page_mapped(page))){
					unlock_page(page);
					printk("%s file_stat:0x%llx file_area:0x%llx status:0x%x page:0x%llx flags:0x%lx page->mapping:0x%llx mapping:0x%llx\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state,(u64)page,page->flags,(u64)page->mapping,(u64)mapping);
					continue;
				}

				//第一次循环，lruvec是NULL，则先加锁。并对lruvec赋值，这样下边的if才不会成立，然后误触发内存回收，此时还没有move page到inactive lru链表
				if(NULL == lruvec){
					lruvec_new = mem_cgroup_lruvec_async(page_memcg(page),page_pgdat(page));
					lruvec = lruvec_new;
					spin_lock_irq(&lruvec->lru_lock);
				}else{
					lruvec_new = mem_cgroup_lruvec_async(page_memcg(page),page_pgdat(page));
				}

				//if成立条件如果前后的两个page的lruvec不一样 或者 遍历的page数达到32，强制进行一次内存回收
				if( (move_page_count >= SWAP_CLUSTER_MAX) ||
						unlikely(lruvec != lruvec_new))
				{
					if(0 == move_page_count)
						panic("%s scan_page_count == 0 error pgdat:0x%llx lruvec:0x%llx lruvec_new:0x%llx\n",__func__,(u64)pgdat,(u64)lruvec,(u64)lruvec_new);

					//第一次进入这个if，pgdat是NULL，此时不用spin unlock，只有后续的page才需要
					if(unlikely(lruvec != lruvec_new)){
						//多次开关锁次数加1
						p_hot_cold_file_global->lru_lock_count++;
					}
					spin_unlock_irq(&lruvec->lru_lock);

					//回收inactive lru链表尾的page，这些page刚才才移动到inactive lru链表尾
					nr_reclaimed += shrink_inactive_list_async(move_page_count,lruvec,&sc,LRU_INACTIVE_FILE);

					//回收后对move_page_count清0
					move_page_count = 0;
					//回收后对遍历的file_area个数清0
					traverse_file_area_count = 0;

					//lruvec赋值最新page所属的lruvec
					lruvec = lruvec_new;
					//对新的page所属的pgdat进行spin lock。内核遍历lru链表都是关闭中断的，这里也关闭中断
					spin_lock_irq(&lruvec->lru_lock);
				}

				/*这里有个很重要的隐藏点，当执行到这里时，前后挨着的page所属的lruvec必须是同一个，这样才能
				 * list_move_tail到同一个lruvec inactive lru链表尾。否则就出乱子了，把不同lruvec的page移动到同一个。保险起见，
				 * 如果出现这种情况，强制panic*/
				if(lruvec != mem_cgroup_lruvec_async(page_memcg(page),page_pgdat(page)))
					panic("%s lruvec not equal error pgdat:0x%llx lruvec:0x%llx lruvec_new:0x%llx\n",__func__,(u64)pgdat,(u64)lruvec,(u64)lruvec_new);

				if(PageActive(page)){
			               /*!!!!!!!!!!!重大bug，5.14的内核，把page添加到lru链表不再指定LRU_INACTIVE_FILE或LRU_ACTIVE_FILE，而是
			                *del_page_from_lru_list/add_page_to_lru_list 函数里判断page是否是acitve来决定page处于哪个链表。因此
		                        *必须把ClearPageActive(page)清理page的active属性放到del_page_from_lru_list_async后边，否则会误判page处于LRU_INACTIVE_FILE链表*/
					del_page_from_lru_list_async(page,lruvec);
					barrier();
					//如果page在active lru链表，则清理active属性，把page从acitve链表移动到inactive链表，并令前者链表长度减1，后者链表长度加1
					ClearPageActive(page);
					barrier();
					add_page_to_lru_list_tail_async(page,lruvec);
				}else{
					//否则，page只是在inactive链表里移动，直接list_move即可，不用更新链表长度
					list_move_tail(&page->lru,&lruvec->lists[LRU_INACTIVE_FILE]);
				}

				//移动到inactive lru链表尾的page数加1
				move_page_count ++;
				/*这里有个问题，如果上边的if成立，触发了内核回收，当前这个page就要一直lock page，到这里才能unlock，这样
				 * 是不是lock page时间有点长。但是为了保证这个page这段时间不会被其他进程释放掉，只能一直lock page。并且
				 * 上边if里只回收32个page，还是clean page，没有io，时间很短的。*/
				unlock_page(page);

			}
		}

#endif
		//rcu_read_unlock();
	}
err:   

	//file_stat解锁
	unlock_file_stat(p_file_stat);

	//当函数退出时，如果move_page_count大于0，则强制回收这些page
	if(move_page_count > 0){
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
		reclaim_stat_recent_rotated = lruvec->reclaim_stat.recent_rotated[1];
		if(pgdat)
			spin_unlock_irq(&pgdat->lru_lock);
#else
		if(lruvec)
			spin_unlock_irq(&lruvec->lru_lock);
#endif

		//回收inactive lru链表尾的page，这些page刚才才移动到inactive lru链表尾
		nr_reclaimed += shrink_inactive_list_async(move_page_count,lruvec,&sc,LRU_INACTIVE_FILE);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
		if(reclaim_stat_recent_rotated != lruvec->reclaim_stat.recent_rotated[1]){
			printk("2:%s %ld page recaim fail\n",__func__,lruvec->reclaim_stat.recent_rotated[1] - reclaim_stat_recent_rotated);
			lruvec->reclaim_stat.recent_rotated[1] = reclaim_stat_recent_rotated;
		}
#endif
	}else{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
		if(pgdat)
			spin_unlock_irq(&pgdat->lru_lock);
#else
		if(lruvec)
			spin_unlock_irq(&lruvec->lru_lock);
#endif
	}

	//hot_cold_file_global_info.hot_cold_file_shrink_counter.lock_fail_count += lock_fail_count;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.nr_unmap_fail += nr_unmap_fail;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.writeback_count += sc.nr.writeback;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.dirty_count += sc.nr.dirty;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.page_has_private_count += page_has_private_count;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.mapping_count += mapping_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_count += nr_reclaimed;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_fail_count += free_pages_fail_count;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.page_unevictable_count += page_unevictable_count;
	isolate_pages = sc.nr.taken;

	return isolate_pages;
}
unsigned int cold_mmap_file_isolate_lru_pages_and_shrink(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct file_area *p_file_area,struct page *page_buf[],int cold_page_count)
{
	unsigned int isolate_pages = 0;
	int i,traverse_page_count;
	struct page *page;
	//isolate_mode_t mode = ISOLATE_UNMAPPED;
	pg_data_t *pgdat = NULL;
	unsigned int move_page_count = 0;
	struct lruvec *lruvec = NULL,*lruvec_new = NULL;
	unsigned long nr_reclaimed = 0;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
	unsigned long reclaim_stat_recent_rotated;
#endif	
	struct scan_control_async sc = {
		.gfp_mask = __GFP_RECLAIM,
		.order = 1,
		.priority = DEF_PRIORITY,
		.may_writepage = 0,
		.may_unmap = 1,
		.may_swap = 0,
		.reclaim_idx = MAX_NR_ZONES - 1,
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,18,0)
		.no_demotion = 1,//高版本内核多了一个no_demotion
#endif
	};

	printk("1:%s file_stat:0x%llx cold_page_count:%d\n",__func__,(u64)p_file_stat,cold_page_count);
	traverse_page_count = 0;
	//对file_stat加锁
	lock_file_stat(p_file_stat,0);
	//如果文件inode和mapping已经释放了，则不能再使用mapping了，必须直接return
	if(file_stat_in_delete(p_file_stat) || (NULL == p_file_stat->mapping)){
		printk("2:%s file_stat:0x%llx %d_0x%llx\n",__func__,(u64)p_file_stat,file_stat_in_delete(p_file_stat),(u64)p_file_stat->mapping);
		//如果异常退出，也要对page unlock
		for(i = 0; i< cold_page_count;i ++)
		{
			page = page_buf[i];
			if(page)
				unlock_page(page);
			else
				panic("%s page error\n",__func__);
		}
		goto err;
	}
	/*read/write系统调用的pagecache的内存回收执行的cold_file_isolate_lru_pages()函数里里，对此时并发文件inode被delete做了严格防护，这里
	 * 对mamp的pagecache是否也需要防护并发inode被delete呢？突然觉得没有必要呀？因为文件还有文件页page没有被释放呀，就是这里正在回收的
	 * 文件页！这种情况文件inode可能会被delete吗？不会吧，必须得等文件的文件页全部被回收，才可能释放文件inode吧??????????????????*/
	for(i = 0; i< cold_page_count;i ++)
	{
		page = page_buf[i];
		printk("3:%s file_stat:0x%llx file_area:0x%llx page:0x%llx\n",__func__,(u64)p_file_stat,(u64)p_file_area,(u64)page);
		//此时page肯定是加锁状态，否则就主动触发crash
		if(!test_bit(PG_locked,&page->flags)){
			panic("%s page:0x%llx page->flags:0x%lx\n",__func__,(u64)page,page->flags);
		}

		if(traverse_page_count++ > 32){
			traverse_page_count = 0;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
			//使用pgdat->lru_lock锁，且有进程阻塞在这把锁上则强制休眠。还有，如果lru_lock持锁时间过长，也需要调度，否则会发生softlockups
			if(pgdat && (spin_is_contended(&pgdat->lru_lock) || need_resched())){
				spin_unlock_irq(&pgdat->lru_lock); 
				if(need_resched())
					schedule();
				else
					msleep(5);//其实这里改成schedule()也可以!!!!!!!!!!!!!

				spin_lock_irq(&pgdat->lru_lock);
				//p_hot_cold_file_global->hot_cold_file_shrink_counter.lru_lock_contended_count ++;
			}
#else
			//使用 lruvec->lru_lock 锁，且有进程阻塞在这把锁上
			if(lruvec && (spin_is_contended(&lruvec->lru_lock) || need_resched())){
				spin_unlock_irq(&lruvec->lru_lock); 
				if(need_resched())
					schedule();
				else
					msleep(5);

				spin_lock_irq(&lruvec->lru_lock);
				//p_hot_cold_file_global->hot_cold_file_shrink_counter.lru_lock_contended_count ++;
			}
#endif
		}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
#if 0	
		/*到这里的page，是已经pagelock的，这里就不用再pagelock了*/
		if(unlikely(pgdat != page_pgdat(page)))
		{
			//第一次进入这个if，pgdat是NULL，此时不用spin unlock，只有后续的page才需要
			if(pgdat){
				//对之前page所属pgdat进行spin unlock
				spin_unlock_irq(&pgdat->lru_lock);
				//多次开关锁次数加1
				p_hot_cold_file_global->mmap_file_lru_lock_count++;
			}
			//pgdat最新的page所属node节点对应的pgdat
			pgdat = page_pgdat(page);
			if(pgdat != p_hot_cold_file_global->p_hot_cold_file_node_pgdat[pgdat->node_id].pgdat)
				panic("pgdat not equal\n");
			//对新的page所属的pgdat进行spin lock。内核遍历lru链表都是关闭中断的，这里也关闭中断
			spin_lock_irq(&pgdat->lru_lock);
		}
#endif

		/*如果page映射了也表页目录，这是异常的，要给出告警信息!!!!!!!!!!!!!!!!!!!还有其他异常状态*/
		if (unlikely(PageAnon(page))|| unlikely(PageCompound(page)) || unlikely(PageSwapCache(page))){
			panic("%s file_stat:0x%llx file_area:0x%llx status:0x%x page:0x%llx flags:0x%lx error\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state,(u64)page,page->flags);
		}

		//第一次循环，pgdat是NULL，则先加锁。并对 pgdat 和 lruvec 赋值，这样下边的if才不会成立，然后误触发内存回收，此时还没有move page到inactive lru链表
		if(NULL == pgdat){
			pgdat = page_pgdat(page);
			lruvec_new = mem_cgroup_lruvec(page_memcg(page),pgdat);
			lruvec = lruvec_new;
			spin_lock_irq(&pgdat->lru_lock);
		}else{
			lruvec_new = mem_cgroup_lruvec(page_memcg(page),pgdat);
		}

		//if成立条件如果前后的两个page的lruvec或所属node节点(pgdat)不一样 或者 遍历的page数达到32，强制进行一次内存回收

		/*正常情况每个文件的page cache的page都应该属于同一个node,进行一次spin_lock(&pgdat->lru_lock)就行,但是也有可能属于不同的内存节点node，
		  那就需要每次出现新的page所属的内存节点node的pgdat=page_pgdat(page)时,那就把老的pgdat=page_pgdat(page)解锁，对新的pgdat=page_pgdat(page)加
		  锁pgdat != page_pgdat(page)成立说明前后两个page所属node不一样,那就要把前一个page所属pgdat spin unlock,然后对新的page所属pgdat spin lock*/
		if( (move_page_count >= SWAP_CLUSTER_MAX) ||
				unlikely(lruvec != lruvec_new) ||
				unlikely(pgdat != page_pgdat(page)))
		{
			if(0 == move_page_count)
				panic("%s scan_page_count == 0 error pgdat:0x%llx lruvec:0x%llx lruvec_new:0x%llx\n",__func__,(u64)pgdat,(u64)lruvec,(u64)lruvec_new);

			//第一次进入这个if，pgdat是NULL，此时不用spin unlock，只有后续的page才需要
			if(unlikely(lruvec != lruvec_new)|| unlikely(pgdat != page_pgdat(page))){
				//多次开关锁次数加1
				p_hot_cold_file_global->mmap_file_lru_lock_count++;
			}
			spin_unlock_irq(&pgdat->lru_lock);

			/*因为在shrink_inactive_list_async->putback_inactive_pages函数里，内存回收失败的page移动回lru链表前，这些page会统计到
			 *lruvec->reclaim_stat->recent_rotated[1]，内存回收后强制恢复到原来的数据*/
			reclaim_stat_recent_rotated = lruvec->reclaim_stat.recent_rotated[1];
			//回收inactive lru链表尾的page，这些page刚才才移动到inactive lru链表尾
			nr_reclaimed += shrink_inactive_list_async(move_page_count,lruvec,&sc,LRU_INACTIVE_FILE);

			if(reclaim_stat_recent_rotated != lruvec->reclaim_stat.recent_rotated[1]){
				printk("%s %ld page recaim fail\n",__func__,lruvec->reclaim_stat.recent_rotated[1] - reclaim_stat_recent_rotated);
				lruvec->reclaim_stat.recent_rotated[1] = reclaim_stat_recent_rotated;
			}

			//回收后对move_page_count清0
			move_page_count = 0;
			//回收后对遍历的file_area个数清0
			//traverse_file_area_count = 0;

			//lruvec赋值最新page所属的lruvec
			lruvec = lruvec_new;
			//pgdat最新的page所属node节点对应的pgdat
			pgdat = page_pgdat(page);
			//对新的page所属的pgdat进行spin lock。内核遍历lru链表都是关闭中断的，这里也关闭中断
			spin_lock_irq(&pgdat->lru_lock);
		}

		/*这里有个很重要的隐藏点，当执行到这里时，前后挨着的page所属的lruvec必须是同一个，这样才能
		 * list_move_tail到同一个lruvec inactive lru链表尾。否则就出乱子了，把不同lruvec的page移动到同一个。保险起见，
		 * 如果出现这种情况，强制panic*/
		if(lruvec != mem_cgroup_lruvec(page_memcg(page),pgdat))
			panic("%s lruvec not equal error pgdat:0x%llx lruvec:0x%llx lruvec_new:0x%llx\n",__func__,(u64)pgdat,(u64)lruvec,(u64)lruvec_new);

		if(PageActive(page)){
			del_page_from_lru_list_async(page,lruvec,LRU_ACTIVE_FILE);
			//如果page在active lru链表，则清理active属性，把page从acitve链表移动到inactive链表，并令前者链表长度减1，后者链表长度加1
			ClearPageActive(page);
			add_page_to_lru_list_tail_async(page,lruvec,LRU_INACTIVE_FILE);
		}else{
			//否则，page只是在inactive链表里移动，直接list_move即可，不用更新链表长度
			list_move_tail(&page->lru,&lruvec->lists[LRU_INACTIVE_FILE]);
		}
		//移动到inactive lru链表尾的page数加1
		move_page_count ++;
		/*这里有个问题，如果上边的if成立，触发了内核回收，当前这个page就要一直lock page，到这里才能unlock，这样
		 * 是不是lock page时间有点长。但是为了保证这个page这段时间不会被其他进程释放掉，只能一直lock page。并且
		 * 上边if里只回收32个page，还是clean page，没有io，时间很短的。*/
		unlock_page(page);
#else
				
	     /*这个5.14.0-284.11.1.el9_2 内核分支分支，把大部分注释都删掉了,详细注释都在前边的分支*/
	     if (page && !xa_is_value(page)) {
			/*如果page映射了也表页目录，这是异常的，要给出告警信息!!!!!!!!!!!!!!!!!!!还有其他异常状态*/
			if (unlikely(PageAnon(page))|| unlikely(PageCompound(page)) || unlikely(PageSwapCache(page))){
				panic("%s file_stat:0x%llx file_area:0x%llx status:0x%x page:0x%llx flags:0x%lx error\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state,(u64)page,page->flags);
			}
			
			//第一次循环，lruvec是NULL，则先加锁。并对lruvec赋值，这样下边的if才不会成立，然后误触发内存回收，此时还没有move page到inactive lru链表
			if(NULL == lruvec){
				lruvec_new = mem_cgroup_lruvec_async(page_memcg(page),page_pgdat(page));
				lruvec = lruvec_new;
				spin_lock_irq(&lruvec->lru_lock);
			}else{
				lruvec_new = mem_cgroup_lruvec_async(page_memcg(page),page_pgdat(page));
			}

			//if成立条件如果前后的两个page的lruvec不一样 或者 遍历的page数达到32，强制进行一次内存回收
			if( (move_page_count >= SWAP_CLUSTER_MAX) ||
					unlikely(lruvec != lruvec_new))
			{
				if(0 == move_page_count)
					panic("%s scan_page_count == 0 error pgdat:0x%llx lruvec:0x%llx lruvec_new:0x%llx\n",__func__,(u64)pgdat,(u64)lruvec,(u64)lruvec_new);

				//第一次进入这个if，pgdat是NULL，此时不用spin unlock，只有后续的page才需要
				if(unlikely(lruvec != lruvec_new)){
					//多次开关锁次数加1
					p_hot_cold_file_global->lru_lock_count++;
				}
				spin_unlock_irq(&lruvec->lru_lock);

				//回收inactive lru链表尾的page，这些page刚才才移动到inactive lru链表尾
				nr_reclaimed += shrink_inactive_list_async(move_page_count,lruvec,&sc,LRU_INACTIVE_FILE);

				//回收后对move_page_count清0
				move_page_count = 0;

				//lruvec赋值最新page所属的lruvec
				lruvec = lruvec_new;
				//对新的page所属的pgdat进行spin lock。内核遍历lru链表都是关闭中断的，这里也关闭中断
				spin_lock_irq(&lruvec->lru_lock);
			}

			/*这里有个很重要的隐藏点，当执行到这里时，前后挨着的page所属的lruvec必须是同一个，这样才能
			 * list_move_tail到同一个lruvec inactive lru链表尾。否则就出乱子了，把不同lruvec的page移动到同一个。保险起见，
			 * 如果出现这种情况，强制panic*/
			if(lruvec != mem_cgroup_lruvec_async(page_memcg(page),page_pgdat(page)))
				panic("%s lruvec not equal error pgdat:0x%llx lruvec:0x%llx lruvec_new:0x%llx\n",__func__,(u64)pgdat,(u64)lruvec,(u64)lruvec_new);

			if(PageActive(page)){
				del_page_from_lru_list_async(page,lruvec);
				barrier();
				//如果page在active lru链表，则清理active属性，把page从acitve链表移动到inactive链表，并令前者链表长度减1，后者链表长度加1
				ClearPageActive(page);
				barrier();
				add_page_to_lru_list_tail_async(page,lruvec);
			}else{
				//否则，page只是在inactive链表里移动，直接list_move即可，不用更新链表长度
				list_move_tail(&page->lru,&lruvec->lists[LRU_INACTIVE_FILE]);
			}

			//移动到inactive lru链表尾的page数加1
			move_page_count ++;
			/*这里有个问题，如果上边的if成立，触发了内核回收，当前这个page就要一直lock page，到这里才能unlock，这样
			 * 是不是lock page时间有点长。但是为了保证这个page这段时间不会被其他进程释放掉，只能一直lock page。并且
			 * 上边if里只回收32个page，还是clean page，没有io，时间很短的。*/
			unlock_page(page);
	        }
#endif
	}
err:
	//file_stat解锁
	unlock_file_stat(p_file_stat);

	//当函数退出时，如果move_page_count大于0，则强制回收这些page
	if(move_page_count > 0){
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
		reclaim_stat_recent_rotated = lruvec->reclaim_stat.recent_rotated[1];
		if(pgdat)
			spin_unlock_irq(&pgdat->lru_lock);
#else
		if(lruvec)
			spin_unlock_irq(&lruvec->lru_lock);
#endif
		//回收inactive lru链表尾的page，这些page刚才才移动到inactive lru链表尾
		nr_reclaimed += shrink_inactive_list_async(move_page_count,lruvec,&sc,LRU_INACTIVE_FILE);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
		if(reclaim_stat_recent_rotated != lruvec->reclaim_stat.recent_rotated[1]){
			printk("2:%s %ld page recaim fail\n",__func__,lruvec->reclaim_stat.recent_rotated[1] - reclaim_stat_recent_rotated);
			lruvec->reclaim_stat.recent_rotated[1] = reclaim_stat_recent_rotated;
		}
#endif
	}else{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)	
		if(pgdat)
			spin_unlock_irq(&pgdat->lru_lock);
#else
		if(lruvec)
			spin_unlock_irq(&lruvec->lru_lock);
#endif
	}

	//hot_cold_file_global_info.hot_cold_file_shrink_counter.lock_fail_count += lock_fail_count;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.nr_unmap_fail += nr_unmap_fail;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.mmap_writeback_count += sc.nr.writeback;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.mmap_dirty_count += sc.nr.dirty;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.page_has_private_count += page_has_private_count;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.mapping_count += mapping_count;
	hot_cold_file_global_info.hot_cold_file_shrink_counter.mmap_free_pages_count += nr_reclaimed;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.free_pages_fail_count += free_pages_fail_count;
	//hot_cold_file_global_info.hot_cold_file_shrink_counter.page_unevictable_count += page_unevictable_count;
	isolate_pages = sc.nr.taken;

	return isolate_pages;
}

#endif
/*****proc文件系统**********************************************************************************************************************/
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
	.proc_lseek     = seq_lseek,
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
	.proc_lseek     = seq_lseek,
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
	.proc_lseek     = seq_lseek,
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
//nr_pages_level
static int nr_pages_level_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", hot_cold_file_global_info.nr_pages_level);
	return 0;
}
static int nr_pages_level_open(struct inode *inode, struct file *file)
{
	return single_open(file, nr_pages_level_show, NULL);
}
static ssize_t nr_pages_level_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{
	int rc;
	unsigned int val;
	rc = kstrtouint_from_user(buffer, count, 10,&val);
	if (rc)
		return rc;

	if(val > 0)
		hot_cold_file_global_info.nr_pages_level = val;
	else
		return -EINVAL;

	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations nr_pages_level_fops = {
	.open		= nr_pages_level_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= nr_pages_level_write,
};
#else
static const struct proc_ops nr_pages_level_fops = {
	.proc_open		= nr_pages_level_open,
	.proc_read		= seq_read,
	.proc_lseek     = seq_lseek,
	.proc_release	= single_release,
	.proc_write		= nr_pages_level_write,
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
	.proc_lseek     = seq_lseek,
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
	.proc_lseek     = seq_lseek,
	.proc_release	= single_release,
	.proc_write		= async_drop_caches_write,
};
#endif
//enable_disable_async_memory_reclaim
static int enable_disable_async_memory_reclaim_show(struct seq_file *m, void *v)
{
	seq_printf(m, "ASYNC_MEMORY_RECLAIM_ENABLE:%d\n",test_bit(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status));
	return 0;
}
static int enable_disable_async_memory_reclaim_open(struct inode *inode, struct file *file)
{
	return single_open(file,enable_disable_async_memory_reclaim_show, NULL);
}
static ssize_t enable_disable_async_memory_reclaim_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{   
	int rc;
	unsigned int val;
	rc = kstrtouint_from_user(buffer, count, 10,&val);
	if (rc)
		return rc;

	if(val == 0)
		clear_bit_unlock(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status);
	else
		set_bit(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status);

	return count;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
static const struct file_operations enable_disable_async_memory_reclaim_fops = {
	.open		= enable_disable_async_memory_reclaim_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= enable_disable_async_memory_reclaim_write,
};
#else
static const struct proc_ops enable_disable_async_memory_reclaim_fops = {
	.proc_open		= enable_disable_async_memory_reclaim_open,
	.proc_read		= seq_read,
	.proc_lseek     = seq_lseek,
	.proc_release	= single_release,
	.proc_write		= enable_disable_async_memory_reclaim_write,
};
#endif
void get_file_name(char *file_name_path,struct file_stat * p_file_stat)
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
int hot_cold_file_print_all_file_stat(struct hot_cold_file_global *p_hot_cold_file_global,struct seq_file *m,int is_proc_print)//is_proc_print:1 通过proc触发的打印
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
void printk_shrink_param(struct hot_cold_file_global *p_hot_cold_file_global,struct seq_file *m,int is_proc_print)
{
	struct hot_cold_file_shrink_counter *p = &p_hot_cold_file_global->hot_cold_file_shrink_counter;

	if(is_proc_print){
		seq_printf(m,"scan_file_area:%d scan_file_stat:%d scan_delete_file_stat:%d scan_cold_file_area:%d scan_large_to_small:%d scan_fail_file_stat:%d file_area_refault_to_temp:%d file_area_free:%d file_area_hot_to_temp:%d-%d\n",p->scan_file_area_count,p->scan_file_stat_count,p->scan_delete_file_stat_count,p->scan_cold_file_area_count,p->scan_large_to_small_count,p->scan_fail_file_stat_count,p->file_area_refault_to_temp_list_count,p->file_area_free_count,p->file_area_hot_to_temp_list_count,p->file_area_hot_to_temp_list_count2);

		seq_printf(m,"isolate_pages:%d del_file_stat:%d del_file_area:%d lock_fail_count:%d writeback:%d dirty:%d page_has_private:%d mapping:%d free_pages:%d free_pages_fail:%d scan_zero_file_area_file_stat_count:%d unevictable:%d lru_lock_contended:%d nr_unmap_fail:%d\n",p->isolate_lru_pages,p->del_file_stat_count,p->del_file_area_count,p->lock_fail_count,p->writeback_count,p->dirty_count,p->page_has_private_count,p->mapping_count,p->free_pages_count,p->free_pages_fail_count,p->scan_zero_file_area_file_stat_count,p->page_unevictable_count,p->lru_lock_contended_count,p->nr_unmap_fail);

		seq_printf(m,"file_area_delete_in_cache:%d file_area_cache_hit:%d file_area_access_in_free_page:%d hot_file_area_in_free_page:%d refault_file_area_in_free_page:%d hot_file_area_one_period:%d refault_file_area_one_period:%d find_file_area_from_tree:%d all_file_area_access:%d small_file_page_refuse:%d find_file_area_from_last:%d lru_lock_count:%d\n",p->file_area_delete_in_cache_count,p->file_area_cache_hit_count,p->file_area_access_count_in_free_page,p->hot_file_area_count_in_free_page,p_hot_cold_file_global->refault_file_area_count_in_free_page,p->hot_file_area_count_one_period,p->refault_file_area_count_one_period,p->find_file_area_from_tree_not_lock_count,p->all_file_area_access_count,p->small_file_page_refuse_count,p->find_file_area_from_last_count,p_hot_cold_file_global->lru_lock_count);

		seq_printf(m,"0x%llx age:%ld file_stat_count:%d file_stat_hot:%d file_stat_zero_file_area:%d file_stat_large_count:%d all_refault_count:%ld\n",(u64)p_hot_cold_file_global,p_hot_cold_file_global->global_age,p_hot_cold_file_global->file_stat_count,p_hot_cold_file_global->file_stat_hot_count,p_hot_cold_file_global->file_stat_count_zero_file_area,p_hot_cold_file_global->file_stat_large_count,p_hot_cold_file_global->all_refault_count);
	}
	else
	{
		printk("scan_file_area_count:%d scan_file_stat_count:%d scan_delete_file_stat_count:%d scan_cold_file_area_count:%d scan_large_to_small_count:%d scan_fail_file_stat_count:%d file_area_refault_to_temp_list_count:%d file_area_free_count:%d file_area_hot_to_temp_list_count:%d-%d\n",p->scan_file_area_count,p->scan_file_stat_count,p->scan_delete_file_stat_count,p->scan_cold_file_area_count,p->scan_large_to_small_count,p->scan_fail_file_stat_count,p->file_area_refault_to_temp_list_count,p->file_area_free_count,p->file_area_hot_to_temp_list_count,p->file_area_hot_to_temp_list_count2);

		printk("isolate_lru_pages:%d del_file_stat_count:%d del_file_area_count:%d lock_fail_count:%d writeback_count:%d dirty_count:%d page_has_private_count:%d mapping_count:%d free_pages_count:%d free_pages_fail_count:%d scan_zero_file_area_file_stat_count:%d unevictable:%d lru_lock_contended:%d nr_unmap_fail:%d\n",p->isolate_lru_pages,p->del_file_stat_count,p->del_file_area_count,p->lock_fail_count,p->writeback_count,p->dirty_count,p->page_has_private_count,p->mapping_count,p->free_pages_count,p->free_pages_fail_count,p->scan_zero_file_area_file_stat_count,p->page_unevictable_count,p->lru_lock_contended_count,p->nr_unmap_fail);

		printk("file_area_delete_in_cache_count:%d file_area_cache_hit_count:%d file_area_access_count_in_free_page:%d hot_file_area_count_in_free_page:%d refault_file_area_count_in_free_page:%d hot_file_area_count_one_period:%d refault_file_area_count_one_period:%d find_file_area_from_tree_not_lock_count:%d all_file_area_access:%d small_file_page_refuse_count:%d find_file_area_from_last:%d lru_lock_count:%d\n",p->file_area_delete_in_cache_count,p->file_area_cache_hit_count,p->file_area_access_count_in_free_page,p->hot_file_area_count_in_free_page,p_hot_cold_file_global->refault_file_area_count_in_free_page,p->hot_file_area_count_one_period,p->refault_file_area_count_one_period,p->find_file_area_from_tree_not_lock_count,p->all_file_area_access_count,p->small_file_page_refuse_count,p->find_file_area_from_last_count,p_hot_cold_file_global->lru_lock_count);


		printk(">>>>>0x%llx global_age:%ld file_stat_count:%d file_stat_hot_count:%d file_stat_count_zero_file_area:%d file_stat_large_count:%d all_refault_count:%ld<<<<<<\n",(u64)p_hot_cold_file_global,p_hot_cold_file_global->global_age,p_hot_cold_file_global->file_stat_count,p_hot_cold_file_global->file_stat_hot_count,p_hot_cold_file_global->file_stat_count_zero_file_area,p_hot_cold_file_global->file_stat_large_count,p_hot_cold_file_global->all_refault_count);
	}
}

static int async_memory_reclaime_info_show(struct seq_file *m, void *v)
{
	hot_cold_file_print_all_file_stat(&hot_cold_file_global_info,m,1);
	printk_shrink_param(&hot_cold_file_global_info,m,1);
	return 0;
}
int hot_cold_file_proc_init(struct hot_cold_file_global *p_hot_cold_file_global)
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
	p = proc_create("nr_pages_level", S_IRUGO | S_IWUSR, hot_cold_file_proc_root, &nr_pages_level_fops);
	if (!p){
		printk("proc_create nr_pages_level fail\n");
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

	p = proc_create("enable_disable_async_memory_reclaim", S_IRUGO | S_IWUSR, hot_cold_file_proc_root,&enable_disable_async_memory_reclaim_fops);
	if (!p){
		printk("proc_create enable_disable_async_memory_reclaim fail\n");
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
	remove_proc_entry("nr_pages_level",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("open_print",p_hot_cold_file_global->hot_cold_file_proc_root);

	remove_proc_entry("async_memory_reclaime_info",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("async_drop_caches",p_hot_cold_file_global->hot_cold_file_proc_root);
	remove_proc_entry("enable_disable_async_memory_reclaim",p_hot_cold_file_global->hot_cold_file_proc_root);

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
int drop_cache_truncate_inode_pages(struct hot_cold_file_global *p_hot_cold_file_global)
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
					/*这个加个内存屏障，保证前后代码隔离开。即file_stat有delete标记后，inode->i_mapping->rh_reserved1一定是0，p_file_stat->mapping一定是NULL*/
					smp_wmb();
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
			/*inode->i_lock加锁后再测试一次inode是否被其他进程并发iput，是的话下边if成立.到这里不用担心inode结构被其他进程释放了，因为此时
			 *lock_file_stat(p_file_stat)加锁保证，到这里inode结构不会被其他进程释放*/
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
			//设置file_stat in_temp_list最好放到把file_stat添加到global temp链表操作前，原因在add_mmap_file_stat_to_list()有分析
			set_file_stat_in_file_stat_temp_head_list(p_file_stat);
			smp_wmb();
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
void file_stat_free_leak_page(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat *p_file_stat)
{
	struct inode *inode;
	//file_stat加锁，防止此时inode并发被删除了。如果删除了则p_file_stat->mapping 是NULL，直接return
	//并且，如果inode引用计数是0，说明inode马上也要被释放了，没人用了，这种文件file_stat也跳过不处理
	lock_file_stat(p_file_stat,0);
	if(file_stat_in_delete(p_file_stat) || (NULL == p_file_stat->mapping) || atomic_read(&p_file_stat->mapping->host->i_count) == 0){
		unlock_file_stat(p_file_stat);
		return;
	}

	inode = p_file_stat->mapping->host;
	/*inode->i_lock加锁后再测试一次inode是否被其他进程并发iput，是的话下边if成立.到这里不用担心inode结构被其他进程释放了，因为此时
	 * lock_file_stat(p_file_stat)加锁保证，到这里inode结构不会被其他进程释放*/
	spin_lock(&inode->i_lock);
	if( ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW))) || atomic_read(&inode->i_count) == 0){
		spin_unlock(&inode->i_lock);
		unlock_file_stat(p_file_stat);
		return;	
	}
	//令inode引用计数加1,下边file_stat_truncate_inode_pages不用担心inode被其他进程释放掉
	atomic_inc(&inode->i_count);
	spin_unlock(&inode->i_lock);
	unlock_file_stat(p_file_stat);

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

	//截断文件page后再令inode引用计数减1
	iput(inode);
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
		hot_cold_file_global_info.file_stat_count ++;

		memset(p_file_stat,0,sizeof(struct file_stat));
		//设置文件是cache文件状态，有些cache文件可能还会被mmap映射，要与mmap文件互斥，要么是cache文件要么是mmap文件，不能两者都是 
		set_file_stat_in_cache_file(p_file_stat);
		//初始化file_area_hot头结点
		INIT_LIST_HEAD(&p_file_stat->file_area_hot);
		INIT_LIST_HEAD(&p_file_stat->file_area_temp);
		//INIT_LIST_HEAD(&p_file_stat->file_area_cold);
		INIT_LIST_HEAD(&p_file_stat->file_area_free_temp);
		INIT_LIST_HEAD(&p_file_stat->file_area_free);
		INIT_LIST_HEAD(&p_file_stat->file_area_refault);
		INIT_LIST_HEAD(&p_file_stat->file_area_mapcount);

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
