#include "base.h"

/*因为buffer io write的page不会调用到mark_page_accessed()，因此考虑kprobe pagecache_get_page。但是分析generic_file_buffered_read()源码，有概率
 * goto no_cached_page分支，导致本次读的文件页不会调用到find_get_page()->pagecache_get_page()。考虑再三把kprobe的函数换成buffer io read/write 
 * 会执行到拷贝用户空间数据的两个函数*/
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
/*static struct kprobe kp_mark_page_accessed = {
	.symbol_name    = "mark_page_accessed",
};*/
static struct kprobe kp_write_cache_func = {
	.symbol_name    = "iov_iter_copy_from_user_atomic",//buffer io write把数据写入文件页page执行到
};
static struct kprobe kp_read_cache_func = {
	.symbol_name    = "copy_page_to_iter",//buffer io read读取文件页page数据执行到
};
#else
/*static struct kprobe kp_mark_page_accessed = {
	.symbol_name    = "folio_mark_accessed",
};*/
static struct kprobe kp_write_cache_func = {
	.symbol_name    = "copy_page_from_iter_atomic",//buffer io write把数据写入文件页page执行到
};
static struct kprobe kp_read_cache_func = {
	.symbol_name    = "copy_page_to_iter",//buffer io read读取文件页page数据执行到 copy_folio_to_iter()
};
#endif
static struct kprobe kp__destroy_inode = {
	.symbol_name    = "__destroy_inode",
};

static int hot_cold_file_init(void);
static int inline cold_file_stat_delete(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat_del);
static int  cold_mmap_file_stat_delete(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat_del);
static int walk_throuth_all_mmap_file_area(struct hot_cold_file_global *p_hot_cold_file_global);
#ifndef USE_KERNEL_SHRINK_INACTIVE_LIST
static int  solve_reclaim_fail_page(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat *p_file_stat,struct list_head *page_list);
#endif
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
	unsigned int /*shift,*/ offset = 0;
	unsigned long max_area_index;
	struct hot_cold_file_area_tree_node *node = NULL, *child;
	void **slot = (void **)&root->root_node;
	int ret,shift;
	
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
	if(shift < 0)
		panic("%s shift:%d error\n",__func__,shift);

	//page_slot_in_tree是3重指针，*page_slot_in_tree 和 slot 是2重指针，*page_slot_in_tree和slot才能彼此赋值。赋值后*page_slot_in_tree保存的是槽位的地址
	*page_slot_in_tree = slot;
	return node;
}
/*按照索引area_index从radix tree查找file_area，查找失败则创建node节点
 *空树时函数返回NULL并且page_slot_in_tree指向root->root_node的地址。当传入索引很大找不到file_area时，函数返回NULL并且page_slot_in_tree不会被赋值(保持原值NULL)
 * */
static struct hot_cold_file_area_tree_node *hot_cold_file_area_tree_lookup(struct hot_cold_file_area_tree_root *root,
		unsigned long area_index,void ***page_slot_in_tree)
{
	unsigned int /*shift,*/ offset = 0;
	unsigned long max_area_index;
	struct hot_cold_file_area_tree_node *node = NULL, *child;
	void **slot = (void **)&root->root_node;
	int shift;

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
		max_area_index = 0;
		shift = 0;
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
	while (hot_cold_file_area_tree_is_internal_node(child) && (shift > 0)) {
        shift -= TREE_MAP_SHIFT;
		node = entry_to_node(child);
		//根据area_index索引计算在父节点的槽位索引offset
		offset = (area_index >> node->shift) & TREE_MAP_MASK;
		//根据area_index索引计算在父节点的槽位索引offset，找到在父节点的槽位保存的数据，可能是子节点 或者 保存在file_area_tree树最下层节点的file_area指针
		child = rcu_dereference_raw(node->slots[offset]);
		//根据area_index索引计算在父节点的槽位索引offset，令slot指向在父节点的槽位
		slot = &node->slots[offset];
		//下轮循环，node= child 成为新的父节点。slot指向父节点node的某个槽位，这个槽位保存child这个节点指针 或者file_area_tree树最下层节点的file_area_tree指针
	}

	/*如果shift不是0，直接返回NULL，为什么？这是个隐藏很深的bug，在头特定场景下会出大问题。举例，现在radix tree树两层，最多能容纳64*64=4096个成员。
	 *现在根节点只有node.slot[0]和node.slot[1]两个成员，目前只保存了索引是0~127的这128个file_area。现在查找索引是128的file_area，根节点node.slot[2]
	 *是NULL，上边的while循环里，child = rcu_dereference_raw(node->slots[offset])=根节点node.slot[2]=NULL。然后立即while退出循环。shift初值
	 *根节点shift+6=12。因此到这里时shift是6。这种情况下，就说明在查找file_area时，因为它的父节点是NULL(即根节点node[2]是NULL)导致中途结束。
	 *此时应该返回NULL，表示待查找的file_area是NULL。否则是"return node"返回的根节点，并且因为"*page_slot_in_tree = slot"，page_slot_in_tree
	 *指向的file_area的父节点在根节点的槽位地址。这就导致mmap文件页回收reverse_file_stat_radix_tree_hole()函数中，遍历radix tree创建空洞
	 *file_area时，出现lookup的父节点和槽位地址出现错乱的的重大bug*/
	if(0 != shift){
		return NULL;
	}
	else if(shift < 0)
		panic("%s shift:%d error\n",__func__,shift);
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
#if 0
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
				printk("%s file_stat:0x%llx file_area:0x%llx status:%d delete hot_file_area_cache\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state);
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
	/*如果要delete的file_area正是file_stat->file_area_last指向的，则对它清0，并且等所有进程退出hot_file_update_file_status()函数，ref_count为0，
	 *此时确保所有进程不再使用刚才的file_stat->file_area_last了。再执行下边释放这个file_area的代码*/
	else if(p_file_area == p_file_stat->file_area_last){
		/*置NULL已经没什么意义了，不对也有意思，下边只是把bit0置1，将来还要清0，这样file_area_last才是NULL*/
		p_file_stat->file_area_last = NULL;
		smp_wmb();
		/*bit0置1，标记p_file_stat->file_area_last指向的file_area已经要删除了，hot_file_update_file_status函数里就不能再使用file_area_last
		 *指向的file_area了。注意，仅仅有上一行的p_file_stat->file_area_last = NULL是不行的，因为无法确保p_file_stat->file_area_last最新值NULL，
		 *被接下来执行hot_file_update_file_status函数的进程识别到，可能还是p_file_stat->file_area_last老的值。而test_and_set_bit_lock把
		 *p_file_stat->file_area_last的bit0置1，然后等ref_count原子变量是0。之后的进行执行hot_file_update_file_status函数，就能保证看到
		 *p_file_stat->file_area_last的bit0的最新值1了*/
		test_and_set_bit_lock(0,(unsigned long *)(&p_file_stat->file_area_last));
		printk("%s file_stat:0x%llx file_area:0x%llx status:%d delete file_area_last\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state);
		while(atomic_read(&p_hot_cold_file_global->ref_count))
			msleep(1);
	}
#endif
	/*如果待删除的file_area的父节点是p_file_stat->cache_file_area_tree_node，并且它只有一个file_area了，且这个file_area又要被删除了。
	 *那就令cache_file_area_tree_node失效。并且要等所有进程退出hot_file_update_file_status函数，不再访问该文件的file_area radix tree后，
	 *再去下边删除file_area和父节点。防止访问无效的内存*/
	if(p_file_area->parent && p_file_area->parent == p_file_stat->cache_file_area_tree_node && p_file_area->parent->count == 1){
		p_file_stat->cache_file_area_tree_node = NULL;
		while(atomic_read(&p_hot_cold_file_global->ref_count))
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
static int  cold_file_stat_delete(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat_del)
{
	/*1:lock_file_stat加锁原因是:当异步内存回收线程在这里释放file_stat结构时，同一时间file_stat对应文件inode正在被释放而执行到
	 * __destroy_inode_handler_post()函数。如果这里把file_stat释放了，__destroy_inode_handler_post()使用file_stat就要crash。
	 * 而lock_file_stat()防止这种情况。同时，__destroy_inode_handler_post()执行后会立即释放inode和mapping，然后此时这里要用到
	 * p_file_stat->mapping->rh_reserved1，此时同样也会因file_stat已经释放而crash
	 *2:spin_lock(&p_file_stat_del->file_stat_lock)加锁的作用是，此时该文件可能在hot_file_update_file_status()函数被并发访问，分配
	 * 新的file_area，这样该file_stat就不能释放了*/

	lock_file_stat(p_file_stat_del,0);

	spin_lock(&p_file_stat_del->file_stat_lock);
	/*如果file_stat的file_area个数大于0，说明此时该文件被方法访问了，在hot_file_update_file_status()中分配新的file_area。
	 *此时这个file_stat就不能释放了*/
	if(p_file_stat_del->file_area_count > 0){
		/*此时file_stat是不可能有delete标记的，有的话告警。防止__destroy_inode_handler_post中设置了delete。正常不可能，这里有lock_file_stat加锁防护*/
		if(file_stat_in_delete(p_file_stat_del)){
			printk("%s %s %d file_stat:0x%llx status:0x%lx in delete\n",__func__,current->comm,current->pid,(u64)p_file_stat_del,p_file_stat_del->file_stat_status);
			dump_stack();
		}	
		spin_unlock(&p_file_stat_del->file_stat_lock);
		unlock_file_stat(p_file_stat_del);
		return 1;
	}
	/*如果file_stat在__destroy_inode_handler_post中被释放了，file_stat一定有delete标记。否则没有delete标记，这里先标记file_stat的delete*/
	if(0 == file_stat_in_delete(p_file_stat_del)/*p_file_stat_del->mapping*/){
		/*文件inode的mapping->rh_reserved1清0表示file_stat无效，这__destroy_inode_handler_post()删除inode时，发现inode的mapping->rh_reserved1是0就不再使用file_stat了，会crash*/
		p_file_stat_del->mapping->rh_reserved1 = 0;
		barrier();
		p_file_stat_del->mapping = NULL;
		/*在这个加个内存屏障，保证前后代码隔离开。即file_stat有delete标记后，inode->i_mapping->rh_reserved1一定是0，p_file_stat->mapping一定是NULL*/
		smp_wmb();
		set_file_stat_in_delete(p_file_stat_del);
	}
	spin_unlock(&p_file_stat_del->file_stat_lock);

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

	return 0;
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
	//mapcount链表
	list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,&p_file_stat_del->file_area_mapcount,file_area_list){
		if(!file_area_in_mapcount_list(p_file_area) || file_area_in_free_list_error(p_file_area))
			panic("%s file_area:0x%llx status:%d not in file_area_mapcount\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

		cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat_del,p_file_area);
		del_file_area_count ++;
	}


	if(p_file_stat_del->file_area_count != 0){
		panic("file_stat_del:0x%llx file_area_count:%d !=0 !!!!!!!!\n",(u64)p_file_stat_del,p_file_stat_del->file_area_count);
	}

	//把file_stat从p_hot_cold_file_global的链表中剔除，然后释放file_stat结构
	if(file_stat_in_cache_file(p_file_stat_del))
	    cold_file_stat_delete(p_hot_cold_file_global,p_file_stat_del);
    else
	    cold_mmap_file_stat_delete(p_hot_cold_file_global,p_file_stat_del);

	return del_file_area_count;
}

//如果一个文件file_stat超过一定比例(比如50%)的file_area都是热的，则判定该文件file_stat是热文件，file_stat要移动到global file_stat_hot_head链表。返回1是热文件
static int inline is_file_stat_hot_file(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat){
	int ret;

	//如果文件file_stat的file_area个数比较少，则比例按照50%计算
	if(p_file_stat->file_area_count < p_hot_cold_file_global->file_area_level_for_large_file){
		//超过50%的file_area是热的，则判定文件file_stat是热文件
		//if(div64_u64((u64)p_file_stat->file_area_count*100,(u64)p_file_stat->file_area_hot_count) > 50)
		if(p_file_stat->file_area_hot_count > p_file_stat->file_area_count >> 1)
			ret = 1;
		else
			ret = 0;
	}else{
		//否则，文件很大，则必须热file_area超过文件总file_area数的很多很多，才能判定是热文件。因为此时file_area很多，冷file_area的数目有很多，应该遍历回收这种file_area的page
		if(p_file_stat->file_area_hot_count > (p_file_stat->file_area_count - (p_file_stat->file_area_count >> 2)))
			ret  = 1;
		else
			ret =  0;
	}
	return ret;
}
//当文件file_stat的file_area个数超过阀值则判定是大文件
static int inline is_file_stat_large_file(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat)
{
	if(p_file_stat->file_area_count > hot_cold_file_global_info.file_area_level_for_large_file)
		return 1;
	else
		return 0;
}
//模仿page_mapping()判断是否是page cache
static inline struct address_space * hot_cold_file_page_mapping(struct page *page)
{
	struct address_space *mapping;
	/*pagecache读写的page不可能是PageSwapCache(page),并且PageAnon(page)与下边if((unsigned long)mapping&PAGE_MAPPING_ANON)重复了.
	 *也不可能是PageSlab(page)。但tmpfs文件系统里的读写的文件页page，是PageSwapBacked的，这个要过滤掉*/
	if (unlikely(PageSwapBacked(page)) || page_mapped(page) || PageCompound(page) /*PageAnon(page)|| PageSwapCache(page) ||PageSlab(page)*/)
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
static int inline is_file_area_move_list_head(struct file_area *p_file_area)
{
	/*如果file_area当前周期内被访问次数达到阀值，则被移动到链表头。此时file_area可能处于file_stat的hot、refault、temp链表。必须是
	 *if(file_area_access_count_get(p_file_area) == PAGE_COUNT_IN_AREA)，否则之后file_area每被访问一次，就要向链表头移动一次，太浪费性能。
	 *目前限定每个周期内，file_area只能向file_stat的链表头移动一次。为了降低性能损耗，感觉还是性能损耗有点大，比如访问一个2G的文件，从文件头
	 *到文件尾的page每个都被访问一遍，于是每个file_area的page都被访问一次，这样if(file_area_access_count_get(p_file_area) == PAGE_COUNT_IN_AREA)
	 *对每个file_area都成立，每个file_area都移动到file_area->hot、refault、temp链表头，太浪费性能了。于是把就调整成
	 *file_area_access_count_get(p_file_area) > PAGE_COUNT_IN_AREA了!!!!!!!!!!!但这样有个问题，就是不能保证file_area被访问过就立即移动到
	 *file_area->hot、refault、temp链表头，链表尾的file_area就不能保证全是冷file_area了。没办法，性能损耗比较大损耗也是要考虑的!!!!!!!!!!!!!!!!!!!*/
	//if((hot_cold_file_global_info.global_age == p_file_area->file_area_age) && (file_area_access_count_get(p_file_area) == PAGE_COUNT_IN_AREA)){
	if((hot_cold_file_global_info.global_age == p_file_area->file_area_age) && (file_area_access_count_get(p_file_area) > PAGE_COUNT_IN_AREA)){
		return 1;
	}
	/*如果上个周期file_area被访问过，下个周期file_area又被访问，则也把file_area移动到链表头。file_area_access_count_get(p_file_area) > 0
	 *表示上个周期file_area被访问过，hot_cold_file_global_info.global_age - p_file_area->file_area_age == 1表示是连续的两个周期*/
	else if((hot_cold_file_global_info.global_age - p_file_area->file_area_age == 1) && (file_area_access_count_get(p_file_area) > 0)){
		return 1;
	}

	return 0;
}
static struct file_area *file_area_alloc_and_init(struct hot_cold_file_area_tree_node *parent_node,void **page_slot_in_tree,unsigned int area_index_for_page,struct file_stat * p_file_stat)
{
	struct file_area *p_file_area = NULL;

	/*到这里，针对当前page索引的file_area结构还没有分配,page_slot_in_tree是槽位地址，*page_slot_in_tree是槽位里的数据，就是file_area指针，
	  但是NULL，于是针对本次page索引，分配file_area结构*/
	p_file_area = kmem_cache_alloc(hot_cold_file_global_info.file_area_cachep,GFP_ATOMIC);
	if (!p_file_area) {
		//spin_unlock(&p_file_stat->file_stat_lock);
		printk("%s file_area alloc fail\n",__func__);
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

out:
    return p_file_area;
}
int hot_file_update_file_status(struct page *page)
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
		struct hot_cold_file_area_tree_node *parent_node = NULL;
		int ret = 0;
		struct file_stat * p_file_stat = NULL;
		struct file_area *p_file_area = NULL;
		//int i;
		//struct file_area *p_file_area_temp = NULL;
		int file_area_move_list_head = 0;
		
		//async_memory_reclaim_status不再使用smp_rmb内存屏障，而直接使用test_and_set_bit_lock/clear_bit_unlock原子操作
		if(unlikely(!test_bit(ASYNC_MEMORY_RECLAIM_ENABLE,&async_memory_reclaim_status)))
			return 0;

		/*如果文件的文件页page数太少，该文件的文件页page不被本异步内存回收模块统计访问频率并回收，可通过proc接口设置。比如要加
		 * mapping->rh_reserved1 == 0这个判断。因为可能一个文件最初pagecache很多然后被该异步内存回收模块统计到，但是回收了很多
		 * 文件页page后，mapping->nrpages小于nr_pages_level了，此时该文件的文件页page只要被读写了也需要被该模块统计到*/
		if((mapping->rh_reserved1 == 0) && (mapping->nrpages < hot_cold_file_global_info.nr_pages_level)){
			hot_cold_file_global_info.hot_cold_file_shrink_counter.small_file_page_refuse_count ++;
			return 0;
		}

		atomic_inc(&hot_cold_file_global_info.ref_count);
		/*1:与 __destroy_inode_handler_post()函数mapping->rh_reserved1清0的smp_wmb()成对，获取最新的mapping->rh_reserved1数据.
		 *2:还有一个作用，上边的ref_count原子变量加1可能不能禁止编译器重排序，因此这个内存屏障可以防止reorder*/
		smp_rmb();

retry:   
		/*还要再判断一次async_memory_reclaim_status是否是0，因为驱动卸载会先获取原子变量ref_count的值0，然后这里再执行
		 *atomic_inc(&hot_cold_file_global_info.ref_count)令ref_count加1.这种情况必须判断async_memory_reclaim_status是0，
		 *直接return返回。否则驱动卸载过程会释放掉file_stat结构，然后该函数再使用这个file_stat结构，触发crash*/
		if(unlikely(!test_bit(ASYNC_MEMORY_RECLAIM_ENABLE,&async_memory_reclaim_status))){
			ret = -EPERM;
			goto out;
		}
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
			//mapping->rh_reserved1，第2个进程获取锁后执行到这里mapping->rh_reserved1就会成立
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

			//mapping->file_stat记录该文件绑定的file_stat结构，将来判定是否对该文件分配了file_stat
			mapping->rh_reserved1 = (unsigned long)p_file_stat;
			//file_stat记录mapping结构
			p_file_stat->mapping = mapping;
			//设置file_stat in_temp_list最好放到把file_stat添加到global temp链表操作前，原因在add_mmap_file_stat_to_list()有分析
			set_file_stat_in_file_stat_temp_head_list(p_file_stat);
			smp_wmb();
			//把针对该文件分配的file_stat结构添加到hot_cold_file_global_info的file_stat_temp_head链表
			list_add(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.file_stat_temp_head);
			//新分配的file_stat必须设置in_file_stat_temp_head_list链表
			//set_file_stat_in_file_stat_temp_head_list(p_file_stat);
			spin_lock_init(&p_file_stat->file_stat_lock);

			spin_unlock(&hot_cold_file_global_info.global_lock);
		}

already_alloc:	    
		//根据page索引找到所在的file_area的索引，二者关系默认是 file_area的索引 = page索引/6
		area_index_for_page =  page->index >> PAGE_COUNT_IN_AREA_SHIFT;
		p_file_stat = (struct file_stat *)mapping->rh_reserved1;


		/*1:如果mapping->rh_reserved1被其他代码使用，直接返回错误*/
		if(p_file_stat == NULL || p_file_stat->mapping != mapping){
			ret = -EPERM;
			printk("%s p_file_stat:0x%llx status:0x%lx error\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
			goto out;
		}
		
		/*如果这个file_stat对应的文件是mmap文件，现在被cache读写了，直接return，禁止一个文件既是cache文件又是mmap文件。
		 *walk_throuth_all_mmap_file_area()函数有详细介绍*/
		if(file_stat_in_mmap_file(p_file_stat)){
			ret = -EPERM;
			/*不能把p_file_stat->mapping->rh_reserved1清0，否则这个mmap文件的file_stat就失效了，并且这个file_stat结构就泄漏了。
			 *下次这个文件mmap映射，又要再分配file_stat，老的file_stat就内存泄漏了，无效了。mmap的文件的page被read/write读写，
			 *实际测试证实，是正常现象!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

			//p_file_stat->mapping->rh_reserved1 = 0;
			if(shrink_page_printk_open1)
				printk("%s p_file_stat:0x%llx status:0x%lx in_mmap_file\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
			goto out;
		}
		/*分析证实，此时file_stat是可能在file_stat_has_zero_file_area_manage->cold_file_stat_delete()中被并发标记delete的。防护措施
		 *是下边spin_lock(&p_file_stat->file_stat_lock)加锁后，再判断file_stat是否有delete标记有的话，就goto retry分配新的file_stat*/
#if 0
		//如果当前正在使用的file_stat的inode已经释放了，主动触发crash 
		if(file_stat_in_delete(p_file_stat)){
			panic("%s %s %d file_stat:0x%llx status:0x%lx in delete\n",__func__,current->comm,current->pid,(u64)p_file_stat,p_file_stat->file_stat_status);
		}
#endif	

		//每个周期执行hot_file_update_file_status函数访问所有文件的所有file_area总次数
		hot_cold_file_global_info.hot_cold_file_shrink_counter.all_file_area_access_count ++;

		/*如果本次待查找的file_area在p_file_stat->cache_file_area_tree_node缓存数组里，直接获取不用再遍历file_area了*/
		if(area_index_for_page >= p_file_stat->cache_file_area_tree_node_base_index && 
				area_index_for_page <= (p_file_stat->cache_file_area_tree_node_base_index + TREE_MAP_MASK) && p_file_stat->cache_file_area_tree_node){
			unsigned int offset = area_index_for_page & TREE_MAP_MASK;
			p_file_area = p_file_stat->cache_file_area_tree_node->slots[offset];
			/*必须要判断从cache_file_area_tree_node查找的file_area的索引跟本次访问的page的file_area索引是否相等，因为此时可能会有多个进程并发访问
			 *同一个文件，在该函数末尾对p_file_stat->cache_file_area_tree_node_base_index 和 p_file_stat->cache_file_area_tree_node同时赋值，
			 *导致cache_file_area_tree_node_base_index表示的不再是cache_file_area_tree_node的最小file_area的索引，就是二者不一致了!!!!!!!!*/
			if(p_file_area && ((p_file_area->start_index >> PAGE_COUNT_IN_AREA_SHIFT) == area_index_for_page)){
				parent_node = p_file_stat->cache_file_area_tree_node;
				//printk("%s p_file_stat:0x%llx index:%ld area_index_for_page:%d find_file_area\n",__func__,(u64)p_file_stat,page->index,area_index_for_page);
				goto find_file_area;
			}
			p_file_area = NULL;
		}
#if 0
		/*先尝试从p_file_stat->file_area_last得到本次的file_area，file_area不能是热file_area。最近访问过的热file_area保存
		 *在p_file_stat->hot_file_area_cache[]缓存数组。*/
		if(p_file_stat->file_area_last){
			/*file_area_last的bit0置1说明这个file_area已经在cold_file_area_detele函数被标记delete了，就不能再使用了指向的file_area，可能已经释放了*/
			if(likely(test_bit(0,(unsigned long *)(&p_file_stat->file_area_last)) == 0)){
				if(p_file_stat->file_area_last->start_index == (area_index_for_page << PAGE_COUNT_IN_AREA_SHIFT) && !file_area_in_hot_list(p_file_stat->file_area_last)){
					p_file_area = p_file_stat->file_area_last;
					hot_cold_file_global_info.hot_cold_file_shrink_counter.find_file_area_from_last_count ++;
					goto find_file_area;
				}
			}else
				//这里对file_area_last的bit0清0，file_area_last才是NULL,否则一直是1
				clear_bit_unlock(0,(unsigned long *)(&p_file_stat->file_area_last));
		}

		/*先根据索引area_index_for_page从p_file_stat->hot_file_area_cache[]这个缓存buf中找到file_area，这样避免下边file_stat_lock加锁、radix tree遍历
		 *等操作。但是要注意，存在这种情况，a进程正在下边的for循环查找p_file_stat->hot_file_area_cache数组，b进程在这个for循环下边，把热file_area赋值
		 *给p_file_stat->hot_file_area_cache数组，存在这种并发。但是没关系，只要不是把这个数组里的file_area结构释放掉就没事，因为成无效内存访问了*/
		for(i = 0;i < FILE_AREA_CACHE_COUNT;i ++){
			p_file_area_temp = p_file_stat->hot_file_area_cache[i];
			//file_area的起始page索引与file_stat->hot_file_area_cache数组的file_area起始page索引相等
			if(p_file_area_temp)
			{
				if(file_area_in_hot_list(p_file_area_temp))
				{
					//从p_file_stat->hot_file_area_cache数组找到匹配的file_area，简单操作后就返回，避免下边file_stat_lock加锁，radix tree遍历等
					if((area_index_for_page == p_file_area_temp->start_index >> PAGE_COUNT_IN_AREA_SHIFT))
					{
						p_file_area = p_file_area_temp;
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
					/*加这个内存屏障，是保证其他进程看到file_area被清理了in cache状态状态后，p_file_stat->hot_file_area_cache[i] = NULL
					  这个赋值所有cpu也都同步给其他cpu了*/
					smp_wmb();
					clear_file_area_in_cache(p_file_area_temp);
					smp_wmb();
				}
			}
		}
#endif

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
		 *就会导致直接使用if(*page_slot_in_tree)因为page_slot_in_tree是NULL而crash。此时只能靠返回值NULL过滤掉。NO、NO、NO，错了，错了,
		 空树时函数返回NULL并且page_slot_in_tree指向root->root_node的地址。当传入索引很大找不到file_area时，函数返回NULL并且page_slot_in_tree不会被赋值(保持原值NULL)*/
		if(parent_node){
			if(*page_slot_in_tree){
				p_file_area = *page_slot_in_tree;
				if(p_file_area->start_index != (area_index_for_page << PAGE_COUNT_IN_AREA_SHIFT))
					panic("1:p_file_area->start_index:%ld != area_index_for_page:%d\n",p_file_area->start_index,(area_index_for_page << PAGE_COUNT_IN_AREA_SHIFT));

find_file_area:
				//检测file_area被访问的次数，判断是否有必要移动到file_stat->hot、refault、temp等链表头
				file_area_move_list_head = is_file_area_move_list_head(p_file_area);

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
				1：不管file_area处于file_stat的哪个链表，只要file_area_move_list_head大于0，就要移动到所处file_stat->file_area_temp、file_area_hot、
				file_area_refault、file_area_free_temp、file_area_free 链表头
				2: file_area处于 tmemp链表，但是单个周期内访问计数大于热file_area阀值，要晋级为热file_area
				3：file_area处于in-free-list 链表，要晋级到refault链表
				*/
				if(!(file_area_move_list_head || 
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
		/*分析证实，此时file_stat是可能在file_stat_has_zero_file_area_manage->cold_file_stat_delete()中被并发标记delete的。
		 *于是这里spin_lock(&p_file_stat->file_stat_lock)加锁后，判断出file_stat有delete标记，说明file_stat已经要释放，无效了，于是
		 *就goto retry分配新的file_stat*/
		if(file_stat_in_delete(p_file_stat)){
			if(p_file_stat->mapping->rh_reserved1 != 0)
				panic("%s %s %d file_stat:0x%llx status:0x%lx rh_reserved1!= 0\n",__func__,current->comm,current->pid,(u64)p_file_stat,p_file_stat->file_stat_status);

			goto retry;
		}
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
				//分配file_area并初始化，成功返回0
				if(file_area_alloc_and_init(parent_node,page_slot_in_tree,area_index_for_page,p_file_stat) == NULL){
					spin_unlock(&p_file_stat->file_stat_lock);
					goto out;
				}
				/*
				//到这里，针对当前page索引的file_area结构还没有分配,page_slot_in_tree是槽位地址，*page_slot_in_tree是槽位里的数据，就是file_area指针，
				//但是NULL，于是针对本次page索引，分配file_area结构
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
				*/				
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
		 了，再结束遍历。
		 
		 这是最初的策略，现在修改成file_area被访问则移动到file_stat的hot、refault、temp链表头，要经过前边的
		 file_area_move_list_head = is_file_area_move_list_head(p_file_area)判断，file_area_move_list_head为1才会把file_area移动到链表头
		 */
		if(file_area_move_list_head /*file_area_access_count_get(p_file_area) == 2*/)
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

		/*如果file_area处于in_free_list链表，第1次访问就移动到链表头。因为这种file_area可能被判定为refault file_araa，精度要求高.file_area在内存回收
		 *时一直是in_free_list状态，状态不会改变，也不会移动到其他链表！这个时间可能被频繁访问，只有每个周期内第一次被访问才移动到俩表头*/
		if(file_area_access_count_get(p_file_area) == 1 && file_area_in_free_list(p_file_area))
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
#if 0
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
#endif					
				}

			//如果file_area处于file_stat的free_list或free_temp_list链表
			if(file_area_in_free_list(p_file_area)){
				if(file_area_in_free_list(p_file_area))
					clear_file_area_in_free_list(p_file_area);
				//file_area 的page被内存回收后，过了仅N秒左右就又被访问则发生了refault，把该file_area移动到file_area_refault链表，不再参与内存回收扫描!!!!需要设个保护期限制
				smp_rmb();
				if(p_file_area->shrink_time && (ktime_to_ms(ktime_get()) - (p_file_area->shrink_time << 10) < 60000)){
					p_file_area->shrink_time = 0;
					set_file_area_in_refault_list(p_file_area);
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
					//一个周期内产生的refault file_area个数
					hot_cold_file_global_info.hot_cold_file_shrink_counter.refault_file_area_count_one_period ++;
					hot_cold_file_global_info.all_refault_count ++;
				        hot_cold_file_global_info.refault_file_area_count_in_free_page ++;
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
				printk("%s refaut 0x%llx shrink_time:%d\n",__func__,(u64)p_file_area,p_file_area->shrink_time);
				p_file_area->shrink_time = 0;
				clear_file_area_in_temp_list(p_file_area);
				set_file_area_in_refault_list(p_file_area);
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
				//一个周期内产生的refault file_area个数
				hot_cold_file_global_info.hot_cold_file_shrink_counter.refault_file_area_count_one_period ++;
				hot_cold_file_global_info.all_refault_count ++;
				hot_cold_file_global_info.refault_file_area_count_in_free_page ++;
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
		/*p_file_stat->file_area_last保存文件file_stat最近一次访问的file_area，方便下次加速访问。ret是0说明file_area和file_stat都成功访问到
		 *并被赋值，二者都不会是NULL，不用再额外判断二者是否NULL*/
		if(ret == 0){
#if 0	
			//ret的if判断和下边的if必须保证先后顺序
			barrier();
			if(p_file_stat->file_area_last != p_file_area && !file_area_in_hot_list(p_file_area))
				p_file_stat->file_area_last = p_file_area;
#endif
			/*把最近一次访问的文件的file_area的父节点保存到cache_file_area_tree_node，它保存的最小file_area索引保存到
			 *cache_file_area_tree_node_base_index。这样下次再访问同一个父节点的page的file_area，直接从cache_file_area_tree_node->slots[]数组
			 *获取，就不用再遍历radix tree了。但是有个并发问题，就是可能会有多个进程并发访问同一个文件,然后在这里对二者同时赋值，这导致
			 *cache_file_area_tree_node_base_index表示的不再是cache_file_area_tree_node的最小file_area的索引，就是二者不一致了。针对这个问题，
			 *在前边使用二者的代码有防护。还有一个问题，就是如果cache_file_area_tree_node指向的node没删除了怎么办？在delete node的代码有防护，
			 *必须等所有进程退出该函数，才能删除node，类似rcu宽限期，不过这里使用ref_count原子变量实现的*/
			if(p_file_stat->cache_file_area_tree_node != parent_node){
				p_file_stat->cache_file_area_tree_node = parent_node;
				p_file_stat->cache_file_area_tree_node_base_index = area_index_for_page & (~TREE_MAP_MASK);
			}
		}

		//防止原子操作之前重排序
		barrier();
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
EXPORT_SYMBOL(hot_file_update_file_status);

#ifndef USE_KERNEL_SHRINK_INACTIVE_LIST
static unsigned long cold_file_shrink_pages(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat *p_file_stat,bool is_mmap_file)
{
	int i;
	unsigned long nr_reclaimed = 0;
	struct reclaim_stat stat = {};
    struct list_head *p_pgdat_page_list;

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
        if(0 == is_mmap_file)//回收read/write系统调用读写产生的文件页
		    p_pgdat_page_list = &p_hot_cold_file_node_pgdat[i].pgdat_page_list;
		else//回收mmap的文件的文件页
            p_pgdat_page_list = &p_hot_cold_file_node_pgdat[i].pgdat_page_list_mmap_file;

		if(!list_empty(p_pgdat_page_list)){
			//开始释放p_hot_cold_file_node_pgdat[i]->pgdat_page_list链表上的page
			nr_reclaimed += async_shrink_free_page(p_hot_cold_file_node_pgdat[i].pgdat,NULL,p_pgdat_page_list,&sc,&stat);
			if(is_mmap_file)
				//这些page在内存回收时被访问了，file_area移动到refault链表
				solve_reclaim_fail_page(p_hot_cold_file_global,p_file_stat,p_pgdat_page_list);

			//把p_hot_cold_file_node_pgdat[i]->pgdat_page_list链表上未释放成功的page再移动到lru链表
			hot_cold_file_putback_inactive_pages(p_hot_cold_file_node_pgdat[i].pgdat,p_pgdat_page_list);

			//此时p_hot_cold_file_node_pgdat[pgdat->node_id]->pgdat_page_list链表上还残留的page没人再用了，引用计数是0，这里直接释放
			mem_cgroup_uncharge_list_async(p_pgdat_page_list);
			/*重大隐藏bug，如果p_hot_cold_file_node_pgdat[i].pgdat_page_list链表此时还有引用计数是0的page， free_unref_page_list函数就要释放掉
			 *这些page到伙伴系统，是直接list_add到伙伴系统的链表，不是list_move。就是说，没有把page从p_hot_cold_file_node_pgdat[i].pgdat_page_list
			 *链表剔除。这样page就同时存在于伙伴系统的page链表 和 p_hot_cold_file_node_pgdat[i].pgdat_page_list 这个全局链表。这样就有问题了!!!!!!
			 *将来这些残留在p_hot_cold_file_node_pgdat[i].pgdat_page_list链表的page就是一个坑，会被async_shrink_free_page函数错误释放掉!!!!!!!!!
			 *这个bug隐藏的太深了！解决办法在后边重置p_hot_cold_file_node_pgdat[i].pgdat_page_list链表就行了。
			 *对p_hot_cold_file_node_pgdat[i].pgdat_page_list_mmap_file这个全局链表上的page的处理同理!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
			free_unref_page_list_async(p_pgdat_page_list);
			//清空p_hot_cold_file_node_pgdat[i].pgdat_page_list链表，清理可能残留的page
			INIT_LIST_HEAD(p_pgdat_page_list);
		}
	}
	return nr_reclaimed;
}
#endif

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
	//unsigned int scan_large_to_small_count = 0;
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
			//如果大文件突然被删除了，这里要清理标记，并令file_stat_large_count减1
			if(file_stat_in_large_file(p_file_stat)){
				p_hot_cold_file_global->file_stat_large_count --;
				clear_file_stat_in_large_file(p_file_stat);
			}

			scan_delete_file_stat_count ++;
			clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			//如果该文件inode被释放了，则把对应file_stat移动到hot_cold_file_global->file_stat_delete_head链表
			list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_delete_head);
			continue;
		}
		/*如果这个file_stat对应的文件是mmap文件，现在被cache读写了，直接return，禁止一个文件既是cache文件又是mmap文件。
		 *walk_throuth_all_mmap_file_area()函数有详细介绍*/
		else if(file_stat_in_mmap_file(p_file_stat)){
			clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			set_file_stat_in_delete(p_file_stat);
			list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_delete_head);
			p_file_stat->mapping->rh_reserved1 = 0;
			printk("%s p_file_stat:0x%llx status:0x%lx in_mmap_file\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
			continue;
		}

		//如果file_stat的file_area全被释放了，则把file_stat移动到hot_cold_file_global->file_stat_zero_file_area_head链表
		if(p_file_stat->file_area_count == 0){
			//如果大文件的file_area全被释放了，这里要清理标记，并令file_stat_large_count减1，否则会导致file_stat_large_count泄漏
			if(file_stat_in_large_file(p_file_stat)){
				p_hot_cold_file_global->file_stat_large_count --;
				clear_file_stat_in_large_file(p_file_stat);
			}
			clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			set_file_stat_in_zero_file_area_list(p_file_stat);
			p_hot_cold_file_global->file_stat_count_zero_file_area ++;
			//如果该文件inode被释放了，则把对应file_stat移动到hot_cold_file_global->file_stat_zero_file_area_head链表
			list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_zero_file_area_head);
			continue;
		}

		/*file_stat_temp_head来自 hot_cold_file_global->file_stat_temp_head 或 hot_cold_file_global->file_stat_temp_large_file_head 链表，当是
		 * hot_cold_file_global->file_stat_temp_large_file_head时，file_stat_in_large_file(p_file_stat)才会成立*/


#if 0 
		/*当file_stat上有些file_area长时间没有被访问则会释放掉file_are结构。此时原本在hot_cold_file_global->file_stat_temp_large_file_head 链表的
		 *大文件file_stat则会因file_area数量减少而需要降级移动到hot_cold_file_global->file_stat_temp_head链表.这个判断起始可以放到
		 hot_file_update_file_status()函数，算了降低损耗。但是这段代码是冗余，于是把这段把有大文件标记但不再是大文件的file_stat移动到
		 global file_stat_temp_head链表的代码放到内存回收后期执行的free_page_from_file_area()函数里了。这两处的代码本身就是重复操作，
		 hot_file_update_file_status函数也会判断有大文件标记的file_stat是否是大文件*/
		if(file_stat_in_large_file(p_file_stat) && !is_file_stat_large_file(&hot_cold_file_global_info,p_file_stat)){

			scan_large_to_small_count ++;
			clear_file_stat_in_large_file(p_file_stat);
			/*不用现在把file_stat移动到global file_stat_temp_head链表。等该file_stat的file_area经过内存回收后，该file_stat会因为
			 *clear_file_stat_in_large_file而移动到file_stat_temp_head链表。想了想，还是现在就移动到file_stat->file_stat_temp_head链表尾，
			 否则内存回收再移动更麻烦。要移动到链表尾，这样紧接着就会从file_stat_temp_head链表链表尾扫描到该file_stat*/
			list_move_tail(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);
			p_hot_cold_file_global->file_stat_large_count --;
			continue;
		}
#endif	
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

		/*1: cold_file_area_for_file_stat != 0表示把有冷file_area的file_stat移动到file_stat_free_list临时链表.此时的file_sata已经不在
		file_stat_temp_head链表，不用clear_file_stat_in_file_stat_temp_head_list
		2: 如果file_stat->file_area_refault链表非空，说明也需要扫描这上边的file_area，要把上边冷的file_area移动回file_stat_temp_head_list
		链表，参数内存回收扫描，结束保护期
		3: 如果file_stat->file_area_free 和 file_stat->file_area_hot链表上也非空，说明上边也有file_area需要遍历，file_area_hot链表上的冷
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
	//p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_large_to_small_count = scan_large_to_small_count;
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
	unsigned int scan_large_to_small_count = 0;

	/*同一个文件file_stat的file_area对应的page，更大可能是属于同一个内存节点node，所以要基于一个个文件的file_stat来扫描file_area，
	 *避免频繁开关内存节点锁pgdat->lru_lock锁*/  

	//遍历file_stat_free_list临时链表上的file_stat，释放这些file_stat的file_stat->file_area_free_temp链表上的冷file_area的page
	list_for_each_entry(p_file_stat,file_stat_free_list,hot_cold_file_list)
	{
#ifdef USE_KERNEL_SHRINK_INACTIVE_LIST
		isolate_lru_pages += cold_file_isolate_lru_pages_and_shrink(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_free_temp);
		free_pages += p_hot_cold_file_global->hot_cold_file_shrink_counter.free_pages_count;
#else		
		/*对file_area_free_temp上的file_stat上的file_area对应的page进行隔离，隔离成功的移动到
		 *p_hot_cold_file_global->hot_cold_file_node_pgdat->pgdat_page_list对应内存节点链表上*/
		isolate_lru_pages += cold_file_isolate_lru_pages(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_free_temp);
		//这里真正释放p_hot_cold_file_global->hot_cold_file_node_pgdat->pgdat_page_list链表上的内存page
		free_pages += cold_file_shrink_pages(p_hot_cold_file_global,p_file_stat,0);
#endif

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
#if 0	
            /*如果p_file_stat->file_area_last在file_stat->file_area_free链表上，经历过一个周期后还没被访问，那就清空p_file_stat->file_area_last这个cache*/
			if(p_file_stat->file_area_last == p_file_area){
			    p_file_stat->file_area_last = NULL;
			}
#endif			

			if(unlikely(file_area_access_count_get(p_file_area) > 0)){
				/*这段代码时新加的，是个隐藏很深的小bug。file_area在内存回收前都要对access_count清0，但是在内存回收最后，可能因对应page
				 *被访问了而access_count加1，然后对age赋值为当时的global age，但是file_area的page内存回收失败了。等了很长时间后，终于再次
				 *扫描到这个文件file_stat，但是file_area的age还是与global age相差很大了，正常就要判定这个file_area长时间没访问而释放掉。
				 *但这是正常现象不合理的！因为这个file_area的page在内存回收时被访问了。于是就通过file_area的access_count大于0而判定这个file_area的
				 *page在内存回收最后被访问了，于是就不能释放掉file_area。那就要移动到file_stat->temp链表或者refault链表!!!!!!!!!!!!!!!!!!!!*/
				spin_lock(&p_file_stat->file_stat_lock);
				clear_file_area_in_free_list(p_file_area);
				set_file_area_in_temp_list(p_file_area);
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				spin_unlock(&p_file_stat->file_stat_lock);	    
				printk("%s file_area:0x%llx status:0x%x accessed in reclaim\n",__func__,(u64)p_file_area,p_file_area->file_area_state);
			}
			/*如果file_stat->file_area_free链表上的file_area长时间没有被访问则释放掉file_area结构。之前的代码有问题，判定释放file_area的时间是
			 *file_area_free_age_dx，这样有问题，会导致file_area被内存回收后，在下个周期file_area立即被释放掉。原因是file_area_free_age_dx=5，
			 file_area_temp_to_cold_age_dx=5，下个内存回收周期 global_age - file_area_free_age_dx肯定大于5*/
			else if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > 
					(p_hot_cold_file_global->file_area_free_age_dx + p_hot_cold_file_global->file_area_temp_to_cold_age_dx)){
				file_area_free_count ++;
				file_area_count = 0;
				/*hot_file_update_file_status()函数中会并发把file_area从file_stat->file_area_free链表移动到file_stat->file_area_free_temp
				 *链表.这里把file_stat->file_area_free链表上的file_area剔除掉并释放掉，需要spin_lock(&p_file_stat->file_stat_lock)加锁，
				 *这个函数里有加锁*/
				cold_file_area_detele(p_hot_cold_file_global,p_file_stat,p_file_area);
			}
			else{
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
				p_hot_cold_file_global->refault_file_area_count_in_free_page --;
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
				p_hot_cold_file_global->refault_file_area_count_in_free_page ++;
				hot_cold_file_global_info.all_refault_count ++;
				hot_cold_file_global_info.hot_cold_file_shrink_counter.refault_file_area_count_one_period ++;
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
					//之前是小文件，内存回收期间变成大文件，这种情况再设置大文件标记
					if(!file_stat_in_large_file(p_file_stat)){
					    set_file_stat_in_large_file(p_file_stat);
					    /*这个if成立，说明是内存回收期间小文件变成大文件。因为file_stat期间不是in_temp_list状态，update函数不会
					     * 把文件file_stat移动到大文件链表，也不会file_stat_large_count加1，只能这里加1了*/
					    p_hot_cold_file_global->file_stat_large_count ++;
                                        }
					//p_hot_cold_file_global->file_stat_large_count ++;//大文件数加1，这不是新产生的大文件，已经加过1了
					list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_large_file_head);
				}
				else//普通文件
				{	
					/*如果file_stat有大文件标记，说明之前是大文件，但是经过多轮内存回收、释放file_stat->file_area_free链表上
					 * file_area后，不再是大文件了，就移动到global file_stat_temp_head链表。但是必须清理掉大文件标记。否则这
					 * 会导致状态错误:file_stat_temp_head链表上的file_stat有大文件标记，将来即便再变成大文件也无法移动到大文件链表*/
					if(file_stat_in_large_file(p_file_stat)){
					    clear_file_stat_in_large_file(p_file_stat);
					    p_hot_cold_file_global->file_stat_large_count --;
					}
					list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);
				}
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
	//扫描到的大文件转小文件的个数
	p_hot_cold_file_global->hot_cold_file_shrink_counter.scan_large_to_small_count = scan_large_to_small_count;

	if(shrink_page_printk_open)
		printk("5:%s %s %d p_hot_cold_file_global:0x%llx free_pages:%d isolate_lru_pages:%d file_stat_temp_head:0x%llx file_area_free_count:%d file_area_refault_to_list_temp_count:%d file_area_hot_to_temp_list_count:%d\n",__func__,current->comm,current->pid,(u64)p_hot_cold_file_global,free_pages,isolate_lru_pages,(u64)file_stat_temp_head,file_area_free_count,file_area_refault_to_temp_list_count,file_area_hot_to_temp_list_count);
	return free_pages;
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

			//如果返回值大于0说明file_stat对应文件被并发访问了，于是goto file_stat_access分支处理
			if(cold_file_stat_delete(p_hot_cold_file_global,p_file_stat) > 0)
				goto file_stat_access;

			del_file_stat_count ++;
			//0个file_area的file_stat个数减1
			p_hot_cold_file_global->file_stat_count_zero_file_area --;
		}
		/*如果p_file_stat->file_area_count大于0，说明最近被访问了，则把file_stat移动回 gloabl file_stat_temp_head、file_stat_temp_large_file_head、
		 *file_stat_hot_head链表。hot_file_update_file_status()不会把file_stat移动回热文件或大文件或普通文件链表吗？不会，因为此时file_stat是
		 *in_zero_file_area_list状态，只有file_stat_in_temp_list状态才会移动到*/
		else if (p_file_stat->file_area_count > 0)
		{
file_stat_access:		
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
			else if(is_file_stat_large_file(p_hot_cold_file_global,p_file_stat)){
				set_file_stat_in_file_stat_temp_head_list(p_file_stat); 
				set_file_stat_in_large_file(p_file_stat);
				//这不是新产生的大文件，已经加过1了。错了，这是新产生的大文件，与hot_file_update_file_status()产生的大文件效果一样
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

	memset(&p_hot_cold_file_global->hot_cold_file_shrink_counter,0,sizeof(struct hot_cold_file_shrink_counter));
	
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

	if(0 == test_bit(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status))
		return 0;
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

	if(0 == test_bit(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status))
		return 0;

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
				//set_file_stat_in_large_file(p_file_stat);重复设置状态
				//p_hot_cold_file_global->file_stat_large_count ++;//这不是新产生的大文件，已经加过1了 
				list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_large_file_head);
			}
			else
				list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->file_stat_temp_head);
			spin_unlock(&p_hot_cold_file_global->global_lock);
		}
	}

	if(0 == test_bit(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status))
		return 0;

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

	if(0 == test_bit(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status))
		return 0;

	//对没有file_area的file_stat的处理
	file_stat_has_zero_file_area_manage(p_hot_cold_file_global);

	//如果此时echo 触发了drop_cache，ASYNC_DROP_CACHES置1，则禁止异步内存回收线程处理global drop_cache_file_stat_head链表上的file_stat
	if(!test_bit(ASYNC_DROP_CACHES, &async_memory_reclaim_status))
	    //处理drop cache的文件的pagecache
	    drop_cache_truncate_inode_pages(p_hot_cold_file_global);

	if(0 == test_bit(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status))
		return 0;

	//打印所有file_stat的file_area个数和page个数
	if(shrink_page_printk_open1)
	    hot_cold_file_print_all_file_stat(p_hot_cold_file_global,NULL,0);
	//打印内存回收时统计的各个参数
	if(shrink_page_printk_open1)
	    printk_shrink_param(p_hot_cold_file_global,NULL,0);

	/*每个周期打印hot_cold_file_shrink_counter参数后清0*/
	//memset(&p_hot_cold_file_global->hot_cold_file_shrink_counter,0,sizeof(struct hot_cold_file_shrink_counter));
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
	unsigned int del_mmap_file_area_count = 0,del_mmap_file_stat_count = 0;
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

	/*针对mmap文件的**************************/
	//hot_cold_file_global->mmap_file_stat_temp_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->mmap_file_stat_temp_head,hot_cold_file_list){
		/*标记 p_file_stat->mapping->rh_reserved1=0，表示该文件的file_stat已经释放了。注意，该函数会使用global_lock锁，是cache文件读写使用的。
		 *mmap文件用的是mmap_file_global_lock锁。但是在这个驱动卸载释放所有的file_stat和file_area场景，mmap文件使用global_lock锁页无所谓，无非
		 *增加global_lock锁的耗时而已*/
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_stat_count ++;
	}
	//hot_cold_file_global->mmap_file_stat_zero_file_area_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->mmap_file_stat_zero_file_area_head,hot_cold_file_list){
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_stat_count ++;
	}
	//hot_cold_file_global->mmap_file_stat_delete_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->mmap_file_stat_delete_head,hot_cold_file_list){
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_stat_count ++;
	}
	//hot_cold_file_global->mmap_file_stat_temp_large_file_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->mmap_file_stat_temp_large_file_head,hot_cold_file_list){
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_stat_count ++;
	}
	//hot_cold_file_global->mmap_file_stat_hot_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->mmap_file_stat_hot_head,hot_cold_file_list){
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_stat_count ++;
	}
	//hot_cold_file_global->mmap_file_stat_uninit_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->mmap_file_stat_uninit_head,hot_cold_file_list){
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_stat_count ++;
	}
	//hot_cold_file_global->mmap_file_stat_mapcount_head链表
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->mmap_file_stat_mapcount_head,hot_cold_file_list){
		cold_file_disable_file_stat_mapping(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_area_count += cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
		del_mmap_file_stat_count ++;
	}

	if(p_hot_cold_file_global->mmap_file_stat_count != 0){
		panic("cold_file_delete_all_file_stat: file_stat_count:%d !=0 !!!!!!!!\n",p_hot_cold_file_global->mmap_file_stat_count);
	}

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
		if(test_bit(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status))
		{
	        //每个周期global_age加1
	        hot_cold_file_global_info.global_age ++;
			walk_throuth_all_file_area(p_hot_cold_file_global);
			walk_throuth_all_mmap_file_area(p_hot_cold_file_global);
		}
	}
	return 0;
}

static int hot_cold_file_init(void)
{
	int node_count,i;
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

	INIT_LIST_HEAD(&hot_cold_file_global_info.mmap_file_stat_temp_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.mmap_file_stat_zero_file_area_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.mmap_file_stat_delete_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.mmap_file_stat_temp_large_file_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.mmap_file_stat_hot_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.mmap_file_stat_uninit_head);
	INIT_LIST_HEAD(&hot_cold_file_global_info.mmap_file_stat_mapcount_head);

	spin_lock_init(&hot_cold_file_global_info.global_lock);
	spin_lock_init(&hot_cold_file_global_info.mmap_file_global_lock);

	atomic_set(&hot_cold_file_global_info.ref_count,0);
	atomic_set(&hot_cold_file_global_info.inode_del_count,0);

	hot_cold_file_global_info.file_area_hot_to_temp_age_dx = FILE_AREA_HOT_to_TEMP_AGE_DX;
	hot_cold_file_global_info.file_area_refault_to_temp_age_dx = FILE_AREA_REFAULT_TO_TEMP_AGE_DX;
	hot_cold_file_global_info.file_area_temp_to_cold_age_dx = FILE_AREA_TEMP_TO_COLD_AGE_DX;
	hot_cold_file_global_info.file_area_free_age_dx = FILE_AREA_FREE_AGE_DX;
	hot_cold_file_global_info.file_stat_delete_age_dx  = FILE_STAT_DELETE_AGE_DX;
	hot_cold_file_global_info.global_age_period = ASYNC_MEMORY_RECLIAIM_PERIOD;

	//256M的page cache对应file_area个数，被判定为大文件
	hot_cold_file_global_info.file_area_level_for_large_file = (256*1024*1024)/(4096 *PAGE_COUNT_IN_AREA);
	//mmap的文件，文件页超过50M就判定为大文件
	hot_cold_file_global_info.mmap_file_area_level_for_large_file = (50*1024*1024)/(4096 *PAGE_COUNT_IN_AREA);
	//64K对应的page数
	hot_cold_file_global_info.nr_pages_level = 16;

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
		INIT_LIST_HEAD(&hot_cold_file_global_info.p_hot_cold_file_node_pgdat[i].pgdat_page_list_mmap_file);
	}

	hot_cold_file_global_info.hot_cold_file_thead = kthread_run(hot_cold_file_thread,&hot_cold_file_global_info, "hot_cold_file_thread");
	if (IS_ERR(hot_cold_file_global_info.hot_cold_file_thead)) {
		printk("Failed to start  hot_cold_file_thead\n");
		return -1;

	}
	
	//获取用到的内核非export的函数指针
	if(look_up_not_export_function())
		return -1;

	//如果编译进内核，就不用再禁止slab random，编译成ko才禁止slab random
#if defined(CONFIG_X86) && defined(CONFIG_ENABLE_KPROBE)
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
	printk("disable slab random\n");
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

		/*注意，现在增加了对mmap文件异步内存回收的支持，因此inode的删除也要考虑mmap文件的*/

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
				/*在这个加个内存屏障，保证前后代码隔离开。即file_stat有delete标记后，inode->i_mapping->rh_reserved1一定是0，p_file_stat->mapping一定是NULL*/
				smp_wmb();

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

			/*补充，因为现在支持proc接口使能/禁止 异步内存回收，因此走到这个分支也有可能是proc接口禁止异步内存回收了，而不是驱动卸载.
			 * 还有，这个流程mmap文件删除inode，也会用到global_lock锁，但是分析没事，只是增加global_lock的耗时*/
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



/***以下代码是针对mmap文件的*********************************************************************************************************/
/***以下代码是针对mmap文件的*********************************************************************************************************/
/***以下代码是针对mmap文件的*********************************************************************************************************/
#define BUF_PAGE_COUNT (PAGE_COUNT_IN_AREA * 8)
#define SCAN_PAGE_COUNT_ONCE (PAGE_COUNT_IN_AREA * 8)

#define FILE_AREA_REFAULT 0
#define FILE_AREA_FREE 1
#define FILE_AREA_MAPCOUNT 2
#define FILE_AREA_HOT 3

//文件page扫描过一次后，去radix tree扫描空洞page时，一次在保存file_area的radix tree上扫描的node节点个数，一个节点64个file_area
#define SCAN_FILE_AREA_NODE_COUNT 2
#define FILE_AREA_PER_NODE TREE_MAP_SIZE

//一个冷file_area，如果经过FILE_AREA_TO_FREE_AGE_DX个周期，仍然没有被访问，则释放掉file_area结构
#define MMAP_FILE_AREA_TO_FREE_AGE_DX  30
//发生refault的file_area经过FILE_AREA_REFAULT_TO_TEMP_AGE_DX个周期后，还没有被访问，则移动到file_area_temp链表
#define MMAP_FILE_AREA_REFAULT_TO_TEMP_AGE_DX 30
//普通的file_area在FILE_AREA_TEMP_TO_COLD_AGE_DX个周期内没有被访问则被判定是冷file_area，然后释放这个file_area的page
#define MMAP_FILE_AREA_TEMP_TO_COLD_AGE_DX  10//这个参数调的很小容易在file_area被内存回收后立即释放，这样测试了很多bug，先不要改

//file_area如果在 MMAP_FILE_AREA_HOT_AGE_DX 周期内被检测到访问 MMAP_FILE_AREA_HOT_DX 次，file_area被判定为热file_area
#define MMAP_FILE_AREA_HOT_DX 2
//hot链表上的file_area在MMAP_FILE_AREA_HOT_TO_TEMP_AGE_DX个周期内没有被访问，则降级到temp链表
#define MMAP_FILE_AREA_HOT_TO_TEMP_AGE_DX 10

//mapcount的file_area在MMAP_FILE_AREA_MAPCOUNT_AGE_DX个周期内不再遍历访问，降低性能损耗
#define MMAP_FILE_AREA_MAPCOUNT_AGE_DX 5
//hot链表上的file_area在MMAP_FILE_AREA_HOT_AGE_DX个周期内不再遍历访问，降低性能损耗
#define MMAP_FILE_AREA_HOT_AGE_DX 20
//free链表上的file_area在MMAP_FILE_AREA_HOT_AGE_DX个周期内不再遍历访问，降低性能损耗
#define MMAP_FILE_AREA_FREE_AGE_DX 5
//refault链表上的file_area在MMAP_FILE_AREA_HOT_AGE_DX个周期内不再遍历访问，降低性能损耗
#define MMAP_FILE_AREA_REFAULT_AGE_DX 5

//每次扫描文件file_stat的热file_area个数
#define SCAN_HOT_FILE_AREA_COUNT_ONCE 8
//每次扫描文件file_stat的mapcount file_area个数
#define SCAN_MAPCOUNT_FILE_AREA_COUNT_ONCE 8
//当扫描完一轮文件file_stat的temp链表上的file_area时，进入冷却期，在MMAP_FILE_AREA_COLD_AGE_DX个age周期内不再扫描这个文件上的file_area
#define MMAP_FILE_AREA_COLD_AGE_DX 5

static struct kprobe kp__xfs_file_mmap = {
	.symbol_name    = "xfs_file_mmap",
};
static struct kprobe kp__ext4_file_mmap = {
	.symbol_name    = "ext4_file_mmap",
};

//如果一个文件file_stat超过一定比例的file_area都是热的，则判定该文件file_stat是热文，件返回1是热文件
static int inline is_mmap_file_stat_hot_file(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat){
	int ret;

	//如果文件file_stat的file_area个数比较少，超过3/4的file_area是热的，则判定文件file_stat是热文件
	if(p_file_stat->file_area_count < p_hot_cold_file_global->mmap_file_area_level_for_large_file){
		//if(div64_u64((u64)p_file_stat->file_area_count*100,(u64)p_file_stat->file_area_hot_count) > 50)
		if(p_file_stat->file_area_hot_count >= (p_file_stat->file_area_count - (p_file_stat->file_area_count >> 2)))
			ret = 1;
		else
			ret = 0;
	}else{
		//否则，文件很大，则必须热file_area超过文件总file_area个数的7/8，才能判定是热文件，这个比例后续看具体情况调整吧
		if(p_file_stat->file_area_hot_count > (p_file_stat->file_area_count - (p_file_stat->file_area_count >> 3)))
			ret  = 1;
		else
			ret =  0;
	}
	return ret;
}
//当文件file_stat的file_area个数超过阀值则判定是大文件
static int inline is_mmap_file_stat_large_file(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat)
{
	if(p_file_stat->file_area_count > hot_cold_file_global_info.mmap_file_area_level_for_large_file)
		return 1;
	else
		return 0;
}
//如果一个文件file_stat超过一定比例的file_area的page都是mapcount大于1的，则判定该文件file_stat是mapcount文件，件返回1是mapcount文件
static int inline is_mmap_file_stat_mapcount_file(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat)
{
	int ret;

	//如果文件file_stat的file_area个数比较少，超过3/4的file_area是mapcount的，则判定文件file_stat是mapcount文件
	if(p_file_stat->file_area_count < p_hot_cold_file_global->mmap_file_area_level_for_large_file){
		//if(div64_u64((u64)p_file_stat->file_area_count*100,(u64)p_file_stat->file_area_hot_count) > 50)
		if(p_file_stat->mapcount_file_area_count >= (p_file_stat->file_area_count - (p_file_stat->file_area_count >> 2)))
			ret = 1;
		else
			ret = 0;
	}else{
		//否则，文件很大，则必须热file_area超过文件总file_area个数的7/8，才能判定是mapcount文件，这个比例后续看具体情况调整吧
		if(p_file_stat->mapcount_file_area_count > (p_file_stat->file_area_count - (p_file_stat->file_area_count >> 3)))
			ret  = 1;
		else
			ret =  0;
	}
	return ret;
}
#ifndef USE_KERNEL_SHRINK_INACTIVE_LIST
//mmap的文件页page，内存回收失败，测试发现都是被访问页表pte置位了，则把这些page移动到file_stat->refault链表
static int  solve_reclaim_fail_page(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat *p_file_stat,struct list_head *page_list)
{
	struct page *page;
	pgoff_t last_index,area_index_for_page;
	struct file_area *p_file_area;
	void **page_slot_in_tree = NULL;
	struct hot_cold_file_area_tree_node *parent_node;

	last_index = (unsigned long)-1;
	list_for_each_entry(page,page_list,lru){

		area_index_for_page = page->index >> PAGE_COUNT_IN_AREA_SHIFT;
		//前后两个page都属于同一个file_area
		if(last_index == area_index_for_page)
			continue;

		last_index = area_index_for_page;
		parent_node = hot_cold_file_area_tree_lookup(&p_file_stat->hot_cold_file_area_tree_root_node,area_index_for_page,&page_slot_in_tree);
		if(IS_ERR(parent_node) || NULL == *page_slot_in_tree){
			panic("2:%s hot_cold_file_area_tree_lookup_and_create fail parent_node:0x%llx page_slot_in_tree:0x%llx\n",__func__,(u64)parent_node,(u64)page_slot_in_tree);
		}
		p_file_area = (struct file_area *)(*page_slot_in_tree);
		/*有可能前边的循环已经把这个file_area移动到refault链表了，那此时if不成立*/
		if(file_area_in_free_list(p_file_area)){
			if(file_area_in_free_list_error(p_file_area)){
				panic("%s file_area:0x%llx status:%d not in file_area_free\n",__func__,(u64)p_file_area,p_file_area->file_area_state);
			}

			/*file_area的page在内存回收时被访问了，file_area移动到refault链表。但如果page的mapcount大于1，那要移动到file_area_mapcount链表*/
			if(page_mapcount(page) == 1){
			    clear_file_area_in_free_list(p_file_area);
			    set_file_area_in_refault_list(p_file_area);
			    list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);
				if(shrink_page_printk_open1)
					printk("%s page:0x%llx file_area:0x%llx status:%d move to refault list\n",__func__,(u64)page,(u64)p_file_area,p_file_area->file_area_state);
			}
			else{
				p_file_stat->mapcount_file_area_count ++;
			    //file_area的page的mapcount大于1，则把file_area移动到file_stat->file_area_mapcount链表
			    clear_file_area_in_free_list(p_file_area);
			    set_file_area_in_mapcount_list(p_file_area);
			    list_move(&p_file_area->file_area_list,&p_file_stat->file_area_mapcount);
				if(shrink_page_printk_open1)
					printk("%s page:0x%llx file_area:0x%llx status:%d move to mapcount list\n",__func__,(u64)page,(u64)p_file_area,p_file_area->file_area_state);

				/*如果文件file_stat的mapcount的file_area个数超过阀值，则file_stat被判定为mapcount file_stat而移动到
			    *global mmap_file_stat_mapcount_head链表。但前提file_stat必须在temp_file链表或temp_large_file链表*/
				if(is_mmap_file_stat_mapcount_file(p_hot_cold_file_global,p_file_stat) && file_stat_in_file_stat_temp_head_list(p_file_stat)){
					 if(file_stat_in_file_stat_temp_head_list_error(p_file_stat))
						 panic("%s file_stat:0x%llx status error:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

					 clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
					 set_file_stat_in_mapcount_file_area_list(p_file_stat);
					 list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_mapcount_head);
					 p_hot_cold_file_global->mapcount_mmap_file_stat_count ++;
					 if(shrink_page_printk_open1)
						 printk("%s file_stat:0x%llx status:0x%llx is mapcount file\n",__func__,(u64)p_file_stat,(u64)p_file_stat->file_stat_status);
				}
			}
		}
	}
	return 0;
}
#endif
static int  cold_mmap_file_stat_delete(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat_del)
{  

	//spin_lock(&p_hot_cold_file_global->mmap_file_global_lock);-----有了global->mmap_file_stat_uninit_head链表后，从global temp删除file_stat，不用再加锁

	//p_file_stat_del->mapping = NULL;多余操作
	clear_file_stat_in_file_stat_temp_head_list(p_file_stat_del);
	list_del(&p_file_stat_del->hot_cold_file_list);
	//差点忘了释放file_stat结构，不然就内存泄漏了!!!!!!!!!!!!!!
	kmem_cache_free(p_hot_cold_file_global->file_stat_cachep,p_file_stat_del);
	hot_cold_file_global_info.mmap_file_stat_count --;

	//spin_unlock(&p_hot_cold_file_global->mmap_file_global_lock);

	return 0;
}
/*对文件inode加锁，如果inode已经处于释放状态则返回0，此时不能再遍历该文件的inode的address_space的radix tree获取page，释放page，
 *此时inode已经要释放了，inode、address_space、radix tree都是无效内存。否则，令inode引用计数加1，然后其他进程就无法再释放这个
 *文件的inode，此时返回1*/
static int inline file_inode_lock(struct file_stat * p_file_stat)
{
	struct inode *inode = p_file_stat->mapping->host;

	/*这里有个隐藏很深的bug!!!!!!!!!!!!!!!!如果此时并发执行inode delete函数，可能执行到spin_lock(&inode->i_lock)时，
	 *inode已经被释放了，那就要crash。因此要并发与inode delete函数执行file_stat_lock()，如果file_stat_lock成功后。
	 *inode已经释放了则file_stat_in_delete(p_file_stat)成立，直接return，不再使用inode*/
	lock_file_stat(p_file_stat,0);
	if(file_stat_in_delete(p_file_stat) || (NULL == p_file_stat->mapping)){
		//不要忘了异常return要先释放锁
		unlock_file_stat(p_file_stat);
		return 0;
	}

	spin_lock(&inode->i_lock);
	//执行到这里，inode肯定没有被释放，并且inode->i_lock加锁成功，其他进程就无法再释放这个inode了
	unlock_file_stat(p_file_stat);

	//如果inode已经被标记释放了，直接return
	if( ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW))) || atomic_read(&inode->i_count) == 0){
		spin_unlock(&inode->i_lock);

		//如果inode已经释放了，则要goto unsed_inode分支释放掉file_stat结构
		return 0;
	}
	//令inode引用计数加1,下边file_stat_truncate_inode_pages不用担心inode被其他进程释放掉
	atomic_inc(&inode->i_count);
	spin_unlock(&inode->i_lock);

	return 1;
}
/*令inode引用计数减1，如果inode引用计数是0则释放inode结构*/
static void inline file_inode_unlock(struct file_stat * p_file_stat)
{
    struct inode *inode = p_file_stat->mapping->host;
    //令inode引用计数减1，如果inode引用计数是0则释放inode结构
	iput(inode);
}

static  unsigned int check_one_file_area_cold_page_and_clear(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct file_area *p_file_area,struct page *page_buf[],int *cold_page_count)
{
	unsigned long vm_flags;
	int ret = 0;
	struct page *page;
	unsigned cold_page_count_temp = 0;
	int i,j;
	struct address_space *mapping = p_file_stat->mapping;
	int file_area_cold = 0;
	struct page *pages[PAGE_COUNT_IN_AREA];
	int mapcount_file_area = 0;
	int file_area_is_hot = 0;

	//file_area已经很长一段时间没有被访问则file_area_cold置1，只有在这个大前提下，file_area的page pte没有被访问，才能回收page
	if(p_hot_cold_file_global->global_age - p_file_area->file_area_age >  MMAP_FILE_AREA_TEMP_TO_COLD_AGE_DX)
		file_area_cold = 1;

	if(cold_page_count)
		cold_page_count_temp = *cold_page_count;

	/*存在一种情况，file_area的page都是非mmap的，普通文件页，这样该函数也会返回0!!!!!!!!!!!!!!!!*/
	memset(pages,0,PAGE_COUNT_IN_AREA*sizeof(struct page *));
	//获取p_file_area对应的文件页page指针并保存到pages数组
	ret = get_page_from_file_area(p_file_stat,p_file_area->start_index,pages);
	if(shrink_page_printk_open)
		printk("1:%s file_stat:0x%llx file_area:0x%llx get %d page\n",__func__,(u64)p_file_stat,(u64)p_file_area,ret);

	if(ret <= 0)
	    goto out; 

	//ret必须清0，否则会影响下边ret += page_referenced_async的ret大于0，误判page被访问pte置位了
	ret = 0;
	for(i = 0;i < PAGE_COUNT_IN_AREA;i ++){
		//page = xa_load(&mapping->i_pages, p_file_area->start_index + i);
		page = pages[i];
		/*这里判断并清理 映射page的页表页目录pte的access bit，是否有必要对page lock_page加锁呢?需要加锁*/
		if (page && !xa_is_value(page)) {
			/*对page上锁，上锁失败就休眠，这里回收mmap的文件页的异步内存回收线程，这里没有加锁且对性能没有要求，可以休眠
			 *到底用lock_page还是trylock_page？如果trylock_page失败的话，说明这个page最近被访问了，那肯定不是冷page，就不用执行
			 *下边的page_referenced检测page的 pte了，浪费性能。??????????????????????????????????????????????????
			 *为什么用trylock_page呢？因为page_lock了实际有两种情况 1：其他进程访问这个page然后lock_page，2：其他进程内存回收
			 *这个page然后lock_pagea。后者page并不是被其他进程被访问而lock了！因此只能用lock_page了，然后再
			 *page_referenced判断page pte，因为这个page可能被其他进程内存回收而lock_page，并不是被访问了lock_page
			 */
			if(shrink_page_printk_open)
				printk("2:%s page:0x%llx index:%ld %ld_%d\n",__func__,(u64)page,page->index,p_file_area->start_index,i);
			lock_page(page);
			//if(trylock_page(page))------不要删
			{
				/*如果page被其他进程回收了，if不成立，这些就不再对该file_area的其他page进行内存回收了，其实
				 *也可以回收，但是处理起来很麻烦，后期再考虑优化优化细节吧!!!!!!!!!!!!!!!!!!!!!!*/
				if(page->mapping != mapping){
					if(shrink_page_printk_open1)
						printk("3:%s file_stat:0x%llx file_area:0x%llx status:0x%x page->mapping != mapping!!!!!!!!!\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state);

					unlock_page(page);
					continue;
				}
				/*如果page不是mmap的要跳过。一个文件可能是cache文件，同时也被mmap映射，因此这类的文件页page可能不是mmap的，只是cache page
				 *这个判断必须放到lock_page后边*/
				if (!page_mapped(page)){
					unlock_page(page);
					if(shrink_page_printk_open1)
						printk("4:%s file_stat:0x%llx file_area:0x%llx status:0x%x page:0x%llx not in page_mapped error!!!!!!\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state,(u64)page);

					continue;
				}
				
				if(0 == mapcount_file_area && page_mapcount(page) > 1)
					mapcount_file_area = 1;

				//检测映射page的页表pte access bit是否置位了，是的话返回1并清除pte access bit。错了，不是返回1，是反应映射page的进程个数
				/*page_referenced函数第2个参数是0里边会自动执行lock page()*/
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
				ret += page_referenced_async(page, 1, page_memcg(page),&vm_flags);
#else
				ret += page_referenced_async(page_folio(page), 1, page_memcg(page),&vm_flags);
#endif
				if(shrink_page_printk_open)
					printk("5:%s file_stat:0x%llx file_area:0x%llx page:0x%llx index:%ld file_area_cold:%d cold_page_count:%d ret:%d page_mapcount:%d access_count:%d\n",__func__,(u64)p_file_stat,(u64)p_file_area,(u64)page,page->index,file_area_cold,cold_page_count == NULL ?-1:*cold_page_count,ret,page_mapcount(page),file_area_access_count_get(p_file_area));

				/*ret大于0说明page最近被访问了，不是冷page，则赋值全局age*/
				if(ret > 0){
					unlock_page(page);
					//本次file_area已经被判定为热file_area了，continue然后遍历下一个page
					if(file_area_is_hot)
						continue;
					file_area_is_hot = 1;

					//不能放在这里，这样二者就相等了,if(p_hot_cold_file_global->global_age - p_file_area->file_area_age <= MMAP_FILE_AREA_HOT_AGE_DX)永远成立
					//p_file_area->file_area_age = p_hot_cold_file_global->global_age;

					/*file_area必须在temp_list链表再令file_area的access_count加1，如果在固定周期内file_area的page被访问次数超过阀值，就判定为热file_area。
					 *file_area可能也在refault_list、free_list也会执行到这个函数，要过滤掉*/
					if(file_area_in_temp_list(p_file_area)){
						//file_area如果在 MMAP_FILE_AREA_HOT_AGE_DX 周期内被检测到访问 MMAP_FILE_AREA_HOT_DX 次，file_area被判定为热file_area
						if(p_hot_cold_file_global->global_age - p_file_area->file_area_age <= MMAP_FILE_AREA_HOT_AGE_DX){

						    //file_area的page被访问了，file_area的access_count加1
						    file_area_access_count_add(p_file_area);
							//在规定周期内file_area被访问次数大于MMAP_FILE_AREA_HOT_DX则file_area被判定为热file_area
							if(file_area_access_count_get(p_file_area) > MMAP_FILE_AREA_HOT_DX){
								//被判定为热file_area后，对file_area的access_count清0
								file_area_access_count_clear(p_file_area);

								//file_stat->temp 链表上的file_area个数减1
								p_file_stat->file_area_count_in_temp_list --;
								//file_area移动到hot链表
								clear_file_area_in_temp_list(p_file_area);
								set_file_area_in_hot_list(p_file_area);
								list_move(&p_file_area->file_area_list,&p_file_stat->file_area_hot);
								//该文件的热file_area数加1
								p_file_stat->file_area_hot_count ++;
								if(shrink_page_printk_open)
									printk("6:%s file_stat:0x%llx file_area:0x%llx is hot status:0x%x\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state);

								//如果文件的热file_area个数超过阀值则被判定为热文件，文件file_stat移动到global mmap_file_stat_hot_head链表
								if(is_mmap_file_stat_hot_file(p_hot_cold_file_global,p_file_stat) && file_stat_in_file_stat_temp_head_list(p_file_stat)){
									clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
									set_file_stat_in_file_stat_hot_head_list(p_file_stat);
									list_move(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.mmap_file_stat_hot_head);
									hot_cold_file_global_info.hot_mmap_file_stat_count ++;
									if(shrink_page_printk_open)
										printk("7:%s file_stat:0x%llx status:0x%llx is hot file\n",__func__,(u64)p_file_stat,(u64)p_file_stat->file_stat_status);
								}
							}
						}else{
							//超过MMAP_FILE_AREA_HOT_AGE_DX个周期后对file_area访问计数清0
							file_area_access_count_clear(p_file_area);
						}
					}

					p_file_area->file_area_age = p_hot_cold_file_global->global_age;
					
					/*这里非常重要。当file_area的一个page发现最近访问过，不能break跳出循环。而是要继续循环把file_area剩下的page也执行
					 *page_referenced()清理掉page的pte access bit。否则，这些pte access bit置位的page会对file_area接下来的冷热造成
					 *重大误判。比如，file_area对应page0~page3，page的pte access bit全置位了。在global_age=1时，执行到该函数，这个for循环
					 *里执行page_referenced()判断出file_area的page0的pte access bit置位了，判断这个file_area最近访问过，然后自动清理掉page的
					 *pte access bit。等global_age=8,10,15时，依次又在该函数的for循环判断出page1、page2、page3的pte access bit置位了。这不仅
					 *导致误判该file_area是热的！实际情况是，page0~page3在global_age=1被访问过一次后就没有再被访问了，等到global_age=15正常
					 *要被判定为冷file_area而回收掉page。但实际却错误连续判定这个file_area一直被访问。解决方法注释掉break，换成continue，这样在
					 *global_age=1时，就会把page0~page3的pte access bit全清0，就不会影响后续判断了。但是这样性能损耗会增大，后续有打算
					 *只用file_area里的1个page判断冷热，不在扫描其他page*/
					//break;
					continue;
				}else{
					/*否则，file_area的page没有被访问，要不要立即就对file_area的access_count清0??????? 修改成，如过了规定周期file_area的page依然没被访问再对
					 *file_area的access_count清0*/
					if(file_area_in_temp_list(p_file_area) && (p_hot_cold_file_global->global_age - p_file_area->file_area_age > MMAP_FILE_AREA_HOT_AGE_DX)){
						file_area_access_count_clear(p_file_area);
					}
				}

				/*cold_page_count不是NULL说明此时遍历的是file_stat->file_area_temp链表上的file_area。否则，遍历的是
				 *file_stat->file_area_refault和file_stat->file_area_free_temp链表上的file_area，使用完page就需要unlock_page*
				 *file_area_cold是1说明此file_area是冷的，file_area的page也没有被访问，然后才回收这个file_area的page*/
				if(cold_page_count != NULL && file_area_cold){
					if(*cold_page_count < BUF_PAGE_COUNT){

						if(p_hot_cold_file_global->global_age - p_file_area->file_area_age <  MMAP_FILE_AREA_TEMP_TO_COLD_AGE_DX - 2)
							panic("%s file_stat:0x%llx status:0x%llx is hot ,can not reclaim\n",__func__,(u64)p_file_stat,(u64)p_file_stat->file_stat_status);

						//冷page保存到page_buf[]，然后参与内存回收
						page_buf[*cold_page_count] = page;
						*cold_page_count = *cold_page_count + 1;
					}
					else
						panic("%s %d error\n",__func__,*cold_page_count);
				}else{
					unlock_page(page);
				}
		 }
			/*-------很重要，不要删
			  else{
			//到这个分支，说明page被其他先lock了。1：其他进程访问这个page然后lock_page，2：其他进程内存回收这个page然后lock_pagea。
			//到底要不要令ret加1呢？想来想去不能，于是上边把trylock_page(page)改成lock_page
			//ret += 1;
			}*/
		}
	}
   
	//必须是处于global temp链表上的file_stat->file_area_temp 链表上的file_area再判断是否是mapcountfile_area
	if(file_stat_in_file_stat_temp_head_list(p_file_stat) && file_area_in_temp_list(p_file_area)){
		/*如果上边for循环遍历的file_area的page的mapcount都是1，且file_area的page上边没有遍历完，则这里继续遍历完剩余的page*/
		while(0 == mapcount_file_area && i < PAGE_COUNT_IN_AREA){
			page= pages[i];
			if (page && !xa_is_value(page) && page_mapped(page) && page_mapcount(page) > 1){
				mapcount_file_area = 1;
			}
			i ++;
		}
		if(mapcount_file_area){
			//file_stat->temp 链表上的file_area个数减1
			p_file_stat->file_area_count_in_temp_list --;
			//文件file_stat的mapcount的file_area个数加1
			p_file_stat->mapcount_file_area_count ++;
			//file_area的page的mapcount大于1，则把file_area移动到file_stat->file_area_mapcount链表
			clear_file_area_in_temp_list(p_file_area);
			set_file_area_in_mapcount_list(p_file_area);
			list_move(&p_file_area->file_area_list,&p_file_stat->file_area_mapcount);
			if(shrink_page_printk_open)
				printk("8:%s file_stat:0x%llx file_area:0x%llx state:0x%x temp to mapcount\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state);

			/*如果文件file_stat的mapcount的file_area个数超过阀值，则file_stat被判定为mapcount file_stat而移动到
			 *global mmap_file_stat_mapcount_head链表。但前提file_stat必须在temp_file链表或temp_large_file链表*/
			if(is_mmap_file_stat_mapcount_file(p_hot_cold_file_global,p_file_stat) /*&& file_stat_in_file_stat_temp_head_list(p_file_stat)*/){
				 if(file_stat_in_file_stat_temp_head_list_error(p_file_stat))
					 panic("%s file_stat:0x%llx status error:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

				 clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
				 set_file_stat_in_mapcount_file_area_list(p_file_stat);
				 list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_mapcount_head);
				 p_hot_cold_file_global->mapcount_mmap_file_stat_count ++;
				 if(shrink_page_printk_open1)
					 printk("9:%s file_stat:0x%llx status:0x%llx is mapcount file\n",__func__,(u64)p_file_stat,(u64)p_file_stat->file_stat_status);
			}
		}
    }

	/*到这里有这些可能
	 *1: file_area的page都是冷的，ret是0
	 *2: file_area的page有些被访问了，ret大于0
	 *3：file_area的page都是冷的，但是有些page前边trylock_page失败了，ret大于0。这种情况目前已经不可能了
	 */
	//历的是file_stat->file_area_temp链表上的file_area是if才成立
	if(ret > 0 && cold_page_count != NULL && file_area_cold){
		/*走到这里，说明file_area的page可能是热的，或者page_lock失败，那就不参与内存回收了。那就要对已加锁的page解锁*/
		//不回收该file_area的page，恢复cold_page_count
		*cold_page_count = cold_page_count_temp;
		/*解除上边加锁的page lock，cold_page_count ~ cold_page_count+i 的page上边加锁了，这里解锁*/
		for(j = 0 ;j < i;j++){
			page = page_buf[*cold_page_count + j];
			if(page){
				if(shrink_page_printk_open1)
					printk("10:%s file_stat:0x%llx file_area:0x%llx cold_page_count:%d page:0x%llx\n",__func__,(u64)p_file_stat,(u64)p_file_area,*cold_page_count,(u64)page);

				unlock_page(page);
			}
		}
	}
out:
	//返回值是file_area里4个page是热page的个数
	return ret;
}
/*1:遍历file_stat->file_area_mapcount上的file_area，如果file_area的page的mapcount都是1，file_area不再是mapcount file_area，则降级到file_stat->temp链表
 *2:遍历file_stat->file_area_hot、refault上的file_area，如果长时间不被访问了，则降级到file_stat->temp链表
 *3:遍历file_stat->file_area_free链表上的file_area，如果对应page还是长时间不访问则释放掉file_area，如果被访问了则升级到file_stat->temp链表
 */

//static int reverse_file_area_mapcount_and_hot_list(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct list_head *file_area_list_head,int traversal_max_count,char type,int age_dx)//file_area_list_head 是p_file_stat->file_area_mapcount 或 p_file_stat->file_area_hot链表
static int reverse_other_file_area_list(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct list_head *file_area_list_head,int traversal_max_count,char type,int age_dx)//file_area_list_head 是p_file_stat->file_area_mapcount、hot、refault、free链表
{
	unsigned int scan_file_area_count = 0;
	struct file_area *p_file_area,*p_file_area_temp;
	struct page *pages[PAGE_COUNT_IN_AREA];
	int i,ret;
	LIST_HEAD(file_area_list);
	struct page *page;

	list_for_each_entry_safe_reverse(p_file_area,p_file_area_temp,file_area_list_head,file_area_list){//从链表尾开始遍历
		//如果file_area_list_head 链表尾的file_area在规定周期内不再遍历，降低性能损耗。链表尾的file_area的file_area_access_age更小，
		//它的file_area_access_age与global_age相差小于age_dx，链表头的更小于
		if(p_hot_cold_file_global->global_age - p_file_area->file_area_access_age <= age_dx){
			if(shrink_page_printk_open)
				printk("1:%s file_stat:0x%llx type:%d  global_age:%ld file_area_access_age:%ld age_dx:%d\n",__func__,(u64)p_file_stat,type,p_hot_cold_file_global->global_age,p_file_area->file_area_access_age,age_dx);

			break;
		}
		if(scan_file_area_count ++ > traversal_max_count)
			break;

		if(FILE_AREA_MAPCOUNT == type){
			if(!file_area_in_mapcount_list(p_file_area) || file_area_in_mapcount_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_mapcount\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			/*存在一种情况，file_area的page都是非mmap的，普通文件页，这样该函数也会返回0!!!!!!!!!!!!!!!!*/
			memset(pages,0,PAGE_COUNT_IN_AREA*sizeof(struct page *));
			//获取p_file_area对应的文件页page指针并保存到pages数组
			ret = get_page_from_file_area(p_file_stat,p_file_area->start_index,pages);
			if(shrink_page_printk_open1)
				printk("1:%s file_stat:0x%llx file_area:0x%llx get %d page--------->\n",__func__,(u64)p_file_stat,(u64)p_file_area,ret);

			//file_area被遍历到时记录当时的global_age，不管此时file_area的page是否被访问pte置位了
			p_file_area->file_area_access_age = p_hot_cold_file_global->global_age;
			//这个file_area没有page，直接遍历下一个file_area
			if(ret <= 0)
				continue;

			for(i = 0;i < ret;i ++){
				page = pages[i];
				if(page_mapcount(page) > 1)
					break;
			}
			//if成立说明file_area的page的mapcount都是1，file_area不再是mapcount file_area，则降级到temp_list链表头
			if(i == ret){
				//file_stat->refault、free、hot、mapcount链表上的file_area移动到file_stat->temp链表时要先对file_area->file_area_access_age清0，原因看定义
				p_file_area->file_area_access_age = 0;
				clear_file_area_in_mapcount_list(p_file_area);
				set_file_area_in_temp_list(p_file_area);
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				//在file_stat->file_area_temp链表的file_area个数加1
				p_file_stat->file_area_count_in_temp_list ++;
				//在file_stat->file_area_mapcount链表的file_area个数减1
				p_file_stat->mapcount_file_area_count --;
			}
			else{
				/*否则file_area移动到file_area_list临时链表。但要防止前边file_area被移动到其他file_stat的链表了，此时就不能再把该file_area
				 *移动到file_area_list临时链表，否则该函数最后会把file_area再移动到老的file_stat链表，file_area的状态和所处链表就错乱了，会crash*/
				if(file_area_in_mapcount_list(p_file_area))
				    list_move(&p_file_area->file_area_list,&file_area_list);
				else
					printk("%s %d file_area:0x%llx status:%d changed\n",__func__,__LINE__,(u64)p_file_area,p_file_area->file_area_state);
			}

		}else if(FILE_AREA_HOT == type){
			if(!file_area_in_hot_list(p_file_area) || file_area_in_hot_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_hot\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			//file_area被遍历到时记录当时的global_age，不管此时file_area的page是否被访问pte置位了
			p_file_area->file_area_access_age = p_hot_cold_file_global->global_age;

			//检测file_area的page最近是否被访问了
			ret = check_one_file_area_cold_page_and_clear(p_hot_cold_file_global,p_file_stat,p_file_area,NULL,NULL);
			//file_area的page被访问了，依然停留在hot链表
			if(ret > 0){
				/*否则file_area移动到file_area_list临时链表。但要防止前边check_one_file_area_cold_page_and_clear()函数file_area被
				 *移动到其他file_stat的链表了，此时就不能再把该file_area移动到file_area_list临时链表，
				 否则该函数最后会把file_area再移动到老的file_stat链表，file_area的状态和所处链表就错乱了，会crash*/
				if(file_area_in_hot_list(p_file_area))
				    list_move(&p_file_area->file_area_list,&file_area_list);
				else
				    printk("%s %d file_area:0x%llx status:%d changed\n",__func__,__LINE__,(u64)p_file_area,p_file_area->file_area_state);

			}
			//file_area在MMAP_FILE_AREA_HOT_TO_TEMP_AGE_DX个周期内没有被访问，则降级到temp链表
			else if(p_hot_cold_file_global->global_age - p_file_area->file_area_age >MMAP_FILE_AREA_HOT_TO_TEMP_AGE_DX){
				//file_stat->refault、free、hot、mapcount链表上的file_area移动到file_stat->temp链表时要先对file_area->file_area_access_age清0，原因看定义
				p_file_area->file_area_access_age = 0;

				clear_file_area_in_hot_list(p_file_area);
				set_file_area_in_temp_list(p_file_area);
				barrier();
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				//在file_stat->file_area_temp链表的file_area个数加1
				p_file_stat->file_area_count_in_temp_list ++;
				//在file_stat->file_area_hot链表的file_area个数减1
				p_file_stat->file_area_hot_count --;
			}
		}
		/*遍历file_stat->file_area_refault链表上的file_area，如果长时间没访问，要把file_area移动回file_stat->file_area_temp链表*/
		else if(FILE_AREA_REFAULT == type ){
			if(!file_area_in_refault_list(p_file_area) || file_area_in_refault_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_refault\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			//file_area被遍历到时记录当时的global_age，不管此时file_area的page是否被访问pte置位了
			p_file_area->file_area_access_age = p_hot_cold_file_global->global_age;

			//检测file_area的page最近是否被访问了
			ret = check_one_file_area_cold_page_and_clear(p_hot_cold_file_global,p_file_stat,p_file_area,NULL,NULL);
			if(ret > 0){
				/*否则file_area移动到file_area_list临时链表。但要防止前边check_one_file_area_cold_page_and_clear()函数file_area被
				 *移动到其他file_stat的链表了，此时就不能再把该file_area移动到file_area_list临时链表，
				 否则该函数最后会把file_area再移动到老的file_stat链表，file_area的状态和所处链表就错乱了，会crash*/
				if(file_area_in_refault_list(p_file_area))
				    list_move(&p_file_area->file_area_list,&file_area_list);
				else
				    printk("%s %d file_area:0x%llx status:%d changed\n",__func__,__LINE__,(u64)p_file_area,p_file_area->file_area_state);

			}
			//file_area在MMAP_FILE_AREA_REFAULT_TO_TEMP_AGE_DX个周期内没有被访问，则降级到temp链表
			else if(p_hot_cold_file_global->global_age - p_file_area->file_area_age >MMAP_FILE_AREA_REFAULT_TO_TEMP_AGE_DX){
				//file_stat->refault、free、hot、mapcount链表上的file_area移动到file_stat->temp链表时要先对file_area->file_area_access_age清0，原因看定义
				p_file_area->file_area_access_age = 0;

				clear_file_area_in_refault_list(p_file_area);
				set_file_area_in_temp_list(p_file_area);
				barrier();
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				//在file_stat->file_area_temp链表的file_area个数加1
				p_file_stat->file_area_count_in_temp_list ++;
			}
		}
		/*遍历file_stat->file_area_free_temp链表上file_area，如果长时间不被访问则释放掉file_area结构。如果短时间被访问了，则把file_area移动到
		 *file_stat->file_area_refault链表，如果过了很长时间被访问了，则把file_area移动到file_stat->file_area_temp链表*/
		else if(FILE_AREA_FREE == type){

			if(!file_area_in_free_list(p_file_area) || file_area_in_free_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_free\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			//file_area被遍历到时记录当时的global_age，不管此时file_area的page是否被访问pte置位了
			p_file_area->file_area_access_age = p_hot_cold_file_global->global_age;

			//检测file_area的page最近是否被访问了
			ret = check_one_file_area_cold_page_and_clear(p_hot_cold_file_global,p_file_stat,p_file_area,NULL,NULL);
			if(0 == ret){
				//file_stat->file_area_free_temp链表上file_area，如果长时间不被访问则释放掉file_area结构，里边有把file_area从链表剔除的代码
				if(p_hot_cold_file_global->global_age - p_file_area->file_area_age > MMAP_FILE_AREA_TO_FREE_AGE_DX){
					clear_file_area_in_free_list(p_file_area);
					cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat,p_file_area);
				}else{
					/*否则file_area移动到file_area_list临时链表。但要防止前边check_one_file_area_cold_page_and_clear()函数file_area被
					 *移动到其他file_stat的链表了，此时就不能再把该file_area移动到file_area_list临时链表，
					 否则该函数最后会把file_area再移动到老的file_stat链表，file_area的状态和所处链表就错乱了，会crash*/
					if(file_area_in_free_list(p_file_area))
						list_move(&p_file_area->file_area_list,&file_area_list);
					else
						printk("%s %d file_area:0x%llx status:%d changed\n",__func__,__LINE__,(u64)p_file_area,p_file_area->file_area_state);
				}
			}else{
				if(0 == p_file_area->shrink_time)
					panic("%s file_stat:0x%llx status:0x%lx p_file_area->shrink_time == 0\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

				//file_area的page被访问而pte置位了，则file_area->file_area_age记录当时的全局age。然后把file_area移动到file_stat->refault或temp链表
				//在check_one_file_area_cold_page_and_clear函数如果page被访问过，就会对file_area->file_area_age赋值，这里就不用再赋值了
				//p_file_area->file_area_age = p_hot_cold_file_global->global_age;

				clear_file_area_in_free_list(p_file_area);
				/*file_stat->file_area_free_temp链表上file_area，短时间被访问了，则把file_area移动到file_stat->file_area_refault链表。否则
				 *移动到file_stat->file_area_temp链表*/
				if(p_file_area->shrink_time && (ktime_to_ms(ktime_get()) - (p_file_area->shrink_time << 10) < 130000)){
					set_file_area_in_refault_list(p_file_area);
					barrier();
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);	
				}
				else{
					//file_stat->refault、free、hot、mapcount链表上的file_area移动到file_stat->temp链表时要先对file_area->file_area_access_age清0
					p_file_area->file_area_access_age = 0;
					set_file_area_in_temp_list(p_file_area);
					barrier();
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
					//在file_stat->file_area_temp链表的file_area个数加1
					p_file_stat->file_area_count_in_temp_list ++;
				}
				p_file_area->shrink_time = 0;
			}
		}

		//在把file_area移动到其他链表后，file_area_list_head链表可能是空的，没有file_area了，就结束遍历。其实这个判断list_for_each_entry_safe_reverse也有
		if(list_empty(file_area_list_head)){
			break;
		}
	}
	//如果file_area_list临时链表上有file_area，则要移动到 file_area_list_head链表头，最近遍历过的file_area移动到链表头
	if(!list_empty(&file_area_list)){
		list_splice(&file_area_list,file_area_list_head);
	}
	if(shrink_page_printk_open1)
		printk("2:%s file_stat:0x%llx type:%d scan_file_area_count:%d\n",__func__,(u64)p_file_stat,type,scan_file_area_count);
	return scan_file_area_count;
}

#if 0 //这段代码不要删除，有重要价值
/*遍历file_stat->file_area_refault和file_stat->file_area_free_temp链表上的file_area，根据具体情况处理*/
static int reverse_file_area_refault_and_free_list(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,struct file_area **file_area_last,struct list_head *file_area_list_head,int traversal_max_count,char type)
{//file_area_list_head 是file_stat->file_area_refault或file_stat->file_area_free_temp链表头

	int ret;
	unsigned int scan_file_area_count = 0;
	struct file_area *p_file_area,*p_file_area_temp;
	char delete_file_area_last = 0;

	printk("1:%s file_stat:0x%llx file_area_last:0x%llx type:%d\n",__func__,(u64)p_file_stat,(u64)*file_area_last,type);
	if(*file_area_last){//本次从上一轮扫描打断的file_area继续遍历
		p_file_area = *file_area_last;
	}
	else{
		//第一次从链表尾的file_area开始遍历
		p_file_area = list_last_entry(file_area_list_head,struct file_area,file_area_list);
		*file_area_last = p_file_area;
	}

	do {
		/*查找file_area在file_stat->file_area_temp链表上一个file_area。如果p_file_area不是链表头的file_area，直接list_prev_entry
		 * 找到上一个file_area。如果p_file_stat是链表头的file_area，那要跳过链表过，取出链表尾的file_area*/
		if(!list_is_first(&p_file_area->file_area_list,file_area_list_head))
			p_file_area_temp = list_prev_entry(p_file_area,file_area_list);
		else
			p_file_area_temp = list_last_entry(file_area_list_head,struct file_area,file_area_list);

		//检测file_area的page最近是否被访问了
		ret = check_one_file_area_cold_page_and_clear(p_hot_cold_file_global,p_file_stat,p_file_area,NULL,NULL);

		/*遍历file_stat->file_area_refault链表上的file_area，如果长时间没访问，要把file_area移动回file_stat->file_area_temp链表*/
		if(FILE_AREA_REFAULT == type ){
			if(!file_area_in_refault_list(p_file_area) || file_area_in_refault_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_refault\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			if(ret > 0){
				p_file_area->file_area_age = p_hot_cold_file_global->global_age;
			}
			//file_area在MMAP_FILE_AREA_REFAULT_TO_TEMP_AGE_DX个周期内没有被访问，则降级到temp链表
			else if(p_hot_cold_file_global->global_age - p_file_area->file_area_age >MMAP_FILE_AREA_REFAULT_TO_TEMP_AGE_DX){
				//这段if判断代码的原因分析见check_file_area_cold_page_and_clear()函数
				if(*file_area_last == p_file_area){
					*file_area_last = p_file_area_temp;
					delete_file_area_last = 1;
				}
				clear_file_area_in_refault_list(p_file_area);
				set_file_area_in_temp_list(p_file_area);
				barrier();
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				//在file_stat->file_area_temp链表的file_area个数加1
				p_file_stat->file_area_count_in_temp_list ++;
			}
		}
		/*遍历file_stat->file_area_free_temp链表上file_area，如果长时间不被访问则释放掉file_area结构。如果短时间被访问了，则把file_area移动到
		 *file_stat->file_area_refault链表，如果过了很长时间被访问了，则把file_area移动到file_stat->file_area_temp链表*/
		else if(FILE_AREA_FREE == type){

			if(!file_area_in_free_list(p_file_area) || file_area_in_free_list_error(p_file_area))
				panic("%s file_area:0x%llx status:%d not in file_area_free\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

			if(0 == ret){
				//file_stat->file_area_free_temp链表上file_area，如果长时间不被访问则释放掉file_area结构，里边有把file_area从链表剔除的代码
				if(p_hot_cold_file_global->global_age - p_file_area->file_area_age >  MMAP_FILE_AREA_TEMP_TO_COLD_AGE_DX){
					//这段if代码的原因分析见check_file_area_cold_page_and_clear()函数
					if(*file_area_last == p_file_area){
						*file_area_last = p_file_area_temp;
						delete_file_area_last = 1;
					}
					clear_file_area_in_free_list(p_file_area);
					cold_file_area_detele_quick(p_hot_cold_file_global,p_file_stat,p_file_area);
				}
			}else{
				if(0 == p_file_area->shrink_time)
					panic("%s file_stat:0x%llx status:0x%lx p_file_area->shrink_time == 0\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

				//这段if代码的原因分析见check_file_area_cold_page_and_clear()函数
				if(*file_area_last == p_file_area){
					*file_area_last = p_file_area_temp;
					delete_file_area_last = 1;
				}

				p_file_area->file_area_age = p_hot_cold_file_global->global_age;
				clear_file_area_in_free_list(p_file_area);
				/*file_stat->file_area_free_temp链表上file_area，短时间被访问了，则把file_area移动到file_stat->file_area_refault链表。否则
				 *移动到file_stat->file_area_temp链表*/
				if(p_file_area->shrink_time && (ktime_to_ms(ktime_get()) - (p_file_area->shrink_time << 10) < 5000)){
					set_file_area_in_refault_list(p_file_area);
					barrier();
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_refault);	
				}
				else{
					set_file_area_in_temp_list(p_file_area);
					barrier();
					list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
					//在file_stat->file_area_temp链表的file_area个数加1
					p_file_stat->file_area_count_in_temp_list ++;
				}
				p_file_area->shrink_time = 0;
			}
		}

		//下一个扫描的file_area
		p_file_area = p_file_area_temp;

		//超过本轮扫描的最大file_area个数则结束本次的遍历
		if(scan_file_area_count > traversal_max_count)
			break;
		scan_file_area_count ++;

		if(0 == delete_file_area_last && p_file_area == *file_area_last)
			break;
		else if(delete_file_area_last)
			delete_file_area_last = 0;

		/*这里退出循环的条件，不能碰到链表头退出，是一个环形队列的遍历形式,以下两种情况退出循环
		 *1：上边的 遍历指定数目的file_area后，强制结束遍历
		 *2：这里的while，本次循环处理到file_area已经是第一次循环处理过了，相当于重复了
		 *3: 添加!list_empty(&file_area_list_head)判断，详情见check_file_area_cold_page_and_clear()分析
		 */
		//}while(p_file_area != *file_area_last && !list_empty(file_area_list_head));
    }while(!list_empty(file_area_list_head));

	if(!list_empty(file_area_list_head)){
		/*下个周期直接从file_area_last指向的file_area开始扫描*/
		if(!list_is_first(&p_file_area->file_area_list,file_area_list_head))
			*file_area_last = list_prev_entry(p_file_area,file_area_list);
		else
			*file_area_last = list_last_entry(file_area_list_head,struct file_area,file_area_list);
	}else{
		/*这里必须对file_area_last清NULL，否则下次执行该函数，file_area_last指向的是一个非法的file_area，从而触发crash。比如
		 *file_stat->file_area_free链表只有一个file_area，因为长时间不被访问，执行cold_file_area_detele_quick()释放了。但是释放
		 前，先执行*file_area_last = p_file_area_temp赋值，这个赋值令*file_area_last指向刚释放的file_area，因为p_file_area_temp
		 指向释放的file_area，file_stat->file_area_free链表只有这一个file_area！继续，释放唯一的file_area后，此时file_stat->file_area_free链表空
		 (即file_area_list_head链表空)，则跳出while循环。然后 *file_area_last 还是指向刚释放file_area。下次执行该函数，使用 *file_area_last
		 这个指向的已经释放的file_aera，就会crash*/
		*file_area_last = NULL;
	}

    return scan_file_area_count;
}
#endif

#if 0 //这段源码不要删除，牵涉到一个内存越界的重大bug!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
/*文件的radix tree在遍历完一次所有的page后，可能存在空洞，于是后续还要再遍历文件的radix tree获取之前没有遍历到的page*/
static unsigned int reverse_file_stat_radix_tree_hole(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat)
{
	int i,j,k;
	struct hot_cold_file_area_tree_node *parent_node;
	void **page_slot_in_tree = NULL;
	unsigned int area_index_for_page;
	int ret = 0;
	struct page *page;
	unsigned int file_page_count = p_file_stat->mapping->host->i_size >> PAGE_SHIFT;//除以4096
	unsigned int start_page_index = 0;
	struct address_space *mapping = p_file_stat->mapping;

	//p_file_stat->traverse_done是0，说明还没有遍历完一次文件的page，那先返回
	if(0 == p_file_stat->traverse_done)
		return ret;

	printk("1:%s file_stat:0x%llx file_stat->last_index:0x%d\n",__func__,(u64)p_file_stat,p_file_stat->last_index);

	//p_file_stat->last_index初值是0，后续依次是64*1、64*2、64*3等等，
	area_index_for_page = p_file_stat->last_index;

	//一次遍历SCAN_FILE_AREA_NODE_COUNT个node，一个node 64个file_area
	for(i = 0;i < SCAN_FILE_AREA_NODE_COUNT;i++){
		/*查找索引0、64*1、64*2、64*3等等的file_area的地址，保存到page_slot_in_tree。page_slot_in_tree指向的是每个node节点的第一个file_area，
		 *每个node节点一共64个file_area，都保存在node节点的slots[64]数组。下边的for循环一次查找node->slots[0]~node->slots[63]，如果是NULL，
		 *说明还没有分配file_area，是空洞，那就分配file_area并添加到radix tree。否则说明file_area已经分配了，就不用再管了*/
		parent_node = hot_cold_file_area_tree_lookup_and_create(&p_file_stat->hot_cold_file_area_tree_root_node,area_index_for_page,&page_slot_in_tree);
		if(IS_ERR(parent_node)){
			ret = -1;
			printk("%s hot_cold_file_area_tree_lookup_and_create fail\n",__func__);
			goto out;
		}
		/*一个node FILE_AREA_PER_NODE(64)个file_area。下边靠着page_slot_in_tree++依次遍历这64个file_area，如果*page_slot_in_tree
		 *是NULL，说明是空洞file_area，之前这个file_area对应的page没有分配，也没有分配file_area，于是按照area_index_for_page<<PAGE_COUNT_IN_AREA_SHIFT
		 *这个page索引，在此查找page是否分配了，是的话就分配file_area*/
		for(j = 0;j < FILE_AREA_PER_NODE - 1;){

			printk("2:%s file_stat:0x%llx i:%d j:%d page_slot_in_tree:0x%llx\n",__func__,(u64)p_file_stat,i,j,(u64)(*page_slot_in_tree));
			//如果是空树，parent_node是NULL，page_slot_in_tree是NULL，*page_slot_in_tree会导致crash
			if(NULL == *page_slot_in_tree){
				//第一次area_index_for_page是0时，start_page_index取值，依次是 0*4 、1*4、2*4、3*4....63*4
				start_page_index = (area_index_for_page + j) << PAGE_COUNT_IN_AREA_SHIFT;
				//page索引超过文件最大page数，结束遍历
				if(start_page_index > file_page_count){
					printk("3:%s start_page_index:%d > file_page_count:%d\n",__func__,start_page_index,file_page_count);
					ret = 1;
					goto out;
				}
				for(k = 0;k < PAGE_COUNT_IN_AREA;k++){
					/*这里需要优化，遍历一次radix tree就得到4个page，完全可以实现的，节省性能$$$$$$$$$$$$$$$$$$$$$$$$*/
					page = xa_load(&mapping->i_pages, start_page_index + k);
					//空洞file_area的page被分配了，那就分配file_area
					if (page && !xa_is_value(page) && page_mapped(page)) {

						//分配file_area并初始化，成功返回0，函数里边把新分配的file_area赋值给*page_slot_in_tree，即在radix tree的槽位
						if(file_area_alloc_and_init(parent_node,page_slot_in_tree,page->index >> PAGE_COUNT_IN_AREA_SHIFT,p_file_stat) < 0){
							ret = -1;
							goto out;
						}
						printk("3:%s file_stat:0x%llx alloc file_area:0x%llx\n",__func__,(u64)p_file_stat,(u64)(*page_slot_in_tree));
						/*4个连续的page只要有一个在radix tree找到，分配file_area,之后就不再查找其他page了*/
						break;
					}
				}
				printk("3:%s start_page_index:%d > file_page_count:%d\n",__func__,start_page_index,file_page_count);
				ret = 1;
				goto out;
			}
			for(k = 0;k < PAGE_COUNT_IN_AREA;k++){
				/*这里需要优化，遍历一次radix tree就得到4个page，完全可以实现的，节省性能$$$$$$$$$$$$$$$$$$$$$$$$*/
				page = xa_load(&mapping->i_pages, start_page_index + k);
				//空洞file_area的page被分配了，那就分配file_area
				if (page && !xa_is_value(page) && page_mapped(page)) {

					//分配file_area并初始化，成功返回0，函数里边把新分配的file_area赋值给*page_slot_in_tree，即在radix tree的槽位
					if(file_area_alloc_and_init(parent_node,page_slot_in_tree,page->index >> PAGE_COUNT_IN_AREA_SHIFT,p_file_stat) < 0){
						ret = -1;
						goto out;
					}
					printk("3:%s file_stat:0x%llx alloc file_area:0x%llx\n",__func__,(u64)p_file_stat,(u64)(*page_slot_in_tree));
					/*4个连续的page只要有一个在radix tree找到，分配file_area,之后就不再查找其他page了*/
					break;
				}
			}
		}
		/*这里有个重大bug，当保存file_area的radix tree的file_area全被释放了，是个空树，此时area_index_for_page指向的是radix tree的根节点的指针的地址，
		 * 即area_index_for_page指向 p_file_stat->hot_cold_file_area_tree_root_node->root_node的地址，然后这里的page_slot_in_tree ++就有问题了。
		 * 原本的设计，area_index_for_page最初指向的是node节点node->slot[64]数组槽位0的slot的地址，然后page_slot_in_tree++依次指向槽位0到槽位63
		 * 的地址。然后看*page_slot_in_tree是否是NULL，是的话说明file_area已经分配。否则说明是空洞file_area，那就要执行xa_load()探测对应索引
		 * 的文件页是否已经分配并插入radix tree(保存page指针的radix tree)了，是的话就file_area_alloc_and_init分配file_area并保存到
		 * page_slot_in_tree指向的保存file_area的radix tree。..........但是，现在保存file_area的radix tree，是个空树，area_index_for_page
		 * 经过上边hot_cold_file_area_tree_lookup探测索引是0的file_area后，指向的是该radix tree的根节点指针的地址，
		 * 即p_file_stat->hot_cold_file_area_tree_root_node->root_node的地址。没办法，这是radix tree的特性，如果只有一个索引是0的成员，该成员
		 * 就是保存在radix tree的根节点指针里。如此，page_slot_in_tree ++就内存越界了，越界到p_file_stat->hot_cold_file_area_tree_root_node
		 * 成员的后边，即p_file_stat的file_stat_lock、max_file_area_age、recent_access_age等成员里，然后对应page分配的话，就要创建新的
		 * file_area并保存到 p_file_stat的file_stat_lock、max_file_area_age、recent_access_age里，导致这些应该是0的成员但却很大。
		 *
		 * 解决办法是，如果该radix tree是空树，先xa_load()探测索引是0的file_aera对应的索引是0~3的文件页page是否分配了，是的话就创建file_area并保存到
		 * radix tree的p_file_stat->hot_cold_file_area_tree_root_node->root_node。然后不令page_slot_in_tree ++，而是xa_load()探测索引是1的file_aera
		 * 对应的索引是4~7的文件页page是否分配了，是的话，直接执行hot_cold_file_area_tree_lookup_and_create创建这个file_area，不是探测结束。
		 * 并且要令p_file_stat->last_index恢复0，这样下次执行该函数还是从索引是0的file_area开始探测，然后探测索引是1的file_area对应的文件页是否分配了。
		 * 这样有点啰嗦，并且会重复探测索引是0的file_area。如果索引是1的file_area的文件页page没分配，那索引是2的file_area的文件页page被分配了。
		 * 现在的代码就有问题了，不会针对这这种情况分配索引是2的file_area*/
		//page_slot_in_tree ++;

		if((NULL == parent_node) && (0 == j) && (0 == area_index_for_page)){
			printk("4:%s file_stat:0x%llx page_slot_in_tree:0x%llx_0x%llx j:%d\n",__func__,(u64)p_file_stat,(u64)page_slot_in_tree,(u64)&p_file_stat->hot_cold_file_area_tree_root_node.root_node,j);
			for(k = 0;k < PAGE_COUNT_IN_AREA;k++){
				/*探测索引是1的file_area对应的文件页page是否分配了，是的话就创建该file_area并插入radix tree*/
				page = xa_load(&mapping->i_pages, PAGE_COUNT_IN_AREA + k);
				if (page && !xa_is_value(page) && page_mapped(page)) {
					//此时file_area的radix tree还是空节点，现在创建根节点node，函数返回后page_slot_in_tree指向的是根节点node->slots[]数组槽位1的地址，下边
					//file_area_alloc_and_init再分配索引是1的file_area并添加到插入radix tree，再赋值高node->slots[1]，即槽位1
					parent_node = hot_cold_file_area_tree_lookup_and_create(&p_file_stat->hot_cold_file_area_tree_root_node,1,&page_slot_in_tree);
					if(IS_ERR(parent_node)){
						ret = -1;
						printk("%s hot_cold_file_area_tree_lookup_and_create fail\n",__func__);
						goto out;
					}

					if(NULL == parent_node || *page_slot_in_tree != NULL){
						panic("%s parent_node:0x%llx *page_slot_in_tree:0x%llx\n",__func__,(u64)parent_node,(u64)(*page_slot_in_tree));
					}
					//分配file_area并初始化，成功返回0，函数里边把新分配的file_area赋值给*page_slot_in_tree，即在radix tree的槽位
					if(file_area_alloc_and_init(parent_node,page_slot_in_tree,1,p_file_stat) < 0){
						ret = -1;
						goto out;
					}
					printk("5:%s file_stat:0x%llx alloc file_area:0x%llx\n",__func__,(u64)p_file_stat,(u64)(*page_slot_in_tree));
					/*4个连续的page只要有一个在radix tree找到，分配file_area,之后就不再查找其他page了*/
					break;
				}
			}

			/*如果parent_node不是NULL。说明上边索引是0的file_area的对应文件页page分配了，创建的根节点，parent_node就是这个根节点。并且，令j加1.
			 *这样下边再就j加1，j就是2了，page_slot_in_tree = parent_node.slots[j]指向的是索引是2的file_area，然后探测对应文件页是否分配了。
			 *因为索引是0、1的file_area已经探测过了。如果 parent_node是NULL，那说明索引是1的file_area对应的文件页page没分配，上边也没有创建
			 *根节点。于是令p_file_stat->last_index清0，直接goto out，这样下次执行该函数，还是从索引是0的file_area开始探测。这样有个问题，如经
			 *索引是1的file_area对应文件页没分配，这类直接goto out了，那索引是2的file_area对应的文件页分配，就不理会了。这种可能是存在的！索引
			 *是2的file_area的文件页page也应该探测呀，后溪再改进吧
			 */
			if(parent_node){
				j ++;
			}else{
				p_file_stat->last_index = 0;
				goto out;
			}
		}
		//j加1令page_slot_in_tree指向下一个file_area
		j++;
		//不用page_slot_in_tree ++了，虽然性能好点，但是内存越界了也不知道。page_slot_in_tree指向下一个槽位的地址
		page_slot_in_tree = &parent_node->slots[j];
#ifdef __LITTLE_ENDIAN//这个判断下端模式才成立
		if((u64)page_slot_in_tree < (u64)(&parent_node->slots[0]) || (u64)page_slot_in_tree > (u64)(&parent_node->slots[TREE_MAP_SIZE])){		
			panic("%s page_slot_in_tree:0x%llx error 0x%llx_0x%llx\n",__func__,(u64)page_slot_in_tree,(u64)(&parent_node->slots[0]),(u64)(&parent_node->slots[TREE_MAP_SIZE]));
		}
#endif	
		//page_slot_in_tree ++;
	    //area_index_for_page的取值，0，后续依次是64*1、64*2、64*3等等，
	    area_index_for_page += FILE_AREA_PER_NODE;
    }
	//p_file_stat->last_index记录下次要查找的第一个node节点的file_area的索引
	p_file_stat->last_index = area_index_for_page;
out:
	if(start_page_index > file_page_count){
		//p_file_stat->last_index清0，下次从头开始扫描文件页
		p_file_stat->last_index = 0;
	}
	return ret;
}
#endif

static int check_page_exist_and_create_file_area(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat *p_file_stat,struct hot_cold_file_area_tree_node **_parent_node,void ***_page_slot_in_tree,unsigned int area_index)
{
	/*空树时函数返回NULL并且page_slot_in_tree指向root->root_node的地址。当传入索引很大找不到file_area时，函数返回NULL并且page_slot_in_tree不会被赋值(保持原值NULL)*/

	int ret = 0;
	int k;
	pgoff_t start_page_index;
	struct page *page;
	struct page *pages[PAGE_COUNT_IN_AREA];

	//struct address_space *mapping = p_file_stat->mapping;
	void **page_slot_in_tree = *_page_slot_in_tree;
	struct hot_cold_file_area_tree_node *parent_node = *_parent_node;
	//file_area的page有一个mapcount大于1，则是mapcount file_area，再把mapcount_file_area置1
	bool mapcount_file_area = 0;
	struct file_area *p_file_area = NULL;

	start_page_index = (area_index) << PAGE_COUNT_IN_AREA_SHIFT;
    
	memset(pages,0,PAGE_COUNT_IN_AREA*sizeof(struct page *));
	//获取p_file_area对应的文件页page指针并保存到pages数组
	ret = get_page_from_file_area(p_file_stat,start_page_index,pages);
	if(shrink_page_printk_open)
		printk("1:%s file_stat:0x%llx start_page_index:%ld get %d page\n",__func__,(u64)p_file_stat,start_page_index,ret);

	if(ret <= 0)
	    goto out; 

	/*探测area_index对应file_area索引的page是否分配了，分配的话则分配对应的file_area。但是如果父节点不存在，需要先分配父节点*/
	for(k = 0;k < PAGE_COUNT_IN_AREA;k++){
		/*探测索引是1的file_area对应的文件页page是否分配了，是的话就创建该file_area并插入radix tree*/
		//page = xa_load(&mapping->i_pages, start_page_index + k);
		page= pages[k];
		//area_index对应file_area索引的page存在
		if (page && !xa_is_value(page) && page_mapped(page)){

			if( 0 == mapcount_file_area && page_mapcount(page) > 1)
				mapcount_file_area = 1;

			//父节点不存在则创建父节点，并令page_slot_in_tree指向area_index索引对应file_area在父节点的槽位parent_node.slots[槽位索引]槽位地址
			if(NULL == parent_node){//parent_node是NULL，page_slot_in_tree一定也是NULL
				parent_node = hot_cold_file_area_tree_lookup_and_create(&p_file_stat->hot_cold_file_area_tree_root_node,area_index,&page_slot_in_tree);
				if(IS_ERR(parent_node)){
					ret = -1;
					printk("%s hot_cold_file_area_tree_lookup_and_create fail\n",__func__);
					goto out;
				}

			}
			/*到这里，page_slot_in_tree一定不是NULL，是则触发crash。如果parent_node是NULL是有可能的，当radix tree是空树时。查找索引是0的file_area
			 *时，parent_node是NULL，page_slot_in_tree指向p_file_stat->hot_cold_file_area_tree_root_node->root_node的地址。否则，其他情况触发crash*/
			if((area_index != 0 && NULL == parent_node) || (NULL == page_slot_in_tree)){
				panic("%s parent_node:0x%llx *page_slot_in_tree:0x%llx\n",__func__,(u64)parent_node,(u64)(*page_slot_in_tree));
			}
			p_file_area = file_area_alloc_and_init(parent_node,page_slot_in_tree,area_index,p_file_stat);
			//分配file_area并初始化，成功返回0，函数里边把新分配的file_area赋值给*page_slot_in_tree，即在radix tree的槽位
			if(NULL == p_file_area){
				ret = -1;
				goto out;
			}
			//在file_stat->file_area_temp链表的file_area个数加1
			p_file_stat->file_area_count_in_temp_list ++;

			ret = 1;
			//令_page_slot_in_tree指向新分配的file_area在radix tree的parent_node.slots[槽位索引]槽位地址
			if(NULL == *_page_slot_in_tree)
				*_page_slot_in_tree = page_slot_in_tree;

			//新分配的parent_node赋值给*_parent_node
			if(NULL == *_parent_node)
				*_parent_node = parent_node;

			//只要有一个page在radix tree找到，分配file_area,之后就不再查找其他page了
			break;
		}
	}

	/*如果上边for循环遍历的file_area的page的mapcount都是1，且file_area的page上边没有遍历完，则这里继续遍历完剩余的page*/
	while(0 == mapcount_file_area && k < PAGE_COUNT_IN_AREA){
		page= pages[k];
		if (page && !xa_is_value(page) && page_mapped(page) && page_mapcount(page) > 1){
			mapcount_file_area = 1;
		}
		k ++;
	}
	if(mapcount_file_area){
		//file_stat->temp 链表上的file_area个数减1
		p_file_stat->file_area_count_in_temp_list --;
		//文件file_stat的mapcount的file_area个数加1
		p_file_stat->mapcount_file_area_count ++;
		//file_area的page的mapcount大于1，则把file_area移动到file_stat->file_area_mapcount链表
		clear_file_area_in_temp_list(p_file_area);
		set_file_area_in_mapcount_list(p_file_area);
		list_move(&p_file_area->file_area_list,&p_file_stat->file_area_mapcount);
		if(shrink_page_printk_open)
			printk("5:%s file_stat:0x%llx file_area:0x%llx state:0x%x is mapcount file_area\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state);

		/*如果文件file_stat的mapcount的file_area个数超过阀值，则file_stat被判定为mapcount file_stat而移动到
		 *global mmap_file_stat_mapcount_head链表。但前提file_stat必须在temp_file链表或temp_large_file链表*/
		if(is_mmap_file_stat_mapcount_file(p_hot_cold_file_global,p_file_stat) && file_stat_in_file_stat_temp_head_list(p_file_stat)){
			 if(file_stat_in_file_stat_temp_head_list_error(p_file_stat))
				 panic("%s file_stat:0x%llx status error:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

			 clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			 set_file_stat_in_mapcount_file_area_list(p_file_stat);
			 list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_mapcount_head);
		 	 p_hot_cold_file_global->mapcount_mmap_file_stat_count ++;
			 if(shrink_page_printk_open1)
				 printk("6:%s file_stat:0x%llx status:0x%llx is mapcount file\n",__func__,(u64)p_file_stat,(u64)p_file_stat->file_stat_status);
		}
	}

out:
	return ret;
}
/*文件的radix tree在遍历完一次所有的page后，可能存在空洞，于是后续还要再遍历文件的radix tree获取之前没有遍历到的page*/
static unsigned int reverse_file_stat_radix_tree_hole(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat)
{
	int i,j;
	struct hot_cold_file_area_tree_node *parent_node;
	void **page_slot_in_tree = NULL;
	unsigned int base_area_index;
	int ret = 0;
	unsigned int file_page_count = p_file_stat->mapping->host->i_size >> PAGE_SHIFT;//除以4096
	unsigned int start_page_index = 0;
	struct file_area *p_file_area;

	//p_file_stat->traverse_done是0，说明还没有遍历完一次文件的page，那先返回
	if(0 == p_file_stat->traverse_done)
		return ret;
	if(shrink_page_printk_open)
		printk("1:%s file_stat:0x%llx file_stat->last_index:%ld\n",__func__,(u64)p_file_stat,p_file_stat->last_index);

	//p_file_stat->last_index初值是0，后续依次是64*1、64*2、64*3等等，
	base_area_index = p_file_stat->last_index;
	//一次遍历SCAN_FILE_AREA_NODE_COUNT个node，一个node 64个file_area
	for(i = 0;i < SCAN_FILE_AREA_NODE_COUNT;i++){
		//每次必须对page_slot_in_tree赋值NULL，下边hot_cold_file_area_tree_lookup()如果没找到对应索引的file_area，page_slot_in_tree还是NULL
		page_slot_in_tree = NULL;
		j = 0;

		/*查找索引0、64*1、64*2、64*3等等的file_area的地址，保存到page_slot_in_tree。page_slot_in_tree指向的是每个node节点的第一个file_area，
		 *每个node节点一共64个file_area，都保存在node节点的slots[64]数组。下边的for循环一次查找node->slots[0]~node->slots[63]，如果是NULL，
		 *说明还没有分配file_area，是空洞，那就分配file_area并添加到radix tree。否则说明file_area已经分配了，就不用再管了*/

		/*不能用hot_cold_file_area_tree_lookup_and_create，如果是空树，但是去探测索引是1的file_area，此时会直接分配索引是1的file_area对应的node节点
		 *并插入radix tree，注意是分配node节点。而根本不管索引是1的file_area对应的文件页page是否分配了。这样会分配很多没用的node节点，而不管对应索引的
		 *file_area的文件页是否分配了，浪费内存。这里只能探测file_area是否存在，不能node节点*/
		//parent_node = hot_cold_file_area_tree_lookup_and_create(&p_file_stat->hot_cold_file_area_tree_root_node,base_area_index,&page_slot_in_tree);

		/*空树时函数返回NULL并且page_slot_in_tree指向root->root_node的地址。当传入索引很大找不到file_area时，函数返回NULL并且page_slot_in_tree不会被赋值(保持原值NULL)*/
		parent_node = hot_cold_file_area_tree_lookup(&p_file_stat->hot_cold_file_area_tree_root_node,base_area_index,&page_slot_in_tree);
		if(IS_ERR(parent_node)){
			ret = -1;
			printk("2:%s hot_cold_file_area_tree_lookup_and_create fail\n",__func__);
			goto out;
		}
		/*一个node FILE_AREA_PER_NODE(64)个file_area。下边靠着page_slot_in_tree++依次遍历这64个file_area，如果*page_slot_in_tree
		 *是NULL，说明是空洞file_area，之前这个file_area对应的page没有分配，也没有分配file_area，于是按照base_area_index<<PAGE_COUNT_IN_AREA_SHIFT
		 *这个page索引，在此查找page是否分配了，是的话就分配file_area*/
		while(1){
			/* 1：hot_cold_file_area_tree_lookup中找到对应索引的file_area，parent_node非NULL，page_slot_in_tree和*page_slot_in_tree都非NULL
			 * 2：hot_cold_file_area_tree_lookup中没找到对应索引的file_area，但是父节点存在，parent_node非NULL，page_slot_in_tree非NULL，*page_slot_in_tree是NULL
			 * 3：hot_cold_file_area_tree_lookup中没找到对应索引的file_area，父节点也不存在，parent_node是NULL，page_slot_in_tree是NULL，此时不能出现*page_slot_in_tree
			 * 另外，如果radix tree是空树，lookup索引是0的file_area后，page_slot_in_tree指向p_file_stat->hot_cold_file_area_tree_root_node->root_node的地址，
			 *    parent_node是NULL，page_slot_in_tree和*page_slot_in_tree都非NULL
			 *
			 * 简单说，
			 * 情况1：只要待查找索引的file_area的父节点存在，parent_node不是NULL，page_slot_in_tree也一定不是NULL，page_slot_in_tree指向保存
			 * file_area指针在父节点的槽位地址，即parent_node.slot[槽位索引]的地址。如果file_area存在则*page_slot_in_tree非NULL，否则*page_slot_in_tree是NULL
			 * 情况2：待查找的file_area的索引太大，没找到父节点，parent_node是NULL，page_slot_in_tree也是NULL，此时不能用*page_slot_in_tree，会crash
			 * 情况3：radix tree是空树，lookup索引是0的file_area后， parent_node是NULL，page_slot_in_tree非NULL，指向p_file_stat->hot_cold_file_area_tree_root_node->root_node的地址
			 * */

			start_page_index = (base_area_index + j) << PAGE_COUNT_IN_AREA_SHIFT;
			if(start_page_index >= file_page_count){
				if(shrink_page_printk_open)
					printk("3:%s start_page_index:%d >= file_page_count:%d\n",__func__,start_page_index,file_page_count);

				goto out;
			}
			if(shrink_page_printk_open){
				if(page_slot_in_tree)
					printk("4:%s file_stat:0x%llx i:%d j:%d start_page_index:%d base_area_index:%d parent_node:0x%llx page_slot_in_tree:0x%llx *page_slot_in_tree:0x%llx\n",__func__,(u64)p_file_stat,i,j,start_page_index,base_area_index,(u64)parent_node,(u64)page_slot_in_tree,(u64)(*page_slot_in_tree));
				else
					printk("4:%s file_stat:0x%llx i:%d j:%d start_page_index:%d base_area_index:%d parent_node:0x%llx page_slot_in_tree:0x%llx\n",__func__,(u64)p_file_stat,i,j,start_page_index,base_area_index,(u64)parent_node,(u64)page_slot_in_tree);
			}

			/* (NULL == page_slot_in_tree)：对应情况2，radix tree现在节点太少，待查找的file_area索引太大找不到父节点和file_area的槽位，
			 * parent_node 和 page_slot_in_tree都是NULL。那就执行check_page_exist_and_create_file_area()分配父节点 parent_node，并令page_slot_in_tree指向
			 * parent_node->slots[槽位索引]槽位，然后分配对应索引的file_area并保存到parent_node->slots[槽位索引]
			 *
			 * (NULL!= page_slot_in_tree && NULL == *page_slot_in_tree)对应情况1和情况3。情况1：找到对应索引的file_area的槽位，即parent_node.slot[槽位索引]，
			 * parent_node 和 page_slot_in_tree都非NULL，但*page_slot_in_tree是NULL，那就执行check_page_exist_and_create_file_area()分配对应索引的file_area结构
			 * 并保存到parent_node.slot[槽位索引]。 情况3：radix tree是空树，lookup索引是0的file_area后， parent_node是NULL，page_slot_in_tree非NULL，
			 * page_slot_in_tree指向p_file_stat->hot_cold_file_area_tree_root_node->root_node的地址，但如果*page_slot_in_tree是NULL，说明file_area没有分配，
			 * 那就执行check_page_exist_and_create_file_area()分配索引是0的file_area并保存到 p_file_stat->hot_cold_file_area_tree_root_node->root_node。
			 *
			 * */
			if((NULL == page_slot_in_tree)  || (NULL!= page_slot_in_tree && NULL == *page_slot_in_tree)){
				ret = check_page_exist_and_create_file_area(p_hot_cold_file_global,p_file_stat,&parent_node,&page_slot_in_tree,base_area_index + j);
				if(ret < 0){
					printk("5:%sheck_page_exist_and_create_file_area fail\n",__func__);
					goto out;
				}else if(ret >0){
					//ret 大于0说明上边创建了file_area或者node节点，这里再打印出来
					if(shrink_page_printk_open)
						printk("6:%s file_stat:0x%llx i:%d j:%d start_page_index:%d base_area_index:%d parent_node:0x%llx page_slot_in_tree:0x%llx *page_slot_in_tree:0x%llx\n",__func__,(u64)p_file_stat,i,j,start_page_index,base_area_index,(u64)parent_node,(u64)page_slot_in_tree,(u64)(*page_slot_in_tree));
				}
			}

			if(page_slot_in_tree){
				barrier();
				if(*page_slot_in_tree){
					p_file_area = (struct file_area *)(*page_slot_in_tree);
					//file_area自身保存的索引数据 跟所在radix tree的槽位位置不一致，触发crash
					if((p_file_area->start_index >>PAGE_COUNT_IN_AREA_SHIFT) != base_area_index + j)
						panic("%s file_area index error!!!!!! file_stat:0x%llx p_file_area:0x%llx p_file_area->start_index:%ld base_area_index:%d j:%d\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->start_index,base_area_index,j);

				}
			}
			/*
			//情况1：只要待查找索引的file_area的父节点存在，parent_node不是NULL，page_slot_in_tree也一定不是NULL
			if(parent_node){
			    //待查找索引的file_area不存在，则探测它对应的page是否存在，存在的话则分配file_area
			    if(NULL == *page_slot_in_tree){
					if(check_page_exist_and_create_file_area(p_hot_cold_file_global,p_file_stat,&parent_node,&page_slot_in_tree,base_area_index + j) < 0){
			           goto out;
			        }
			    }
			    //待查找索引的file_area存在，什么都不用干
			    else{}
			}
			else
			{
				//情况2：待查找的file_area的索引太大，没找到父节点，parent_node是NULL，page_slot_in_tree也是NULL，此时不能用*page_slot_in_tree，会crash
				if(NULL == page_slot_in_tree){
					if(check_page_exist_and_create_file_area(p_hot_cold_file_global,p_file_stat,&parent_node,&page_slot_in_tree,base_area_index+j) < 0){
					    goto out;
					}
					//到这里，如果指定索引的file_area的page存在，则创建父节点和file_area，parent_node和page_slot_in_tree不再是NULL，*ppage_slot_in_tree也非NULL
				}
				//情况3：radix tree是空树，lookup索引是0的file_area后， parent_node是NULL，page_slot_in_tree非NULL，指向*p_file_stat->hot_cold_file_area_tree_root_node->root_node的地址
				else{
					if((0 == j) && (0 == base_area_index)&& (page_slot_in_tree ==  &p_file_stat->hot_cold_file_area_tree_root_node.root_node)){
						//如果索引是0的file_area不存在，则探测对应page是否存在，存在的话创建索引是0的file_area，不用创建父节点，file_area指针保存在p_file_stat->hot_cold_file_area_tree_root_node->root_node
						if(NULL == *page_slot_in_tree){
							if(check_page_exist_and_create_file_area(p_hot_cold_file_global,p_file_stat,&parent_node,&page_slot_in_tree,base_area_index + j) < 0){
								goto out;
							}
						}
					}else{
						if(check_page_exist_and_create_file_area(p_hot_cold_file_global,p_file_stat,&parent_node,&page_slot_in_tree,base_area_index + j) < 0){
						    goto out;
						}
						//这里可能进入，空树时，探测索引很大的file_area
						printk("%s j:%d base_area_index:%d page_slot_in_tree:0x%llx_0x%llx error!!!!!!!!!\n",__func__,j,base_area_index,(u64)page_slot_in_tree,(u64)&p_file_stat->hot_cold_file_area_tree_root_node.root_node);
					}
				}
			}
			*/			
			//依次只能遍历FILE_AREA_PER_NODE 个file_area
			if(j >= FILE_AREA_PER_NODE - 1)
				break;

			//j加1令page_slot_in_tree指向下一个file_area
			j++;
			if(parent_node){
				//不用page_slot_in_tree ++了，虽然性能好点，但是内存越界了也不知道。page_slot_in_tree指向下一个槽位的地址
				page_slot_in_tree = &parent_node->slots[j];
#ifdef __LITTLE_ENDIAN//这个判断下端模式才成立
				if((u64)page_slot_in_tree < (u64)(&parent_node->slots[0]) || (u64)page_slot_in_tree > (u64)(&parent_node->slots[TREE_MAP_SIZE])){		
					panic("%s page_slot_in_tree:0x%llx error 0x%llx_0x%llx\n",__func__,(u64)page_slot_in_tree,(u64)(&parent_node->slots[0]),(u64)(&parent_node->slots[TREE_MAP_SIZE]));
				}
#endif
			}else{
				/*到这里，应该radix tree是空树时才成立，要令page_slot_in_tree指向NULL，否则当前这个for循环的page_slot_in_tree值会被错误用到下个循环*/
				page_slot_in_tree = NULL;
			}
		}
		//base_area_index的取值，0，后续依次是64*1、64*2、64*3等等，
		base_area_index += FILE_AREA_PER_NODE;
	}
	//p_file_stat->last_index记录下次要查找的第一个node节点的file_area的索引
	p_file_stat->last_index = base_area_index;
out:
	if((ret >= 0) && ((base_area_index +j) << PAGE_COUNT_IN_AREA_SHIFT >= file_page_count)){
		if(shrink_page_printk_open1)
			printk("7:%s last_index = 0 last_index:%ld base_area_index:%d j:%d file_page_count:%d\n",__func__,p_file_stat->last_index,base_area_index,j,file_page_count);

		//p_file_stat->last_index清0，下次从头开始扫描文件页
		p_file_stat->last_index = 0;
	}
	return ret;
}

/*1:先file_stat->file_area_temp链表尾巴遍历file_area，如果在规定周期被访问次数超过阀值，则判定为热file_area而移动
 * file_stat->file_area_hot链表。如果file_stat->file_area_hot链表的热file_area超过阀值则该文件被判定为热文件，file_stat移动到
 * global hot链表。
 *2:如果ile_stat->file_area_temp上file_area长时间不被访问，则释放掉file_area的page，并把file_area移动到file_stat->file_area_free链表
 *  file_stat->file_area_free 和 file_stat->file_area_free_temp 在这里一个意思。
 *3:遍历file_stat->file_area_refault、hot、mapcount、free链表上file_area，处理各不相同，升级或降级到file_stat->temp链表，或者
 *  释放掉file_area，具体看源码吧
 *4:如果file_stat->file_area_temp链表上的file_area遍历了一遍，则进入冷却期。在N个周期内，不在执行该函数遍历该文件
 *file_stat->temp、refault、free、mapcount、hot 链表上file_area。file_stat->file_area_temp链表上的file_area遍历了一遍，导致文件进入
 *冷冻期，此时页牵连无法遍历到该文件file_stat->refault、free、mapcount、hot 链表上file_area，这合理吗。当然可以分开遍历，但是目前
 *觉得没必要，因为file_stat->refault、free、mapcount、hot 链表上file_area也有冷冻期，这个冷冻期还更长，是N的好几倍。因此不会影响，还降低性能损耗
 *5:遍历文件file_stat的原生radix tree，是否存在空洞file_area，是的话则为遍历到的新的文件页创建file_area
 */
static unsigned int check_file_area_cold_page_and_clear(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,unsigned int scan_file_area_max,unsigned int *already_scan_file_area_count)
{
	struct page *page_buf[BUF_PAGE_COUNT];
	int cold_page_count = 0,cold_page_count_last;
	int ret = 0;
	struct file_area *p_file_area,*p_file_area_temp;
	char delete_file_area_last = 0;
	unsigned int reclaimed_pages = 0;
	unsigned int isolate_pages = 0;
	LIST_HEAD(file_area_temp_head);
	memset(page_buf,0,BUF_PAGE_COUNT*sizeof(struct page*));

	/*注意，执行该函数的file_stat都是处于global temp链表的，file_stat->file_area_temp和 file_stat->file_area_mapcount 链表上都有file_area,mapcount的file_area
	 *变多了，达到了该文件要变成mapcount文件的阀值。目前在下边的check_one_file_area_cold_page_and_clear函数里，只会遍历file_stat->file_area_mapcount 链表上
	 *的file_area，如果不是mapcount了，那就降级到file_stat->file_area_temp链表。没有遍历file_stat->file_area_temp链表上的file_area，如果对应page的mapcount大于1
	 *了，再把file_area升级到file_stat->file_area_mapcount链表。如果mapcount的file_area个数超过阀值，那就升级file_stat到mapcount文件。这个有必要做吗???????，
	 *想想还是做吧，否则这种file_area的page回收时很容易失败*/
	if(shrink_page_printk_open)
		printk("1:%s file_stat:0x%llx file_area_last:0x%llx file_area_count_in_temp_list:%d file_area_hot_count:%d mapcount_file_area_count:%d file_area_count:%d\n",__func__,(u64)p_file_stat,(u64)p_file_stat->file_area_last,p_file_stat->file_area_count_in_temp_list,p_file_stat->file_area_hot_count,p_file_stat->mapcount_file_area_count,p_file_stat->file_area_count);

	if(p_file_stat->file_area_last){//本次从上一轮扫描打断的file_stat继续遍历
		p_file_area = p_file_stat->file_area_last;
	}
	else{
		//第一次从链表尾的file_stat开始遍历。或者新的冷却期开始后也是
		p_file_area = list_last_entry(&p_file_stat->file_area_temp,struct file_area,file_area_list);
		p_file_stat->file_area_last = p_file_area;
	}

	while(!list_empty(&p_file_stat->file_area_temp)){

		if(!file_area_in_temp_list(p_file_area) || file_area_in_temp_list_error(p_file_area))
			panic("%s file_area:0x%llx status:%d not in file_area_temp\n",__func__,(u64)p_file_area,p_file_area->file_area_state);

		/*查找file_area在file_stat->file_area_temp链表上一个file_area。如果p_file_area不是链表头的file_area，直接list_prev_entry
		 * 找到上一个file_area。如果p_file_stat是链表头的file_area，那要跳过链表过，取出链表尾的file_area*/
		if(!list_is_first(&p_file_area->file_area_list,&p_file_stat->file_area_temp)){
			p_file_area_temp = list_prev_entry(p_file_area,file_area_list);
		}
		else{
			//从链表尾遍历完一轮file_area了，文件file_stat要进入冷却期
			p_file_stat->cooling_off_start = 1;
			//记录此时的全局age
			p_file_stat->cooling_off_start_age = p_hot_cold_file_global->global_age;
			if(shrink_page_printk_open)
				printk("1_1:%s file_stat:0x%llx cooling_off_start age:%ld\n",__func__,(u64)p_file_stat,p_file_stat->cooling_off_start_age);

			p_file_area_temp = list_last_entry(&p_file_stat->file_area_temp,struct file_area,file_area_list);
		}

		/*遍历file_stat->file_area_temp，查找冷的file_area*/
		cold_page_count_last = cold_page_count;
		if(shrink_page_printk_open)
			printk("2:%s file_stat:0x%llx file_area:0x%llx index:%ld scan_file_area_count_temp_list:%d file_area_count_in_temp_list:%d\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->start_index,p_file_stat->scan_file_area_count_temp_list,p_file_stat->file_area_count_in_temp_list);
	
	    //这个错误赋值会影响到file_stat->access_count，导致误判为热file_area	
		//p_file_area->file_area_access_age = p_hot_cold_file_global->global_age;
		ret = check_one_file_area_cold_page_and_clear(p_hot_cold_file_global,p_file_stat,p_file_area,page_buf,&cold_page_count);
		/*到这里有两种可能
		 *1: file_area的page都是冷的，ret是0
		 *2: file_area的page有些被访问了，ret大于0
		 *3：file_area的page都是冷的，但是有些page前边trylock_page失败了，ret大于0,这种情况后期得再优化优化细节!!!!!!!!!!!!!
		 */
		if(0 == ret){
			/*加下边这个if判断，是因为之前设计的以p_file_stat->file_area_last为基准的循环遍历链表有个重大bug：while循环第一次
			 *遍历p_file_area时，p_file_area和p_file_stat->file_area_last是同一个。而如果p_file_area是冷的，并且本次它的page的
			 *pte页表也没访问，那就要把file_area移动到file_stat->file_area_free_temp链表。这样后续这个while就要陷入死循环了，
			 *因为p_file_stat->file_area_last指向的file_area移动到file_stat->file_area_free_temp链表了。而p_file_stat一个个
			 *指向file_stat->file_area_temp链表的file_area。下边的while(p_file_area != p_file_stat->file_area_last)永远不成立
			 *并且上边check_one_file_area_cold_page_and_clear()里传入的file_area是重复的，会导致里边重复判断page和lock_page，
			 然后就会出现进程hung在lock_page里，因为重复lock_page。解决办法是

			 1：凡是p_file_area和p_file_stat->file_area_last是同一个，一定要更新p_file_stat->file_area_last为p_file_area在
			 file_stat->file_area_temp链表的前一个file_area。
			 2：下边else分支的file_area不太冷但它的page是冷的情况，要把file_area从file_stat->file_area_temp链表移除，并移动到
			 file_area_temp_head临时链表。while循环结束时再把这些file_area移动到file_stat->file_area_temp链表尾。这样避免这个
			 while循环里，重复遍历这种file_area，重复lock_page 对应的page，又要hung
			 3：while循环的退出条件加个 !list_empty(file_stat->file_area_temp)。这样做的目的是，如果file_stat->file_area_temp链表
			 只有一个file_area，而它和它的page都是冷的，它移动到ile_stat->file_area_free_temp链表后，p_file_stat->file_area_last
			 指向啥呢？这个链表没有成员了！只能靠!list_empty(file_stat->file_area_temp)退出while循环

			 注意，还有一个隐藏bug，当下边的if成立时，这个while循环就立即退出了，不会接着遍历了。因为if成立时，
			 p_file_stat->file_area_last = p_file_area_temp，二者相等，然后下边执行p_file_area = p_file_area_temp 后，就导致
			 p_file_stat->file_area_last 和 p_file_area 也相等了，while(p_file_area != p_file_stat->file_area_last)就不成立了。
			 解决办法时，当发现该if成立，令 delete_file_area_last置1，然后下边跳出while循环的条件改为
			 if(0 == delete_file_area_last && p_file_area != p_file_stat->file_area_last) break。就是说，当发现
			 本次要移动到其他链表的p_file_area是p_file_stat->file_area_last时，令p_file_stat->file_area_last指向p_file_area在
			 file_stat->file_area_temp链表的上一个file_area(即p_file_area_temp)后，p_file_area也会指向这个file_area，此时不能
			 跳出while循环，p_file_area此时的新file_area还没使用过呢！
			 **/
			if(!file_area_in_temp_list(p_file_area) && (p_file_area == p_file_stat->file_area_last)){
				p_file_stat->file_area_last = p_file_area_temp;
				delete_file_area_last = 1;
			}

			/*二者不相等，说明file_area是冷的，并且它的page的pte本次检测也没被访问，这种情况才回收这个file_area的page*/
			if(cold_page_count_last != cold_page_count)
			{
				//处于file_stat->tmep链表上的file_area，移动到其他链表时，要先对file_area的access_count清0，否则会影响到
				//file_area->file_area_access_age变量，因为file_area->access_count和file_area_access_age是共享枚举变量
				file_area_access_count_clear(p_file_area);
				//file_stat->temp 链表上的file_area个数减1
				p_file_stat->file_area_count_in_temp_list --;

				clear_file_area_in_temp_list(p_file_area);
				/*设置file_area处于file_stat的free_temp_list链表。这里设定，不管file_area处于file_stat->file_area_free_temp还是
				 *file_stat->file_area_free链表，都是file_area_in_free_list状态，没有必要再区分二者*/
				set_file_area_in_free_list(p_file_area);
				/*冷file_area移动到file_area_free_temp链表参与内存回收。移动到 file_area_free_temp链表的file_area也要每个周期都扫描。
				 *1：如果对应文件页长时间不被访问，那就释放掉file_area
				 *2：如果对应page内存回收又被访问了，file_area就要移动到refault链表，长时间不参与内存回收
				 *3：如果refault链表上的file_area的page长时间不被访问，file_area就要降级到temp链表
				 *4：如果文件file_stat的file_area全被释放了，file_stat要移动到 zero_file_area链表，然后释放掉file_stat结构
				 *5：在驱动卸载时，要释放掉所有的file_stat和file_area*/
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_free_temp);
				//记录file_area参与内存回收的时间
				p_file_area->shrink_time = ktime_to_ms(ktime_get()) >> 10;
			}else{
				/*如果file_area的page没被访问，但是file_area还不是冷的，file_area不太冷，则把file_area先移动到临时链表，然后该函数最后再把
				 *该临时链表上的不太冷file_area同统一移动到file_stat->file_area_temp链表尾。这样做的目的是，避免该while循环里重复遍历到
				 *这些file_area*/
				//list_move_tail(&p_file_area->file_area_list,&p_file_stat->file_area_temp);
				list_move(&p_file_area->file_area_list,&file_area_temp_head);
			}
		}else if(ret > 0){
			/*如果file_area的page被访问了，则把file_area移动到链表头-------这个操作就多余了，去掉，只要把不太冷的file_area移动到
			  file_stat->file_area_temp链表尾就行了，这样就达到目的：链表尾是冷file_area，链表头是热file_area*/
			//list_move(&p_file_area->file_area_list,&p_file_stat->file_area_temp);

			/*如果file_area被判定是热file_area等原因而移动到了其他链表，并且file_area_in_temp_list(p_file_area)成立，
			 *并且，p_file_area是p_file_stat->file_area_last，要强制更新p_file_stat->file_area_last为p_file_area_temp。
			 *因为此时这个p_file_stat->file_area_last已经不再处于temp链表了，可能会导致死循环。原因上边友分析*/
			if(!file_area_in_temp_list(p_file_area) && (p_file_area == p_file_stat->file_area_last)){
				p_file_stat->file_area_last = p_file_area_temp;
				delete_file_area_last = 1;
			}
		}

		/*1:凑够BUF_PAGE_COUNT个要回收的page，if成立，则开始隔离page、回收page
		 *2:page_buf剩余的空间不足容纳PAGE_COUNT_IN_AREA个page，if也成立，否则下个循环执行check_one_file_area_cold_page_and_clear函数
		 *向page_buf保存PAGE_COUNT_IN_AREA个page，将导致内存溢出*/
		if(cold_page_count >= BUF_PAGE_COUNT || (BUF_PAGE_COUNT - cold_page_count <=  PAGE_COUNT_IN_AREA)){

        #ifdef USE_KERNEL_SHRINK_INACTIVE_LIST
		    isolate_pages = cold_mmap_file_isolate_lru_pages_and_shrink(p_hot_cold_file_global,p_file_stat,p_file_area,page_buf,cold_page_count);
		    reclaimed_pages = p_hot_cold_file_global->hot_cold_file_shrink_counter.mmap_free_pages_count;
        #else		
			//隔离page
			isolate_pages += cold_mmap_file_isolate_lru_pages(p_hot_cold_file_global,p_file_stat,p_file_area,page_buf,cold_page_count);
			//回收page
			reclaimed_pages += cold_file_shrink_pages(p_hot_cold_file_global,p_file_stat,1);
	    #endif
			cold_page_count = 0;
			if(shrink_page_printk_open)
				printk("3:%s file_stat:0x%llx reclaimed_pages:%d isolate_pages:%d\n",__func__,(u64)p_file_stat,reclaimed_pages,isolate_pages);
		}

		/*下一个扫描的file_area。这个对p_file_area赋值p_file_area_temp，要放到if(*already_scan_file_area_count > scan_file_area_max) break;
		 *跳出while循环前边。否则会存在这样一种问题，前边p_file_area不是太冷而移动到了file_area_temp_head链表头，然后下边break跳出，
		 *p_file_area此时指向的是file_area已经移动到file_area_temp_head链表头链表头了，且这个链表只有这一个file_area。然后下边执行
		 *p_file_stat->file_area_last = list_prev_entry(p_file_area,file_area_list) 对p_file_stat->file_area_last赋值时，
		 *p_file_stat->file_area_last指向file_area就是file_area_temp_head链表头了。下次执行这个函数时，使用p_file_stat->file_area_last
		 *指向的file_area时非法的了*/
		p_file_area = p_file_area_temp;

		//异步内存回收线程本次运行扫描的总file_area个数加1，
		*already_scan_file_area_count = *already_scan_file_area_count + 1;
		//文件file_stat已经扫描的file_area个数加1
		p_file_stat->scan_file_area_count_temp_list ++;

		//超过本轮扫描的最大file_area个数则结束本次的遍历
		if(*already_scan_file_area_count >= scan_file_area_max)
			break;

		/*文件file_stat已经扫描的file_area个数超过file_stat->file_area_temp 链表的总file_area个数，停止扫描该文件的file_area。
		 *然后才会扫描global->mmap_file_stat_temp_head或mmap_file_stat_temp_large_file_head链表上的下一个文件file_stat的file_area
		 *文件file_stat进入冷却期if也成。其实这两个功能重复了，本质都表示遍历完file_stat->temp链表上的file_area*/
		if(/*p_file_stat->scan_file_area_count_temp_list >= p_file_stat->file_area_count_in_temp_list ||*/ p_file_stat->cooling_off_start){
			//文件扫描的file_area个数清0，下次轮到扫描该文件的file_area时，才能继续扫描
			p_file_stat->scan_file_area_count_temp_list = 0;
			ret = 1;
			break;
		}

		if(0 == delete_file_area_last && p_file_area == p_file_stat->file_area_last){
			ret = 1;
			break;
		}
		else if(1 == delete_file_area_last)
			delete_file_area_last = 0;


	/*这里退出循环的条件，不能碰到链表头退出，是一个环形队列的遍历形式,以下两种情况退出循环
	 *1：上边的 遍历指定数目的file_area后，强制结束遍历
	 *2：这里的while，本次循环处理到file_area已经是第一次循环处理过了，相当于重复了
	 */
	//}while(p_file_area != p_file_stat->file_area_last);
	//}while(p_file_area != p_file_stat->file_area_last  && !list_empty(&p_file_stat->file_area_temp));
	//}while(!list_empty(&p_file_stat->file_area_temp));
	}

	/*如果到这里file_stat->file_area_temp链表时空的，说明上边的file_area都被遍历过了，那就令p_file_stat->file_area_last = NULL。
	 *否则令p_file_stat->file_area_last指向本次最后在file_stat->file_area_temp链表上遍历的file_area的上一个file_area*/
	if(!list_empty(&p_file_stat->file_area_temp)){
		/*下个周期直接从p_file_stat->file_area_last指向的file_area开始扫描*/
		if(!list_is_first(&p_file_area->file_area_list,&p_file_stat->file_area_temp))
			p_file_stat->file_area_last = list_prev_entry(p_file_area,file_area_list);
		else
			p_file_stat->file_area_last = list_last_entry(&p_file_stat->file_area_temp,struct file_area,file_area_list);
	}else{
		p_file_stat->file_area_last = NULL;
		//当前文件file_stat->file_area_temp上的file_area扫描完了，需要扫描下一个文件了
		ret = 1;
	}

	if(!list_empty(&file_area_temp_head))
		//把本次扫描的暂存在file_area_temp_head临时链表上的不太冷的file_area移动到file_stat->file_area_temp链表尾
		list_splice_tail(&file_area_temp_head,&p_file_stat->file_area_temp);

    if(shrink_page_printk_open)
	    printk("4:%s file_stat:0x%llx cold_page_count:%d\n",__func__,(u64)p_file_stat,cold_page_count);

	//如果本次对文件遍历结束后，有未达到BUF_PAGE_COUNT数目要回收的page，这里就隔离+回收这些page
	if(cold_page_count){
    #ifdef USE_KERNEL_SHRINK_INACTIVE_LIST
		isolate_pages = cold_mmap_file_isolate_lru_pages_and_shrink(p_hot_cold_file_global,p_file_stat,p_file_area,page_buf,cold_page_count);
		reclaimed_pages = p_hot_cold_file_global->hot_cold_file_shrink_counter.mmap_free_pages_count;
    #else		
		isolate_pages += cold_mmap_file_isolate_lru_pages(p_hot_cold_file_global,p_file_stat,p_file_area,page_buf,cold_page_count);
		reclaimed_pages += cold_file_shrink_pages(p_hot_cold_file_global,p_file_stat,1);
	#endif
		if(shrink_page_printk_open)
			printk("5:%s %s file_stat:0x%llx reclaimed_pages:%d isolate_pages:%d\n",__func__,p_file_stat->file_name,(u64)p_file_stat,reclaimed_pages,isolate_pages);
	}

    /*遍历file_stat->file_area_free_temp链表上已经释放page的file_area，如果长时间还没被访问，那就释放掉file_area。
	 *否则访问的话，要把file_area移动到file_stat->file_area_refault或file_area_temp链表。是否一次遍历完file_area_free_temp
	 *链表上所有的file_area呢？那估计会很损耗性能，因为要检测这些file_area的page映射页表的pte，这样太浪费性能了！
	 *也得弄个file_area_last，每次只遍历file_area_free_temp链表上几十个file_area，file_area_last记录最后一次的
	 *file_area的上一个file_area，下次循环直接从file_area_last指向file_area开始遍历。这样就不会重复遍历file_area，
	 *也不会太浪费性能*/

/*
#if 0
    //list_for_each_entry_safe_reverse(p_file_area,tmp_file_area,&p_file_stat->file_area_free_temp,file_area_list)
	if(!list_empty(&p_file_stat->file_area_free_temp)){
		reverse_file_area_refault_and_free_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_refault_last,&p_file_stat->file_area_free_temp,32,FILE_AREA_FREE);
	}
	//遍历file_stat->file_area_refault链表上file_area，如果长时间不被访问，要降级到file_stat->file_area_temp链表
	//list_for_each_entry_safe_reverse(p_file_area,tmp_file_area,&p_file_stat->file_area_refault,file_area_list)
	if(!list_empty(&p_file_stat->file_area_refault)){
		reverse_file_area_refault_and_free_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_free_last,&p_file_stat->file_area_refault,16,FILE_AREA_REFAULT);
	}
	//遍历file_stat->file_area_mapcount上的file_area，如果file_area的page的mapcount都是1，file_area不再是mapcount file_area，则降级到temp_list
	if(!list_empty(&p_file_stat->file_area_mapcount)){
		reverse_file_area_mapcount_and_hot_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_mapcount,8,FILE_AREA_MAPCOUNT,MMAP_FILE_AREA_MAPCOUNT_AGE_DX);
	}
	//遍历file_stat->file_area_hot上的file_area，如果长时间不被访问了，则降级到temp_list
	if(!list_empty(&p_file_stat->file_area_hot)){
		reverse_file_area_mapcount_and_hot_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_hot,8,FILE_AREA_HOT,MMAP_FILE_AREA_HOT_AGE_DX);
	}	
*/
//#else
	/*遍历file_stat->file_area_free链表上file_area，如果长时间不被访问则释放掉，如果被访问了则升级到file_stat->file_area_refault或temp链表*/
	if(!list_empty(&p_file_stat->file_area_free_temp)){
		reverse_other_file_area_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_free_temp,32,FILE_AREA_FREE,MMAP_FILE_AREA_FREE_AGE_DX);
	}
	/*遍历file_stat->file_area_refault链表上file_area，如果长时间不被访问，要降级到file_stat->file_area_temp链表*/
	if(!list_empty(&p_file_stat->file_area_refault)){
		reverse_other_file_area_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_refault,16,FILE_AREA_REFAULT,MMAP_FILE_AREA_REFAULT_AGE_DX);
	}
	//遍历file_stat->file_area_mapcount上的file_area，如果file_area的page的mapcount都是1，file_area不再是mapcount file_area，则降级到temp_list
	if(!list_empty(&p_file_stat->file_area_mapcount)){
		reverse_other_file_area_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_mapcount,8,FILE_AREA_MAPCOUNT,MMAP_FILE_AREA_MAPCOUNT_AGE_DX);
	}
	//遍历file_stat->file_area_hot上的file_area，如果长时间不被访问了，则降级到temp_list
	if(!list_empty(&p_file_stat->file_area_hot)){
		reverse_other_file_area_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_hot,8,FILE_AREA_HOT,MMAP_FILE_AREA_HOT_AGE_DX);
	}
//#endif

	/*文件的radix tree在遍历完一次所有的page后，可能存在空洞，于是后续还要再遍历文件的radix tree获取之前没有遍历到的page*/
	reverse_file_stat_radix_tree_hole(p_hot_cold_file_global,p_file_stat);

    if(shrink_page_printk_open1)
	    printk("%s %s file_stat:0x%llx already_scan_file_area_count:%d reclaimed_pages:%d isolate_pages:%d\n",__func__,p_file_stat->file_name,(u64)p_file_stat,*already_scan_file_area_count,reclaimed_pages,isolate_pages);
	return ret;
}
#if 0 //这个函数的作用已经分拆了，第一次扫描文件page并创建file_area的代码已经移动到scan_uninit_file_stat()函数了
/*
 * 1：如果还没有遍历过file_stat对应的文件的radix tree，先遍历一遍radix tree，得到page，分配file_area并添加到file_stat->file_area_temp链表头，
 *    还把file_area保存在radix tree
 * 2：如果已经遍历完一次文件的radix tree，则开始遍历file_stat->file_area_temp链表上的file_area的page，如果page被访问了则把file_area移动到
 * file_stat->file_area_temp链表头。如果file_area的page长时间不被访问，把file_area移动到file_stat->file_area_free链表，则回收这些page
 * 
 * 2.1：遍历file_stat->file_area_free链表上的file_area，如果对应page被访问了则file_area移动到file_stat->file_area_refault链表;
 *      如果对应page长时间不被访问则释放掉file_area
 * 2.2：如果file_stat->file_area_refault链表上file_area的page如果长时间不被访问，则移动回file_stat->file_area_temp链表
 *
 * 2.3：文件可能有page没有被file_area控制，存在空洞。就是说有些文件页page最近被访问了，才分配并加入radix tree，这些page还没有分配
 *      对应的file_area。于是遍历文件file_stat保存file_area的radix tree，找到没有file_area的槽位，计算出本应该保存在这个槽位的file_area
 *      对应的page的索引，再去保存page的radix tree的查找这个page是否分配了，是的话就分配file_area并添加到file_stat->file_area_temp链表头
 * */
static unsigned int traverse_mmap_file_stat_get_cold_page(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,unsigned int scan_file_area_max,unsigned int *already_scan_file_area_count)
{
	int i,k;
	struct hot_cold_file_area_tree_node *parent_node;
	void **page_slot_in_tree;
	unsigned int area_index_for_page;
	int ret = 0;
	struct page *page;
	unsigned int file_page_count = p_file_stat->mapping->host->i_size >> PAGE_SHIFT;//除以4096
	struct address_space *mapping = p_file_stat->mapping;

	printk("1:%s file_stat:0x%llx file_stat->last_index:%d file_area_count:%d traverse_done:%d\n",__func__,(u64)p_file_stat,p_file_stat->last_index,p_file_stat->file_area_count,p_file_stat->traverse_done);
	if(p_file_stat->max_file_area_age || p_file_stat->recent_access_age || p_file_stat->hot_file_area_cache[0] || p_file_stat->hot_file_area_cache[1] ||p_file_stat->hot_file_area_cache[2]){
		panic("file_stat error\n");
	}

	/*p_file_stat->traverse_done非0，说明还没遍历完一次文件radix tree上所有的page，那就遍历一次，每4个page分配一个file_area*/
	if(0 == p_file_stat->traverse_done){
		/*第一次扫描文件的page，每个周期扫描SCAN_PAGE_COUNT_ONCE个page，一直到扫描完所有的page。4个page一组，每组分配一个file_area结构*/
		for(i = 0;i < SCAN_PAGE_COUNT_ONCE >> PAGE_COUNT_IN_AREA_SHIFT;i++){
			for(k = 0;k < PAGE_COUNT_IN_AREA;k++){
				/*这里需要优化，遍历一次radix tree就得到4个page，完全可以实现的，节省性能$$$$$$$$$$$$$$$$$$$$$$$$*/
				page = xa_load(&mapping->i_pages, p_file_stat->last_index + k);
				if (page && !xa_is_value(page) && page_mapped(page)) {
					area_index_for_page = page->index >> PAGE_COUNT_IN_AREA_SHIFT;
					parent_node = hot_cold_file_area_tree_lookup_and_create(&p_file_stat->hot_cold_file_area_tree_root_node,area_index_for_page,&page_slot_in_tree);
					if(IS_ERR(parent_node)){
						ret = -1;
						printk("%s hot_cold_file_area_tree_lookup_and_create fail\n",__func__);
						goto out;
					}
					if(NULL == *page_slot_in_tree){
						//分配file_area并初始化，成功返回0
						if(file_area_alloc_and_init(parent_node,page_slot_in_tree,area_index_for_page,p_file_stat) < 0){
							ret = -1;
							goto out;
						}
					}
					else{
						printk("%s file_stat:0x%llx file_area index:%d_%ld already alloc\n",__func__,(u64)p_file_stat,area_index_for_page,page->index);
					}
					/*4个连续的page只要有一个在radix tree找到，分配file_area,之后就不再查找其他page了*/
					break;
				}
			}
			p_file_stat->last_index += PAGE_COUNT_IN_AREA;
		}
		//p_file_stat->last_index += SCAN_PAGE_COUNT_ONCE;
		//if成立说明整个文件的page都扫描完了
		if(p_file_stat->last_index >= file_page_count){
			p_file_stat->traverse_done = 1;
			//file_stat->last_index清0
			p_file_stat->last_index = 0;
		}

		ret = 1;
	}else{
		/*到这个分支，文件的所有文件页都遍历了一遍。那就开始回收这个文件的文件页page了。但是可能存在空洞，上边的遍历就会不完整，有些page
		 * 还没有分配，那这里除了内存回收外，还得遍历文件文件的radix tree，找到之前没有映射的page，但是这样太浪费性能了。于是遍历保存file_area
		 * 的radix tree，找到空洞file_area，这些file_area对应的page还没有被管控起来。$$$$$$$$$$$$$$$$$$$$$$$$$$*/
		p_file_stat->traverse_done ++;

		if(!list_empty(&p_file_stat->file_area_temp))
			check_file_area_cold_page_and_clear(p_hot_cold_file_global,p_file_stat,scan_file_area_max,already_scan_file_area_count);
	}
out:
	return ret;
}
#endif

static int traverse_mmap_file_stat_get_cold_page(struct hot_cold_file_global *p_hot_cold_file_global,struct file_stat * p_file_stat,unsigned int scan_file_area_max,unsigned int *already_scan_file_area_count)
{
	int ret;
	if(shrink_page_printk_open)
		printk("1:%s file_stat:0x%llx file_stat->last_index:%ld file_area_count:%d traverse_done:%d\n",__func__,(u64)p_file_stat,p_file_stat->last_index,p_file_stat->file_area_count,p_file_stat->traverse_done);

	if(p_file_stat->max_file_area_age/* || p_file_stat->hot_file_area_cache[0] || p_file_stat->hot_file_area_cache[1] ||p_file_stat->hot_file_area_cache[2]*/){
		panic("file_stat error p_file_stat:0x%llx\n",(u64)p_file_stat);
	}

	/*到这个分支，文件的所有文件页都遍历了一遍。那就开始回收这个文件的文件页page了。但是可能存在空洞，上边的遍历就会不完整，有些page
	 * 还没有分配，那这里除了内存回收外，还得遍历文件文件的radix tree，找到之前没有映射的page，但是这样太浪费性能了。于是遍历保存file_area
	 * 的radix tree，找到空洞file_area，这些file_area对应的page还没有被管控起来*/

	//令inode引用计数加1，防止遍历该文件的radix tree时文件inode被释放了
	if(file_inode_lock(p_file_stat) == 0)
	{
		printk("%s file_stat:0x%llx status 0x%lx inode lock fail\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
		return -1;
	}
	ret = check_file_area_cold_page_and_clear(p_hot_cold_file_global,p_file_stat,scan_file_area_max,already_scan_file_area_count);
	//令inode引用计数减1
	file_inode_unlock(p_file_stat);

	//返回值是1是说明当前这个file_stat的file_area已经全扫描完了，则扫描该file_stat在global->mmap_file_stat_temp_large_file_head或global->mmap_file_stat_temp_head链表上的上一个file_stat的file_area
	return ret;
}

/*
目前遍历各种global 链表上的file_stat，或者file_stat链表上的file_area，有两种形式。
1:比如 check_file_area_cold_page_and_clear()函数，遍历file_stat->temp 链表上的file_area，从链表尾到头遍历，每次定义一个file_stat->file_area_last指针。它指向一个文件file_stat->temp链表上每轮遍历的最后一个file_area。下轮再次遍历这个文件file_stat->temp链表上的file_area时，直接从file_stat->file_area_last指针指向的file_area开始遍历就行。这种形式的好处是，当遍历到热file_area，留在链表头，遍历到冷file_area留在链表尾巴，冷file_area都聚集在file_stat->temp 链表尾。而当遍历完一轮file_stat->temp 链表上的file_area时，file_stat冷却N个周期后才能再次遍历file_stat->temp 链表上的file_area。等N个周期后，继续从file_stat->temp 链表尾遍历file_area，只用遍历链表尾的冷file_area后，就可以结束遍历，进入冷却期。这样就可以大大降级性能损耗，因为不用遍历整个file_stat->temp链表。这个方案的缺点时，在文件file_stat进去冷却期后，N个周期内，不再遍历file_stat->temp 链表上的file_area，也牵连到不能遍历 file_stat->free、refault、hot、mapcount 链表上的file_area。因为check_file_area_cold_page_and_clear()函数中，这些链表上的file_area是连续遍历的。后期可以考虑把遍历file_stat->temp 链表上的file_area 和 遍历 file_stat->free、refault、hot、mapcount 链表上的file_area 分开????????????????????????????????其实也没必要分开，file_stat的冷却期N，也不会太长，而file_stat->free、refault、hot、mapcount  链表上的file_area 的page都比较特殊，根本不用频繁遍历，N个周期不遍历也没啥事，反而能降低性能损耗。

2:比如 reverse_file_area_mapcount_and_hot_list 函数，每次都从file_stat->file_area_mapcount链表尾遍历一定数据的file_area，并记录当时的global age，然后移动到链表头。下次还是从file_stat->file_area_mapcount链表尾开始遍历file_area，如果file_area的age与gloabl age小于M，结束遍历。就是说，这些链表上的file_area必须间隔M个周期才能再遍历一次，降级性能损耗。这种的优点是设计简单，易于理解，但是不能保证链表尾的都是冷file_area。
 * */

#if 0 //下边的代码很有意义，不要删除，犯过很多错误
static int get_file_area_from_mmap_file_stat_list(struct hot_cold_file_global *p_hot_cold_file_global,unsigned int scan_file_area_max,unsigned int scan_file_stat_max,struct list_head *file_stat_temp_head)//file_stat_temp_head链表来自 global->mmap_file_stat_temp_head 和 global->mmap_file_stat_temp_large_file_head 链表
{
	struct file_stat * p_file_stat = NULL,*p_file_stat_temp = NULL;
	unsigned int scan_file_area_count  = 0;
	unsigned int scan_file_stat_count  = 0;
	unsigned int free_pages = 0;
	int ret = 0;
	char delete_file_stat_last = 0;
	char scan_next_file_stat = 0;

	if(list_empty(file_stat_temp_head))
		return ret;

	printk("1:%s file_stat_last:0x%llx\n",__func__,(u64)p_hot_cold_file_global->file_stat_last);
	if(p_hot_cold_file_global->file_stat_last){//本次从上一轮扫描打断的file_stat继续遍历
		p_file_stat = p_hot_cold_file_global->file_stat_last;
	}
	else{
		//第一次从链表尾的file_stat开始遍历
		p_file_stat = list_last_entry(file_stat_temp_head,struct file_stat,hot_cold_file_list);
		p_hot_cold_file_global->file_stat_last = p_file_stat;
	}	

	do{
		/*加个panic判断，如果p_file_stat是链表头p_hot_cold_file_global->mmap_file_stat_temp_head，那就触发panic*/

		/*查找file_stat在global->mmap_file_stat_temp_head链表上一个file_stat。如果p_file_stat不是链表头的file_stat，直接list_prev_entry
		 * 找到上一个file_stat。如果p_file_stat是链表头的file_stat，那要跳过链表过，取出链表尾的file_stat*/
		if(!list_is_first(&p_file_stat->hot_cold_file_list,file_stat_temp_head))
			p_file_stat_temp = list_prev_entry(p_file_stat,hot_cold_file_list);
		else
			p_file_stat_temp = list_last_entry(file_stat_temp_head,struct file_stat,hot_cold_file_list);

		if(!file_stat_in_file_stat_temp_head_list(p_file_stat) || file_stat_in_file_stat_temp_head_list_error(p_file_stat)){
			panic("%s file_stat:0x%llx not int file_stat_temp_head status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
		}


		/*因为存在一种并发，1：文件mmap映射分配file_stat向global mmap_file_stat_temp_head添加，并赋值mapping->rh_reserved1=p_file_stat，
		 * 2：这个文件cache读写执行hot_file_update_file_status()，分配file_stat向global file_stat_temp_head添加,并赋值
		 * mapping->rh_reserved1=p_file_stat。因为二者流程并发执行，因为mapping->rh_reserved1是NULL，导致两个流程都分配了file_stat并赋值
		 * 给mapping->rh_reserved1。因此这里的file_stat可能就是cache读写产生的，目前先暂定把mapping->rh_reserved1清0，让下次文件cache读写
		 * 再重新分配file_stat并赋值给mapping->rh_reserved1。这个问题没有其他并发问题，无非就是分配两个file_stat都赋值给mapping->rh_reserved1。
		 *
		 * 还有一点，异步内存回收线程walk_throuth_all_file_area()回收cache文件的page时，从global temp链表遍历file_stat时，要判断
		 * if(file_stat_in_mmap_file(p_file_stat))，是的话也要p_file_stat->mapping->rh_reserved1 = 0并跳过这个file_stat
		 *
		 * 这个问题有个解决方法，就是mmap文件分配file_stat 和cache文件读写分配file_stat，都是用global_lock锁，现在用的是各自的锁。
		 * 这样就避免了分配两个file_stat并都赋值给mapping->rh_reserved1
		 * */
		if(file_stat_in_cache_file(p_file_stat)){
			/*如果p_file_stat从从global mmap_file_stat_temp_head链表剔除，且与p_hot_cold_file_global->file_stat_last指向同一个file_stat。
			 *那要把p_file_stat在global mmap_file_stat_temp_head链表的上一个file_stat(即p_file_stat_temp)赋值给p_hot_cold_file_global->file_stat_last。
			 *否则，会导致下边的while(p_file_stat != p_hot_cold_file_global->file_stat_last)永远不成立,陷入死循环,详解见check_file_area_cold_page_and_clear()*/
			if(p_hot_cold_file_global->file_stat_last == p_file_stat){
				p_hot_cold_file_global->file_stat_last = p_file_stat_temp;
				delete_file_stat_last = 1;
			}
			spin_lock(&p_hot_cold_file_global->mmap_file_global_lock);
			clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			set_file_stat_in_delete(p_file_stat);
			p_file_stat->mapping->rh_reserved1 = 0;
			list_del(&p_file_stat->hot_cold_file_list);
			spin_unlock(&p_hot_cold_file_global->mmap_file_global_lock);

			/*释放掉file_stat的所有file_area，最后释放掉file_stat。但释放file_stat用的还是p_hot_cold_file_global->global_lock锁防护
			 *并发，这点后期需要改进!!!!!!!!!!!!!!!!!!!!!!!!!*/
			cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
			printk("%s p_file_stat:0x%llx status:0x%lx in_cache_file\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
			//p_file_stat = p_file_stat_temp;
			//continue;
			goto next;
		}else if(file_stat_in_delete(p_file_stat)){
			printk("%s p_file_stat:0x%llx status:0x%lx in_delete\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
			//上边有解释
			if(p_hot_cold_file_global->file_stat_last == p_file_stat){
				p_hot_cold_file_global->file_stat_last = p_file_stat_temp;
				delete_file_stat_last = 1;
			}

			/*释放掉file_stat的所有file_area，最后释放掉file_stat*/
			cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
			//p_file_stat = p_file_stat_temp;
			//continue;
			goto next;
		}

		/*针对0个file_area的file_stat，不能把它移动到mmap_file_stat_zero_file_area_head链表，然后释放掉file_stat。因为如果后续这个文件file_stat
		 *又有文件页page被访问并分配，建立页表页目录映射，我的代码感知不到这点，但是file_stat已经释放了。这种情况下的文件页就无法被内存回收了!
		 *那什么情况下才能释放file_stat呢？在unmap 文件时，可以释放file_stat吗？可以，但是需要保证在unmap且没有其他进程mmap映射这个文件时，
		 *才能unmap时释放掉file_stat结构。这样稍微有点麻烦！还有一种情况可以释放file_stat，就是文件indoe被释放时，这种情况肯定可以释放掉
		 *file_stat结构*/
		if(p_file_stat->file_area_count == 0){
			/*spin_lock(&p_hot_cold_file_global->mmap_file_global_lock);
			  clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			  set_file_stat_in_zero_file_area_list(p_file_stat);
			  list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_zero_file_area_head);
			  spin_unlock(&p_hot_cold_file_global->mmap_file_global_lock);
			  goto next;*/
		}

		ret = traverse_mmap_file_stat_get_cold_page(p_hot_cold_file_global,p_file_stat,scan_file_area_max,&scan_file_area_count);
		//返回值是1是说明当前这个file_stat的temp链表上的file_area已经全扫描完了，则扫描该file_stat在global->mmap_file_stat_temp_large_file_head或global->mmap_file_stat_temp_head链表上的上一个file_stat的file_area
		if(ret > 0){
			scan_next_file_stat = 1; 
		}else if(ret < 0){
			return -1;
		}

#if 0 
		//---------------------重大后期改进
		/*ret是1说明这个file_stat还没有从radix tree遍历完一次所有的page，那就把file_stat移动到global mmap_file_stat_temp_head链表尾
		//这样下个周期还能继续扫描这个文件radix tree的page--------------这个解决方案不行，好的解决办法是每次设定最多遍历新文件的page
		//的个数，如果本次这个文件没有遍历完，下次也要从这个文件继续遍历。
		//有个更好的解决方案，新的文件的file_stat要添加到global mmap_temp_not_done链表，只有这个文件的page全遍历完一次，再把这个file_stat
		//移动到global mmap_file_stat_temp_head链表。异步内存回收线程每次两个链表上的文件file_stat按照一定比例都分开遍历，谁也不影响谁*/
		if(1 == ret){
			if(!list_is_last(&p_file_stat->hot_cold_file_list,file_stat_temp_head)){
				spin_lock(&p_hot_cold_file_global->mmap_file_global_lock);
				list_move_tail(&p_file_stat->hot_cold_file_list,file_stat_temp_head);
				spin_unlock(&p_hot_cold_file_global->mmap_file_global_lock);
			}
		}
#endif

next:
		//只有当前的file_stat的temp链表上的file_area扫描完，才能扫描下一个file_stat
		if(scan_next_file_stat){
			printk("%s p_file_stat:0x%llx file_area:%d scan complete,next scan file_stat:0x%llx\n",__func__,(u64)p_file_stat,p_file_stat->file_area_count,(u64)p_file_stat_temp);
			//下一个file_stat
			//p_file_stat = p_file_stat_temp;
			scan_file_stat_count ++;
		}

		//遍历指定数目的file_stat和file_area后，强制结束遍历
		if(scan_file_area_count >= scan_file_area_max || scan_file_stat_count  >= scan_file_stat_max){
			printk("%s scan_file_area_count:%d scan_file_stat_count:%d exceed max\n",__func__,scan_file_area_count,scan_file_stat_count);
			break;
		}

		if(0 == delete_file_stat_last && p_file_stat == p_hot_cold_file_global->file_stat_last){
			printk("%s p_file_stat:0x%llx == p_hot_cold_file_global->file_stat_last\n",__func__,(u64)p_file_stat);
			break;
		}
		else if(delete_file_stat_last)
			delete_file_stat_last = 0;

		//在scan_next_file_stat时把p_file_stat = p_file_stat_temp赋值放到下边。因为，如果上边可能break了，
		//而p_file_stat = p_file_stat_temp已经赋值过了，但这个file_stat根本没扫描。接着跳出while循环，
		//下边对p_hot_cold_file_global->file_stat_last新的file_stat，而当前的file_stat就漏掉扫描了!!!!!!!!
		if(scan_next_file_stat){
			//下一个file_stat
			p_file_stat = p_file_stat_temp;
		}


	/*这里退出循环的条件，不能碰到链表头退出，是一个环形队列的遍历形式。主要原因是不想模仿read/write文件页的内存回收思路：
	 *先加锁从global temp链表隔离几十个文件file_stat，清理file_stat的状态，然后内存回收。内存回收后再把file_stat加锁
	 *移动到global temp链表头。这样太麻烦了，还浪费性能。针对mmap文件页的内存回收，不用担心并发问题，不用这么麻烦
	 *
	 * 以下两种情况退出循环
	 *1：上边的 遍历指定数目的file_stat和file_area后，强制结束遍历
	 *2：这里的while，本次循环处理到file_stat已经是第一次循环处理过了，相当于重复了
	 *3：添加!list_empty(file_stat_temp_head)判断，原理分析在check_file_area_cold_page_and_clear()函数
	 */
	//}while(p_file_stat != p_hot_cold_file_global->file_stat_last);
	//}while(p_file_stat != p_hot_cold_file_global->file_stat_last && !list_empty(file_stat_temp_head));
	}while(!list_empty(file_stat_temp_head));

	/*scan_next_file_stat如果是1，说明当前文件file_stat的temp链表上已经扫描的file_area个数超过该文件temp链表的总file_area个数，
	 *然后才能更新p_hot_cold_file_global->file_stat_last，这样下次才能扫描该file_stat在global->mmap_file_stat_temp_large_file_head
	 *或global->mmap_file_stat_temp_head链表上的上一个file_stat*/
	if(1 == scan_next_file_stat){
		if(!list_empty(file_stat_temp_head)){
			/*p_hot_cold_file_global->file_stat_last指向_hot_cold_file_global->file_stat_temp_head链表上一个file_area，下个周期
			 *直接从p_hot_cold_file_global->file_stat_last指向的file_stat开始扫描*/
			if(!list_is_first(&p_file_stat->hot_cold_file_list,file_stat_temp_head))
				p_hot_cold_file_global->file_stat_last = list_prev_entry(p_file_stat,hot_cold_file_list);
			else
				p_hot_cold_file_global->file_stat_last = list_last_entry(file_stat_temp_head,struct file_stat,hot_cold_file_list);
		}else{
			p_hot_cold_file_global->file_stat_last = NULL;
		}
	}
	//err:
	return free_pages;
}
#endif

static int get_file_area_from_mmap_file_stat_list(struct hot_cold_file_global *p_hot_cold_file_global,unsigned int scan_file_area_max,unsigned int scan_file_stat_max,struct list_head *file_stat_temp_head)//file_stat_temp_head链表来自 global->mmap_file_stat_temp_head 和 global->mmap_file_stat_temp_large_file_head 链表
{
	struct file_stat * p_file_stat = NULL,*p_file_stat_temp = NULL;
	unsigned int scan_file_area_count  = 0;
	unsigned int scan_file_stat_count  = 0;
	unsigned int free_pages = 0;
	int ret = 0;
	LIST_HEAD(file_stat_list);

	if(list_empty(file_stat_temp_head))
		return ret;
	if(shrink_page_printk_open)
		printk("1:%s file_stat_last:0x%llx\n",__func__,(u64)p_hot_cold_file_global->file_stat_last);

	//每次都从链表尾开始遍历
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,file_stat_temp_head,hot_cold_file_list)
	{
		/*如果p_file_stat是链表头p_hot_cold_file_global->mmap_file_stat_temp_head，那就触发panic*/
		if(!file_stat_in_file_stat_temp_head_list(p_file_stat) || file_stat_in_file_stat_temp_head_list_error(p_file_stat)){
			panic("%s file_stat:0x%llx not int file_stat_temp_head status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
		}
		
		//遍历指定数目的file_stat和file_area后，强制结束遍历。包括遍历delete等文件
		if(scan_file_area_count >= scan_file_area_max){
			if(shrink_page_printk_open)
				printk("%s scan_file_area_count:%d scan_file_stat_count:%d exceed max\n",__func__,scan_file_area_count,scan_file_stat_count);

			break;
		}
		scan_file_stat_count ++;

		/*因为存在一种并发，1：文件mmap映射分配file_stat向global mmap_file_stat_temp_head添加，并赋值mapping->rh_reserved1=p_file_stat，
		 * 2：这个文件cache读写执行hot_file_update_file_status()，分配file_stat向global file_stat_temp_head添加,并赋值
		 * mapping->rh_reserved1=p_file_stat。因为二者流程并发执行，因为mapping->rh_reserved1是NULL，导致两个流程都分配了file_stat并赋值
		 * 给mapping->rh_reserved1。因此这里的file_stat可能就是cache读写产生的，目前先暂定把mapping->rh_reserved1清0，让下次文件cache读写
		 * 再重新分配file_stat并赋值给mapping->rh_reserved1。这个问题没有其他并发问题，无非就是分配两个file_stat都赋值给mapping->rh_reserved1。
		 *
		 * 还有一点，异步内存回收线程walk_throuth_all_file_area()回收cache文件的page时，从global temp链表遍历file_stat时，要判断
		 * if(file_stat_in_mmap_file(p_file_stat))，是的话也要p_file_stat->mapping->rh_reserved1 = 0并跳过这个file_stat
		 *
		 * 这个问题有个解决方法，就是mmap文件分配file_stat 和cache文件读写分配file_stat，都是用global_lock锁，现在用的是各自的锁。
		 * 这样就避免了分配两个file_stat并都赋值给mapping->rh_reserved1
		 * */
		if(file_stat_in_cache_file(p_file_stat)){
			spin_lock(&p_hot_cold_file_global->mmap_file_global_lock);
			clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			set_file_stat_in_delete(p_file_stat);
			p_file_stat->mapping->rh_reserved1 = 0;
			list_del(&p_file_stat->hot_cold_file_list);
			spin_unlock(&p_hot_cold_file_global->mmap_file_global_lock);

			/*释放掉file_stat的所有file_area，最后释放掉file_stat。但释放file_stat用的还是p_hot_cold_file_global->global_lock锁防护
			 *并发，这点后期需要改进!!!!!!!!!!!!!!!!!!!!!!!!!*/
			cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
			printk("%s p_file_stat:0x%llx status:0x%lx in_cache_file\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
			continue;
		}else if(file_stat_in_delete(p_file_stat)){
			printk("%s p_file_stat:0x%llx status:0x%lx in_delete\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
			
			/*释放掉file_stat的所有file_area，最后释放掉file_stat*/
			cold_file_stat_delete_all_file_area(p_hot_cold_file_global,p_file_stat);
			continue;
		}

		//如果文件file_stat还在冷却期，不扫描这个文件file_stat->temp链表上的file_area，只是把file_stat移动到file_stat_list临时链表
		if(p_file_stat->cooling_off_start){
			if(p_hot_cold_file_global->global_age - p_file_stat->cooling_off_start_age < MMAP_FILE_AREA_COLD_AGE_DX){
			    list_move(&p_file_stat->hot_cold_file_list,&file_stat_list);
			    continue;
			}
			else{
			    p_file_stat->cooling_off_start = 0;
			}
		}

		/*针对0个file_area的file_stat，不能把它移动到mmap_file_stat_zero_file_area_head链表，然后释放掉file_stat。因为如果后续这个文件file_stat
		 *又有文件页page被访问并分配，建立页表页目录映射，我的代码感知不到这点，但是file_stat已经释放了。这种情况下的文件页就无法被内存回收了!
		 *那什么情况下才能释放file_stat呢？在unmap 文件时，可以释放file_stat吗？可以，但是需要保证在unmap且没有其他进程mmap映射这个文件时，
		 *才能unmap时释放掉file_stat结构。这样稍微有点麻烦！还有一种情况可以释放file_stat，就是文件indoe被释放时，这种情况肯定可以释放掉
		 *file_stat结构*/
		if(p_file_stat->file_area_count == 0){//这段代码比较重要不要删除---------------------------
			/*spin_lock(&p_hot_cold_file_global->mmap_file_global_lock);
			  clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
			  set_file_stat_in_zero_file_area_list(p_file_stat);
			  list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_zero_file_area_head);
			  spin_unlock(&p_hot_cold_file_global->mmap_file_global_lock);
			  goto next;*/
		}

		ret = traverse_mmap_file_stat_get_cold_page(p_hot_cold_file_global,p_file_stat,scan_file_area_max,&scan_file_area_count);
		//返回值是1是说明当前这个file_stat的temp链表上的file_area已经全扫描完了，则扫描该file_stat在global->mmap_file_stat_temp_large_file_head或global->mmap_file_stat_temp_head链表上的上一个file_stat的file_area
		if(ret < 0){
			return -1;
		}

		/*到这里，只有几种情况
		 *1：当前文件p_file_stat->temp链表上的file_area扫描了一遍，ret是1，此时需要把p_file_stat移动到file_stat_list临时链表，然后下轮for循环扫描下一个文件
		 *2：当前文件p_file_stat->temp链表上的file_area太多了，已经扫描的file_area个数超过scan_file_stat_max，break退出，下次执行该函数还要继续扫描p_file_stat这个文件
		 * */

		//只有当前的file_stat的temp链表上的file_area扫描完，才能扫描下一个file_stat
		if(ret > 0){
			/*遍历过的文件file_stat移动到file_stat_list临时链表。但可能这个file_stat因为热file_area增多而变成了热file_area而移动到了global hot链表。
			 *此时这里再把这个热file_area移动到file_stat_list临时链表，该函数最后再把它移动到global temp链表，那该热file_stat处于的链表就错了，会crash
			 *解决办法是限制这个file_stat必须处于global temp链表才能移动到file_stat_list临时链表*/
			if(file_stat_in_file_stat_temp_head_list(p_file_stat))
			    list_move(&p_file_stat->hot_cold_file_list,&file_stat_list);
			if(shrink_page_printk_open)
				printk("%s p_file_stat:0x%llx file_area:%d scan complete,next scan file_stat:0x%llx\n",__func__,(u64)p_file_stat,p_file_stat->file_area_count,(u64)p_file_stat_temp);
		}else if(scan_file_area_count  >= scan_file_area_max){
			if(shrink_page_printk_open)
				printk("%s scan_file_area_count:%d scan_file_stat_count:%d exceed max\n",__func__,scan_file_area_count,scan_file_stat_count);

			break;
		}else{
			panic("%s file_stat:0x%llx status:0x%lx exception scan_file_area_count:%d scan_file_stat_count:%d ret:%d\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status,scan_file_area_count,scan_file_stat_count,ret);
		}
    }

	//如果file_stat_list临时链表还有file_stat，则把这些file_stat移动到global temp链表头，下轮循环就能从链表尾巴扫描还没有扫描的file_stat了
	if(!list_empty(&file_stat_list)){
		list_splice(&file_stat_list,file_stat_temp_head);
	}
	return free_pages;
}

//扫描global mmap_file_stat_uninit_head链表上的file_stat的page，page存在的话则创建file_area，否则一直遍历完这个文件的所有page，才会遍历下一个文件
static int scan_uninit_file_stat(struct hot_cold_file_global *p_hot_cold_file_global,struct list_head *mmap_file_stat_uninit_head,unsigned int scan_page_max)
{
	int k;
	struct hot_cold_file_area_tree_node *parent_node;
	void **page_slot_in_tree;
	unsigned int area_index_for_page;
	int ret = 0;
	struct page *page;
	struct page *pages[PAGE_COUNT_IN_AREA];
	struct address_space *mapping;
	unsigned int scan_file_area_max = scan_page_max >> PAGE_COUNT_IN_AREA_SHIFT;
	unsigned int scan_file_area_count = 0;
	struct file_stat *p_file_stat,*p_file_stat_temp;
	unsigned int file_page_count;
	char mapcount_file_area = 0;
	struct file_area *p_file_area = NULL;

	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,mmap_file_stat_uninit_head,hot_cold_file_list){
		if(p_file_stat->file_stat_status != (1 << F_file_stat_in_mmap_file)){
			/*实际测试这里遇到过file_stat in delte，则把file_stat移动到global mmap_file_stat_temp_head链表尾，
			 *稍后get_file_area_from_mmap_file_stat_list()函数就会把这个delete的file_stat释放掉*/
			if(file_stat_in_delete(p_file_stat)){
				spin_lock(&hot_cold_file_global_info.mmap_file_global_lock);
				list_move_tail(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_temp_head);
				spin_unlock(&hot_cold_file_global_info.mmap_file_global_lock);
				printk("%s file_stat:0x%llx status:0x%lx in delete\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
				continue;
			}
			else
				panic("%s file_stat:0x%llx status error:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);
		}
		mapping = p_file_stat->mapping;
		file_page_count = p_file_stat->mapping->host->i_size >> PAGE_SHIFT;//除以4096

		if(shrink_page_printk_open)
			printk("1:%s scan file_stat:0x%llx\n",__func__,(u64)p_file_stat);

		/*这个while循环扫一个文件file_stat的page，存在的话则创建file_area。有下边这几种情况
		 *1:文件page太多，扫描的file_area超过mac，文件的page还没扫描完，直接break，下次执行函数还扫描这个文件，直到扫描完
		 *2:文件page很少，扫描的file_area未超过max就break，于是把file_stat移动到global->mmap_file_stat_temp_large_file_head或
		 *  global->mmap_file_stat_temp_head链表。这个file_stat就从global->mmap_file_stat_uninit_head链表尾剔除了，然后扫描第2个文件file_stat*/
		while(scan_file_area_count++ < scan_file_area_max){

			memset(pages,0,PAGE_COUNT_IN_AREA*sizeof(struct page *));
			//获取p_file_stat->last_index对应的PAGE_COUNT_IN_AREA文件页page指针并保存到pages数组
			ret = get_page_from_file_area(p_file_stat,p_file_stat->last_index,pages);

			if(shrink_page_printk_open)
				printk("2:%s file_stat:0x%llx start_page_index:%ld get %d page file_area_count_in_temp_list:%d\n",__func__,(u64)p_file_stat,p_file_stat->last_index,ret,p_file_stat->file_area_count_in_temp_list);
			/*遇到一个重大问题，上边打印"file_stat:0xffff8c9f5fbb1320 start_page_index:464 get 0 page"，然后之后每次执行该函数，都从global mmap_file_stat_uninit_head
			 *链表尾遍历file_stat:0xffff8c9f5fbb1320的起始索引是464的4个page，但这些page都没有，于是ret是0，这导致直接goto out。回收每次就陷入了死循环，无法遍历
			 *global mmap_file_stat_uninit_head链表尾其他file_stat，以及file_stat:0xffff8c9f5fbb1320 start_page_index:464 索引后边的page。简单说，因为一个文件
			 *file_stat的page存在空洞，导致每次执行到该函数都都一直遍历这个文件的空洞page，陷入死循环。解决方法是，遇到文件空洞page，ret是0，继续遍历下一个后边的page
			 *避免陷入死循环*/
			if(0 == ret){
			    p_file_stat->last_index += PAGE_COUNT_IN_AREA;
				if(p_file_stat->last_index >= file_page_count){
				    goto complete;
				}

				continue;
			}
			if(ret < 0){
				printk("2_1:%s file_stat:0x%llx start_page_index:%ld get %d fail\n",__func__,(u64)p_file_stat,p_file_stat->last_index,ret);
				goto out; 
			}

			mapcount_file_area = 0;
			p_file_area = NULL;
			/*第一次扫描文件的page，每个周期扫描SCAN_PAGE_COUNT_ONCE个page，一直到扫描完所有的page。4个page一组，每组分配一个file_area结构*/
			for(k = 0;k < PAGE_COUNT_IN_AREA;k++){
				/*这里需要优化，遍历一次radix tree就得到4个page，完全可以实现的，节省性能$$$$$$$$$$$$$$$$$$$$$$$$*/
				//page = xa_load(&mapping->i_pages, p_file_stat->last_index + k);
				page = pages[k];
				if (page && !xa_is_value(page) && page_mapped(page)) {
					//mapcount file_area
					if(0 == mapcount_file_area && page_mapcount(page) > 1){
						mapcount_file_area = 1;
					}

					area_index_for_page = page->index >> PAGE_COUNT_IN_AREA_SHIFT;
					page_slot_in_tree = NULL;
					parent_node = hot_cold_file_area_tree_lookup_and_create(&p_file_stat->hot_cold_file_area_tree_root_node,area_index_for_page,&page_slot_in_tree);
					if(IS_ERR(parent_node)){
						ret = -1;
						printk("3:%s hot_cold_file_area_tree_lookup_and_create fail\n",__func__);
						goto out;
					}
					if(NULL == *page_slot_in_tree){
						//分配file_area并初始化，成功返回非NULL
						p_file_area = file_area_alloc_and_init(parent_node,page_slot_in_tree,area_index_for_page,p_file_stat);
						if(p_file_area == NULL){
							ret = -1;
							goto out;
						}
					}
					else{
						panic("4:%s file_stat:0x%llx file_area index:%d_%ld 0x%llx already alloc!!!!!!!!!!!!!!!!\n",__func__,(u64)p_file_stat,area_index_for_page,page->index,(u64)(*page_slot_in_tree));
					}
					//file_stat->temp 链表上的file_area个数加1
					p_file_stat->file_area_count_in_temp_list ++;
					/*4个连续的page只要有一个在radix tree找到，分配file_area,之后就不再查找其他page了*/
					break;
				}else{
					if(shrink_page_printk_open1)
						printk("4_1:%s file_stat:0x%llx start_page_index:%ld page:0x%llx error\n",__func__,(u64)p_file_stat,p_file_stat->last_index,(u64)page);
				}
			}

			/*如果上边for循环遍历的file_area的page的mapcount都是1，且file_area的page上边没有遍历完，则这里继续遍历完剩余的page*/
			while(0 == mapcount_file_area && k < PAGE_COUNT_IN_AREA){
				page= pages[k];
				if (page && !xa_is_value(page) && page_mapped(page) && page_mapcount(page) > 1){
					mapcount_file_area = 1;
				}
				k ++;
			}
			if(mapcount_file_area){
				if(!file_area_in_temp_list(p_file_area) || file_area_in_temp_list_error(p_file_area)){
					panic("%s file_area:0x%llx status:%d not in file_area_temp\n",__func__,(u64)p_file_area,p_file_area->file_area_state);
				}

				//文件file_stat的mapcount的file_area个数加1
				p_file_stat->mapcount_file_area_count ++;
				//file_stat->temp 链表上的file_area个数减1
				p_file_stat->file_area_count_in_temp_list --;
				//file_area的page的mapcount大于1，则把file_area移动到file_stat->file_area_mapcount链表
				clear_file_area_in_temp_list(p_file_area);
				set_file_area_in_mapcount_list(p_file_area);
				list_move(&p_file_area->file_area_list,&p_file_stat->file_area_mapcount);
				if(shrink_page_printk_open)
					printk("5:%s file_stat:0x%llx file_area:0x%llx state:0x%x is mapcount file_area\n",__func__,(u64)p_file_stat,(u64)p_file_area,p_file_area->file_area_state);
			}

			//每扫描1个file_area，p_file_stat->last_index加PAGE_COUNT_IN_AREA
			p_file_stat->last_index += PAGE_COUNT_IN_AREA;

			//if成立说明整个文件的page都扫描完了
			if(p_file_stat->last_index >= file_page_count){
complete:				
				if(shrink_page_printk_open1)
					printk("6:%s file_stat:0x%llx %s all page scan complete p_file_stat->last_index:%ld file_page_count:%d\n",__func__,(u64)p_file_stat,p_file_stat->file_name,p_file_stat->last_index,file_page_count);

				//p_file_stat->traverse_done = 1;

				//对file_stat->last_index清0，后续有用于保存最近一次扫描的file_area的索引
				p_file_stat->last_index = 0;
				//在文件file_stat移动到temp链表时，p_file_stat->file_area_count_in_temp_list是文件的总file_area个数
				//p_file_stat->file_area_count_in_temp_list = p_file_stat->file_area_count;//上边已经加1了

				/*文件的page扫描完了，把file_stat从global mmap_file_stat_uninit_head链表移动到global mmap_file_stat_temp_head或
				 *mmap_file_stat_temp_large_file_head。这个过程必须加锁，因为与add_mmap_file_stat_to_list()存在并发修改global mmap_file_stat_uninit_head
				 *链表的情况。后续file_stat再移动到大文件、zero_file_area等链表，就不用再加锁了，完全是异步内存回收线程的单线程操作*/
				spin_lock(&hot_cold_file_global_info.mmap_file_global_lock);

				/*新分配的file_stat必须设置in_file_stat_temp_head_list链表。这个设置file_stat状态的操作必须放到 把file_stat添加到
				 *tmep链表前边，还要加内存屏障。否则会出现一种极端情况，异步内存回收线程从temp链表遍历到这个file_stat，
				 *但是file_stat还没有设置为in_temp_list状态。这样有问题会触发panic。因为mmap文件异步内存回收线程，
				 *从temp链表遍历file_stat没有mmap_file_global_lock加锁，所以与这里存在并发操作。而针对cache文件，异步内存回收线程
				 *从global temp链表遍历file_stat，全程global_lock加锁，不会跟向global temp链表添加file_stat存在方法，但最好改造一下*/
				set_file_stat_in_file_stat_temp_head_list(p_file_stat);
				smp_wmb();

				if(is_mmap_file_stat_large_file(p_hot_cold_file_global,p_file_stat)){
					set_file_stat_in_large_file(p_file_stat);
					list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_temp_large_file_head);
				}
				else
					list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_temp_head);

				spin_unlock(&hot_cold_file_global_info.mmap_file_global_lock);
	
				/*如果文件file_stat的mapcount的file_area个数超过阀值，则file_stat被判定为mapcount file_stat而移动到
				 *global mmap_file_stat_mapcount_head链表。但前提file_stat必须在temp_file链表或temp_large_file链表*/
				if(is_mmap_file_stat_mapcount_file(p_hot_cold_file_global,p_file_stat) && file_stat_in_file_stat_temp_head_list(p_file_stat)){
					if(file_stat_in_file_stat_temp_head_list_error(p_file_stat))
						panic("%s file_stat:0x%llx status error:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

					clear_file_stat_in_file_stat_temp_head_list(p_file_stat);
					set_file_stat_in_mapcount_file_area_list(p_file_stat);
					list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_mapcount_head);
					p_hot_cold_file_global->mapcount_mmap_file_stat_count ++;
					if(shrink_page_printk_open)
						printk("6:%s file_stat:0x%llx status:0x%llx is mapcount file\n",__func__,(u64)p_file_stat,(u64)p_file_stat->file_stat_status);
				}

				break;
			}
		}

		//如果扫描的文件页page数达到本次的限制，结束本次的scan
		if(scan_file_area_count >= scan_file_area_max){
			break;
		}
	}
out:
	return ret;
}
static int scan_mmap_mapcount_file_stat(struct hot_cold_file_global *p_hot_cold_file_global,unsigned int scan_file_area_max)
{
	struct file_stat *p_file_stat,*p_file_stat_temp;
	unsigned int mapcount_file_area_count_origin;
	unsigned int scan_file_area_count = 0;
	char file_stat_change = 0;
	LIST_HEAD(file_stat_list);

	//每次都从链表尾开始遍历
	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->mmap_file_stat_mapcount_head,hot_cold_file_list){
		if(!file_stat_in_mapcount_file_area_list(p_file_stat) || file_stat_in_mapcount_file_area_list_error(p_file_stat))
			panic("%s file_stat:0x%llx not in_mapcount_file_area_list status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

		//遍历file_stat->file_area_mapcount上的file_area，如果file_area的page的mapcount都是1，file_area不再是mapcount file_area，则降级到temp_list
		if(!list_empty(&p_file_stat->file_area_mapcount)){
			mapcount_file_area_count_origin = p_file_stat->mapcount_file_area_count;
			file_stat_change = 0;

			scan_file_area_count += reverse_other_file_area_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_mapcount,SCAN_MAPCOUNT_FILE_AREA_COUNT_ONCE,FILE_AREA_MAPCOUNT,MMAP_FILE_AREA_MAPCOUNT_AGE_DX);

			if(mapcount_file_area_count_origin != p_file_stat->mapcount_file_area_count){
				//文件file_stat的mapcount的file_area个数减少到阀值以下了，降级到普通文件
				if(0 == is_mmap_file_stat_mapcount_file(p_hot_cold_file_global,p_file_stat)){
					clear_file_stat_in_mapcount_file_area_list(p_file_stat);
					set_file_stat_in_file_stat_temp_head_list(p_file_stat);
					if(is_mmap_file_stat_large_file(p_hot_cold_file_global,p_file_stat)){//大文件
						list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_temp_large_file_head);
					}
					else{//普通文件
						list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_temp_head);
					}
					p_hot_cold_file_global->mapcount_mmap_file_stat_count --;
					file_stat_change = 1;
					if(shrink_page_printk_open1)
						printk("1:%s file_stat:0x%llx status:0x%llx  mapcount to temp file\n",__func__,(u64)p_file_stat,(u64)p_file_stat->file_stat_status);
				}
			}
		}

		/*file_stat未发生变化，先移动到file_stat_list临时链表。如果此时global mmap_file_stat_mapcount_head链表没有file_stat了，
		  则p_file_stat_temp指向链表头，下次循环直接break跳出*/
		if(0 == file_stat_change)
			list_move(&p_file_stat->hot_cold_file_list,&file_stat_list);

		//超出扫描的file_area上限，break
		if(scan_file_area_count > scan_file_area_max){
			break;
		}
	}

	//如果file_stat_list临时链表还有file_stat，则把这些file_stat移动到global mmap_file_stat_hot_head链表头，下轮循环就能从链表尾巴扫描还没有扫描的file_stat了
	if(!list_empty(&file_stat_list)){
		list_splice(&file_stat_list,&p_hot_cold_file_global->mmap_file_stat_mapcount_head);
	}

	return scan_file_area_count;
}
static int scan_mmap_hot_file_stat(struct hot_cold_file_global *p_hot_cold_file_global,unsigned int scan_file_area_max)
{
	struct file_stat *p_file_stat,*p_file_stat_temp;
	unsigned int file_area_hot_count_origin;
	unsigned int scan_file_area_count = 0;
	char file_stat_change = 0;
	LIST_HEAD(file_stat_list);


	list_for_each_entry_safe_reverse(p_file_stat,p_file_stat_temp,&p_hot_cold_file_global->mmap_file_stat_hot_head,hot_cold_file_list){
		if(!file_stat_in_file_stat_hot_head_list(p_file_stat) || file_stat_in_file_stat_hot_head_list_error(p_file_stat))
			panic("%s file_stat:0x%llx not in_file_stat_hot_head_list status:0x%lx\n",__func__,(u64)p_file_stat,p_file_stat->file_stat_status);

		//遍历file_stat->file_area_hot上的file_area，如果长时间不被访问了，则降级到temp_list
		if(!list_empty(&p_file_stat->file_area_hot)){
			file_area_hot_count_origin = p_file_stat->file_area_hot_count;

			scan_file_area_count += reverse_other_file_area_list(p_hot_cold_file_global,p_file_stat,&p_file_stat->file_area_hot,SCAN_HOT_FILE_AREA_COUNT_ONCE,FILE_AREA_HOT,MMAP_FILE_AREA_HOT_AGE_DX);

			if(file_area_hot_count_origin != p_file_stat->file_area_hot_count){
				//文件file_stat的mapcount的file_area个数减少到阀值以下了，降级到普通文件
				if(0 == is_mmap_file_stat_hot_file(p_hot_cold_file_global,p_file_stat)){
					clear_file_stat_in_file_stat_hot_head_list(p_file_stat);
					set_file_stat_in_file_stat_temp_head_list(p_file_stat);
					if(is_mmap_file_stat_large_file(p_hot_cold_file_global,p_file_stat)){//大文件
						list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_temp_large_file_head);
					}
					else{//普通文件
						list_move(&p_file_stat->hot_cold_file_list,&p_hot_cold_file_global->mmap_file_stat_temp_head);
					}
					p_hot_cold_file_global->hot_mmap_file_stat_count --;
					file_stat_change = 1;
					if(shrink_page_printk_open1)
						printk("1:%s file_stat:0x%llx status:0x%llx  hot to temp file\n",__func__,(u64)p_file_stat,(u64)p_file_stat->file_stat_status);
				}
			}
		}

		/*file_stat未发生变化，先移动到file_stat_list临时链表。如果此时global mmap_file_stat_mapcount_head链表没有file_stat了，
		  则p_file_stat_temp指向链表头，下次循环直接break跳出*/
		if(0 == file_stat_change)
			list_move(&p_file_stat->hot_cold_file_list,&file_stat_list);

		//超出扫描的file_area上限，break
		if(scan_file_area_count > scan_file_area_max){
			break;
		}
	}

	//如果file_stat_list临时链表还有file_stat，则把这些file_stat移动到global mmap_file_stat_hot_head链表头，下轮循环就能从链表尾巴扫描还没有扫描的file_stat了
	if(!list_empty(&file_stat_list)){
		list_splice(&file_stat_list,&p_hot_cold_file_global->mmap_file_stat_hot_head);
	}
	return scan_file_area_count;
}
static int walk_throuth_all_mmap_file_area(struct hot_cold_file_global *p_hot_cold_file_global)
{
	int ret;
	unsigned int scan_file_area_max,scan_file_stat_max;
	if(shrink_page_printk_open)
		printk("%s mmap_file_stat_count:%d mapcount_mmap_file_stat_count:%d hot_mmap_file_stat_count:%d\n",__func__,p_hot_cold_file_global->mmap_file_stat_count,p_hot_cold_file_global->mapcount_mmap_file_stat_count,p_hot_cold_file_global->hot_mmap_file_stat_count);

	//扫描global mmap_file_stat_uninit_head链表上的file_stat
	ret = scan_uninit_file_stat(p_hot_cold_file_global,&p_hot_cold_file_global->mmap_file_stat_uninit_head,512);
	if(ret < 0)
		return ret;

	//扫描大文件file_area
	scan_file_stat_max = 16;
	scan_file_area_max = 256;
	ret = get_file_area_from_mmap_file_stat_list(p_hot_cold_file_global,scan_file_area_max,scan_file_stat_max,&p_hot_cold_file_global->mmap_file_stat_temp_large_file_head);
	if(ret < 0)
		return ret;

	//扫描小文件file_area
	scan_file_stat_max = 32;
	scan_file_area_max = 128;
	ret = get_file_area_from_mmap_file_stat_list(p_hot_cold_file_global,scan_file_area_max,scan_file_stat_max,&p_hot_cold_file_global->mmap_file_stat_temp_head);
	if(ret < 0)
		return ret;

	scan_file_area_max = 32;
	//扫描热文件的file_area
	ret = scan_mmap_hot_file_stat(p_hot_cold_file_global,scan_file_area_max);
	if(ret < 0)
		return ret;

	scan_file_area_max = 32;
	//扫描mapcount文件的file_area
	ret = scan_mmap_mapcount_file_stat(p_hot_cold_file_global,scan_file_area_max);

	return ret;
}
int add_mmap_file_stat_to_list(struct file *file)
{
	int ret = 0;
	struct file_stat *p_file_stat;
	struct address_space *mapping = file->f_mapping;

	spin_lock(&hot_cold_file_global_info.mmap_file_global_lock);
	/*1:如果两个进程同时访问一个文件，同时执行到这里，需要加锁。第1个进程加锁成功后，分配file_stat并赋值给
	  mapping->rh_reserved1，第2个进程获取锁后执行到这里mapping->rh_reserved1就会成立
      2:异步内存回收功能禁止了*/
	if(mapping->rh_reserved1 || test_bit(ASYNC_MEMORY_RECLAIM_ENABLE,&async_memory_reclaim_status) == 0){
		spin_unlock(&hot_cold_file_global_info.mmap_file_global_lock);
		goto out;  
	}

	p_file_stat = kmem_cache_alloc(hot_cold_file_global_info.file_stat_cachep,GFP_ATOMIC);
	if (!p_file_stat) {
		spin_unlock(&hot_cold_file_global_info.mmap_file_global_lock);
		printk("%s file_stat alloc fail\n",__func__);
		ret =  -ENOMEM;
		goto out;
	}
	//设置file_stat的in mmap文件状态
	hot_cold_file_global_info.mmap_file_stat_count++;
	memset(p_file_stat,0,sizeof(struct file_stat));
	//设置文件是mmap文件状态，有些mmap文件可能还会被读写，要与cache文件互斥，要么是cache文件要么是mmap文件，不能两者都是 
	set_file_stat_in_mmap_file(p_file_stat);
	INIT_LIST_HEAD(&p_file_stat->file_area_hot);
	INIT_LIST_HEAD(&p_file_stat->file_area_temp);
	INIT_LIST_HEAD(&p_file_stat->file_area_free_temp);
	INIT_LIST_HEAD(&p_file_stat->file_area_free);
	INIT_LIST_HEAD(&p_file_stat->file_area_refault);
	//file_area对应的page的pagecount大于0的，则把file_area移动到该链表
	INIT_LIST_HEAD(&p_file_stat->file_area_mapcount);

	//mapping->file_stat记录该文件绑定的file_stat结构，将来判定是否对该文件分配了file_stat
	mapping->rh_reserved1 = (unsigned long)p_file_stat;
	p_file_stat->mapping = mapping;
	/*现在把新的file_stat移动到gloabl  mmap_file_stat_uninit_head了，并且不设置状态图，目前没必要设置状态。
	 *遍历完一次page后才会移动到temp链表。*/
#if 0
	/*新分配的file_stat必须设置in_file_stat_temp_head_list链表。这个设置file_stat状态的操作必须放到 把file_stat添加到
	 *tmep链表前边，还要加内存屏障。否则会出现一种极端情况，异步内存回收线程从temp链表遍历到这个file_stat，
	 *但是file_stat还没有设置为in_temp_list状态。这样有问题会触发panic。因为mmap文件异步内存回收线程，
	 *从temp链表遍历file_stat没有mmap_file_global_lock加锁，所以与这里存在并发操作。而针对cache文件，异步内存回收线程
	 *从global temp链表遍历file_stat，全程global_lock加锁，不会跟向global temp链表添加file_stat存在方法，但最好改造一下*/
	set_file_stat_in_file_stat_temp_head_list(p_file_stat);
	smp_wmb();
#endif	
	//把针对该文件分配的file_stat结构添加到hot_cold_file_global_info的mmap_file_stat_uninit_head链表
	list_add(&p_file_stat->hot_cold_file_list,&hot_cold_file_global_info.mmap_file_stat_uninit_head);

	/*新分配的file_stat必须设置in_file_stat_temp_head_list链表。注意，现在新分配的file_stat是先添加到global mmap_file_stat_uninit_head
	 *链表，而不是添加到global temp链表，因此此时file_stat并没有设置in_file_stat_temp_head_list属性。这点很关键，!!!!!!!!!!!!!!!!!!!!!*/

	//set_file_stat_in_file_stat_temp_head_list(p_file_stat);

	//spin_lock_init(&p_file_stat->file_stat_lock); mmap文件不用 file_stat->file_stat_lock 锁

	spin_unlock(&hot_cold_file_global_info.mmap_file_global_lock);
	strncpy(p_file_stat->file_name,file->f_path.dentry->d_iname,MMAP_FILE_NAME_LEN-1);
	p_file_stat->file_name[MMAP_FILE_NAME_LEN-1] = 0;
	if(shrink_page_printk_open)
		printk("%s file_stat:0x%llx %s\n",__func__,(u64)p_file_stat,file->f_path.dentry->d_iname);

out:
	return ret;
}
static void mmap_file_handler_post(struct kprobe *p, struct pt_regs *regs,
		unsigned long flags)
{
	struct file *file = (struct file *)(regs->di);
	if(file && file->f_mapping && (0 == file->f_mapping->rh_reserved1)){
		//if(strncmp(file->f_path.dentry->d_iname,"kern",4) == 0)
		add_mmap_file_stat_to_list(file);
	}
}
/***以上代码是针对mmap文件的*********************************************************************************************************/
/***以上代码是针对mmap文件的*********************************************************************************************************/
/***以上代码是针对mmap文件的*********************************************************************************************************/


static int __init async_memory_reclaime_for_cold_file_area_init(void)
{
	int ret;
	//kp_mark_page_accessed.post_handler = mark_page_accessed_handler_post;
	
#ifdef CONFIG_ENABLE_KPROBE
	/*ret = register_kprobe(&kp_mark_page_accessed);
	if (ret < 0) {
		pr_err("kp_mark_page_accessed register_kprobe failed, returned %d\n", ret);
		goto err;
	}*/
	kp_read_cache_func.post_handler = mark_page_accessed_handler_post;
	ret = register_kprobe(&kp_read_cache_func);
	if (ret < 0) {
		kp_read_cache_func.post_handler = NULL;
		pr_err("kp_read_cache_func register_kprobe failed, returned %d\n", ret);
		goto err;
	}
	kp_write_cache_func.post_handler = mark_page_accessed_handler_post;
	ret = register_kprobe(&kp_write_cache_func);
	if (ret < 0) {
		kp_write_cache_func.post_handler = NULL;
		pr_err("kp_write_cache_func register_kprobe failed, returned %d\n", ret);
		goto err;
	}
#endif
	kp__destroy_inode.post_handler = __destroy_inode_handler_post;
	ret = register_kprobe(&kp__destroy_inode); 
	if (ret < 0) {
		kp__destroy_inode.post_handler = NULL;
		pr_err("kp__destroy_inode register_kprobe failed, returned %d\n", ret);
		goto err;
	}

	/****针对mmap file*******************/
	kp__ext4_file_mmap.post_handler = mmap_file_handler_post;
	ret = register_kprobe(&kp__ext4_file_mmap); 
	if (ret < 0) {
		kp__ext4_file_mmap.post_handler = NULL;
		pr_err("kp__ext4_file_mmap register_kprobe failed, returned %d\n", ret);
		//goto err;
	}
	kp__xfs_file_mmap.post_handler = mmap_file_handler_post;
	ret = register_kprobe(&kp__xfs_file_mmap); 
	if (ret < 0) {
		kp__xfs_file_mmap.post_handler = NULL;
		pr_err("kp__xfs_file_mmap register_kprobe failed, returned %d\n", ret);
		//goto err;
	}
    
	ret = hot_cold_file_init();
	if(ret < 0){
		goto err;
	}
	ret = hot_cold_file_proc_init(&hot_cold_file_global_info);
	if(ret < 0){
		goto err;
	}
	//只有编译成Ko,才默认启动异步内存回收。如果编译进内核，默认不启动，出现过编译进内核，启动时ext4文件系统修复，结果因这个异步内存回收启动了，阻塞较长时间
#ifdef CONFIG_ENABLE_KPROBE	
	//防止重排序,set_bit不能保证reorder
	smp_mb();
	/*驱动初始化成功再使能该功能，否则可能前边各种global、file_stat链表都还没初始化，但是先有kprpbe初始化成功，就会执行到hot_file_update_file_status
	 *函数，但此时是因为global、file_stat链表都还没初始化，就可能会crash，这是个隐藏很深的bug!!!!!!!!!*/
	set_bit(ASYNC_MEMORY_RECLAIM_ENABLE, &async_memory_reclaim_status);
#endif	
	return 0;
err:
#ifdef CONFIG_ENABLE_KPROBE	
	/*if(kp_mark_page_accessed.post_handler)
		unregister_kprobe(&kp_mark_page_accessed);*/
	if(kp_read_cache_func.post_handler)
		unregister_kprobe(&kp_read_cache_func);
	if(kp_write_cache_func.post_handler)
		unregister_kprobe(&kp_write_cache_func);
#endif

	if(kp__destroy_inode.post_handler)
		unregister_kprobe(&kp__destroy_inode);

	/****针对mmap file*******************/
	if(kp__ext4_file_mmap.post_handler)
		unregister_kprobe(&kp__ext4_file_mmap);
	if(kp__xfs_file_mmap.post_handler)
		unregister_kprobe(&kp__xfs_file_mmap);

	if(hot_cold_file_global_info.hot_cold_file_thead)
		kthread_stop(hot_cold_file_global_info.hot_cold_file_thead);

    if(hot_cold_file_global_info.hot_cold_file_proc_root)
	    hot_cold_file_proc_exit(&hot_cold_file_global_info);
	return ret;
}
static void __exit async_memory_reclaime_for_cold_file_area_exit(void)
{ 
	//这里是重点，先等异步内存回收线程结束运行，就不会再使用任何的file_stat了，此时可以放心执行下边的cold_file_delete_all_file_stat()释放所有文件的file_stat
	kthread_stop(hot_cold_file_global_info.hot_cold_file_thead);

	//为使用 clear_bit_unlock()把async_memory_reclaim_status清0，这样使用async_memory_reclaim_status的地方不用再smp_rmb获取最的async_memory_reclaim_status值0
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
    
	/*如果有进程正在add_mmap_file_stat_to_list()加锁mmap_file_global_lock，然后向global mmap_file_stat_temp_head链表添加file_stat。
	 * 那先等待这个进程释放锁。这里的无锁的并发设计
	 *1:该函数
	    1.1：clear_bit_unlock 禁止异步内存回收
	    1.2：while(spin_is_locked(&hot_cold_file_global_info.mmap_file_global_lock)) msleep(1); 如果global mmap_file_global_lock加锁了就休眠
		1.3：遍历global mmap_file_stat_temp_head链表上的file_stat并释放掉
	  2:add_mmap_file_stat_to_list()函数 
	    2.1：加锁global mmap_file_global_lock
	    2.2：if(异步内存回收禁止了) return;
		2.3：global mmap_file_stat_temp_head链表添加file_stat

	  两个并发过程是1.1和2.1两个cpu同时跑:
	  1：如果2.1先跑了，因为2.1加锁了，1.2就只能休眠等待释放锁。后续再有进程执行add_mmap_file_stat_to_list()
	     ，因为异步内存回收禁止了，2.2直接return了，不会再向global mmap_file_stat_temp_head链表上的添加file_stat。
	     总之，1.3始终可以放心遍历global mmap_file_stat_temp_head链表上的file_stat并释放掉
	  2：如果1.1先跑了，2.2 if(异步内存回收禁止了)成立，直接return，不会再向global mmap_file_stat_temp_head链表上的添加file_stat。
	     1.3也可以放心遍历global mmap_file_stat_temp_head链表上的file_stat并释放掉

		 但是有个问题，1.1 clear_bit_unlock 禁止异步内存回收，执行后可以保证所有cpu都收到最新的async_memory_reclaim_status数据。
		 2.1 加锁global mmap_file_global_lock执行后，可以保证所有的cpu都收到最新的mmap_file_global_lock锁是上锁的数据吗??????????
		 这是个问题????????????????????????????????????????不行在add_mmap_file_stat_to_list函数也有原子变量加1减1防护并发吧
	 */
	while(spin_is_locked(&hot_cold_file_global_info.mmap_file_global_lock)){
	    msleep(1);
	}
	
	//释放所有的file_stat及其file_area
	cold_file_delete_all_file_stat(&hot_cold_file_global_info);
#ifdef CONFIG_ENABLE_KPROBE	
	//unregister_kprobe(&kp_mark_page_accessed);
	unregister_kprobe(&kp_read_cache_func);
	unregister_kprobe(&kp_write_cache_func);
#endif	
	unregister_kprobe(&kp__destroy_inode);
	/*****mmap文件****************/
	unregister_kprobe(&kp__ext4_file_mmap);
	unregister_kprobe(&kp__xfs_file_mmap);

	kmem_cache_destroy(hot_cold_file_global_info.file_stat_cachep);
	kmem_cache_destroy(hot_cold_file_global_info.file_area_cachep);
	kmem_cache_destroy(hot_cold_file_global_info.hot_cold_file_area_tree_node_cachep);
	hot_cold_file_proc_exit(&hot_cold_file_global_info);
}
module_init(async_memory_reclaime_for_cold_file_area_init);
module_exit(async_memory_reclaime_for_cold_file_area_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hujunpeng : dongzhiyan_linux@163.com");
