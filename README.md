linux内核内存回收的另一个思路探索：识别出冷热文件的冷热区域，更精准的回收冷page
-------------------------------------
【优势】

1：不用编译内核，直接编译成内核ko(主要用到struct address_space结构最后的预留字段)，可以单独作为一个pagecache内存回收工具

2: 读写文件产生的pagecache，并不是所有的page都频繁访问，实测总有一些冷page。因此把一个文件的cache分成若干个内存page单元，每个内存page单元由4或8个连续page组成。有些内存page单元的page频繁访问，称为热区域。有些内存page单元的page长时间不被访问，称为冷区域，内存回收时正是回收这些冷区域的page，回收效率比较高。

3：识别出消耗pagecache很多的文件，内存回收先扫描这些文件，尤其是消耗pagecache多但不经常访问的冷文件。这样1次内存回收可以回收到很多的冷page，内存回收效率比较高

4：每个内存回收周期，被访问的page对应数据结构移入自定义的内存回收链表头，这样链表尾对应的都是冷page。内存回收时先从链表尾扫描这些冷page，内存回收效率比较高

5：针对内存回收后很快又被访问的page，对应数据结构存入refault链表，内存回收一定时间内不再扫描，特别照顾


-------------------------------------
【基本实现思路】

1:为每个文件分配一个file_stat数据结构，每个内存page单元分配一个file_area数据结构，对应4或8个连续page。同时创建一个内存回收内核线程，该线程每个内存回收周期(默认1min)运行一次，令全局内存回收计数加1。然后扫描每个文件的pagecache，把长时间不被访问的冷内存page单元的page回收掉，当然具体的回收策略很复杂。

2：在每个文件page被访问而执行到mark_page_accessed()函数时，累加该page对应 内存page单元对应数据结构file_area的访问计数，并把全局内存回收周期数赋值给该file_area的最新内存回收周期数。如果file_area对应的page长时间不被访问，则file_area的最新内存回收周期数就很小，则被判定是冷file_area，其对应的page被判定为冷page，内存回收就回收这些page。这与多代lru内存回收方案里的每个page的age概念比较像，但有很大不同。

3：怎么判断冷热文件、内存回收时优先扫描消耗pagecache多但不经常访问的冷文件、refault page的判断等等，比较复杂，这里不再介绍


-------------------------------------
【使用方法】

红帽8/9系列，centos8(内核版本4.18.0-240)、rocky9(内核版本5.14.0-284.11.1)已经适配，可直接make编译成ko，红帽7系列内核不支持

其他内核发行版

1：安卓手机开源内核(一加)，需要把本源码里 mapping->rh_reserved1 改成 mapping->android_kabi_reserved1，https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550

2: 腾讯opencloud开源内核，需要把本源码里 mapping->rh_reserved1 改成 mapping->kabi_reserved1，https://github.com/OpenCloudOS/OpenCloudOS-Kernel-Stream

3: 阿里龙蜥开源内核，需要把本源码里 mapping->rh_reserved1 改成 mapping->ck_reserved1，https://gitee.com/anolis/cloud-kernel


说明：可能不同的内核编译该ko时，会遇到内核版本不同内存回收有关函数有差异而导致编译失败，此时需要一些修改。后期尽快多适配不同的内核，目前仅适配了红帽的内核。
