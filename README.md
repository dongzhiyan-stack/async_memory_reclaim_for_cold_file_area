linux内核内存回收的另一个思路探索：识别出冷热文件的冷热区域，更精准的回收冷page
-------------------------------------
【优势】

1：不用编译内核，直接编译成内核ko(主要用到struct address_space结构最后的预留字段)，可以单独作为一个pagecache内存回收工具

2：识别出消耗pagecache很多的文件，内存回收先扫描这些文件，尤其是消耗pagecache多但不经常访问的冷文件。这样1次内存回收可以回收到很多的冷page，内存回收效率比较高

3：每个内存回收周期，被访问的page对应数据结构移入自定义的内存回收链表头，这样链表尾对应的都是冷page。内存回收时先从链表尾扫描这些冷page，内存回收效率比较高

4：针对内存回收后很快又被访问的page，对应数据结构存入refault链表，内存回收一定时间内不再扫描，特别照顾

5：把4或8个连续page作为一个内存回收单元，既可以节省内存，内存回收效果也比较好


-------------------------------------
【基本实现思路】

1:为每个文件分配一个file_stat数据结构，每个内存回收单元分配一个file_area数据结构，对应4或8个连续page。同时创建一个内存回收内核线程，该线程每个内存回收周期(默认1min)运行一次，令全局内存回收计数加1，然后扫描每个文件的pagecache，扫描到冷page则回收，当然具体的回收策略很复杂。

2：在每个文件page被访问而执行到mark_page_accessed()函数时，累加该page对应 内存回收单元file_area的访问计数，并把全局内存回收周期数赋值给该file_area的最新内存回收周期数。如果file_area对应的page长时间不被访问，则file_area的最新内存回收周期数就很小，则被判定是冷file_area，其对应的page被判定为冷page，内存回收就回收这些page。这与多代lru内存回收方案里的每个page的age概念比较像，但有很大不同。

3：怎么判断冷热文件、内存回收时优先扫描消耗pagecache多但不经常访问的冷文件、refault page的判断等等，比较复杂，这里不再介绍


-------------------------------------
【使用方法】

红帽8/9系列内核可以make编译，比如centos8、centos9，红帽7系列内核不支持

其他内核发行版

1：安卓手机开源内核(一加)，需要把本源码里 mapping->rh_reserved1 改成 mapping->android_kabi_reserved1，https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550

2: 腾讯opencloud开源内核，需要把本源码里 mapping->rh_reserved1 改成 mapping->kabi_reserved1，https://github.com/OpenCloudOS/OpenCloudOS-Kernel-Stream

3: 阿里龙蜥开源内核，需要把本源码里 mapping->rh_reserved1 改成 mapping->ck_reserved1，https://gitee.com/anolis/cloud-kernel


说明：可能不同的内核具体编译该内核ko时，会遇到一些问题，此时需要一些修改。后期尽快多适配不同的内核，目前仅适配了红帽的内核。
