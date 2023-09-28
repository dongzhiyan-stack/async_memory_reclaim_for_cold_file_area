linux内核异步内存回收的另一个思路探索：识别出冷热文件的冷热区域，更精准的回收冷page
-------------------------------------

【基本设计思路】

1：内存回收的单位是一个个文件，再把文件的pagecache分成一个个小区域(或者叫小单元)，一个区域由4个索引连续的文件页page组成。比如把索引是0到3的文件页page组成一个小区域，索引是4到7的文件页page再组成一个小区域，其他区域类推。一个区域内的文件页page冷热属性接近，每个区域分配一个file_area结构，精确统计该区域内的page的访问频次。然后，提前判断出文件的pagecache哪些区域是进程频繁访问的(即热区域，该区域的文件页page频繁被读写)，哪些区域是进程很少访问的(即冷区域，该区域的文件页page很少被读写)。异步内存回收线程工作时，一个个遍历指定数目的文件，再把每个文件pagecache的冷区域找出来，最后回收掉冷区域对应的文件页page。

【方案优势】

1：不用修改编译内核，直接编译成内核ko(主要用到struct address_space结构最后的预留字段)，可以单独作为一个pagecache内存回收工具

2：系统总有一定数目的文件，产生的pagecache很多，但是大部分pagecache都很少访问，这种文件的pagecache中冷区域占比高(称为冷文件)。内存回收时优先找到这种文件，因为能从这种文件找到很多的冷区域，继而回收到很多的冷文件页page。内存回收效率很高!

3：有些文件的pagecache大部分都被频繁读写(称为热文件)，这种文件的pagecache中热区域占比很高。内存回收时尽量避开这种文件，不回收这种文件的文件页page，因为有较大概率会发生refault

4：针对内存回收后发生refault的文件页page，该文件页所在区域的数据结构将移入所属文件的refault链表，保证较长时间内不再回收该page，有效避免再次refault

5：每个内存回收周期，被访问的文件页page所在区域的数据结构将移动到的自定义的内存回收链表头(有一定策略，不是每次都移动)，这样链表尾对应的都是冷page。内存回收时先从链表尾扫描这些冷page，内存回收效率比较高



-------------------------------------
【方案详细设计】

查看文章 https://blog.csdn.net/hu1610552336/article/details/132331352

-------------------------------------
【使用方法】

红帽8/9系列，centos8(内核版本4.18.0-240)、rocky9(内核版本5.14.0-284.11.1)已经适配，可直接make编译成ko，红帽7系列内核不支持

其他内核发行版

1：安卓手机开源内核(一加)，需要把本源码里 mapping->rh_reserved1 改成 mapping->android_kabi_reserved1，https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550

2: 腾讯opencloud开源内核，需要把本源码里 mapping->rh_reserved1 改成 mapping->kabi_reserved1，https://github.com/OpenCloudOS/OpenCloudOS-Kernel-Stream

3: 阿里龙蜥开源内核，需要把本源码里 mapping->rh_reserved1 改成 mapping->ck_reserved1，https://gitee.com/anolis/cloud-kernel


说明：可能不同的内核编译该ko时，会遇到内核版本不同内存回收有关函数有差异而导致编译失败，此时需要一些修改。后期尽快多适配不同的内核，目前仅适配了红帽的内核。
