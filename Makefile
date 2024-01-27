obj-m := async_memory_reclaim.o
async_memory_reclaim-y = async_memory_reclaim_for_cold_file_area.o base.o
CROSS_COMPILE=''                                                                                                                                                                          

#KDIR := /lib/modules/4.18.0-240.el8.x86_64/build
KDIR := /lib/modules/$(shell uname -r)/build
all:   
	    make -C $(KDIR) M=$(PWD) modules 
clean: 
	    rm -f *.ko *.o *.mod.o *.mod.c .*.cmd *.symvers  Module*
