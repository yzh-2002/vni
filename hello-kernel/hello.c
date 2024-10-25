#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");

static int hello_init(void){
    printk(KERN_ALERT "Hello Kernel!");
    return 0;
}

static void hello_exit(void){
    printk(KERN_ALERT "Googbye Kernel/n");
}

module_init(hello_init);
module_exit(hello_exit);