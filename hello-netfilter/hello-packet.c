#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");

// 以下宏定义在/usr/include/linux/netfilter_ipv4.h
// 内核空间使用需要手动定义
enum
{
    NF_IP_PRE_ROUTING,
    NF_IP_LOCAL_IN,
    NF_IP_FORWARD,
    NF_IP_LOCAL_OUT,
    NF_IP_POST_ROUTING,
    NF_IP_NUMHOOKS
};

static void dump_addr(unsigned char *iphdr)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        // IP数据包头 源目标地址在第12个字节处，占4个字节
        printk("%d", *(iphdr + 12 + i));
    }
    printk(" -> ");
    for (i = 0; i < 4; i++)
    {
        printk("%d", *(iphdr + 16 + i));
    }
    printk("\n");
}

unsigned int my_custom_hook(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    printk("Hello packet!");
    unsigned char *iphdr = skb_network_header(skb);
    if (iphdr)
    {
        // 输出IP数据包源地址和目的地址
        dump_addr(iphdr);
    }
    return NF_ACCEPT;
}

// 注册hook函数需要传入hook option结构
// 此处注册两个hook，故定义两个ho
static struct nf_hook_ops hello_hooks[] = {
    {
        // NF_IP_LOCAL_IN hook
        .hook = my_custom_hook,
        .hooknum = NF_IP_LOCAL_IN,
        .pf = PF_INET, // IPV4协议族
        .priority = NF_IP_PRI_FIRST,
    },
    {
        // NF_IP_LOCAL_OUT hook
        .hook = my_custom_hook,
        .hooknum = NF_IP_LOCAL_OUT,
        .pf = PF_INET, // IPV4协议族
        .priority = NF_IP_PRI_FIRST,
    }};

static int hello_init(void)
{
    printk(KERN_INFO "[+] Register Hello_Packet module!\n");
    nf_register_net_hooks(&init_net, hello_hooks, ARRAY_SIZE(hello_hooks));
    return 0;
}

static void hello_exit(void)
{
    nf_unregister_net_hooks(&init_net, hello_hooks, ARRAY_SIZE(hello_hooks));
    printk(KERN_INFO "Cleaning up Helllo_Packet module.\n");
}

module_init(hello_init);
module_exit(hello_exit);