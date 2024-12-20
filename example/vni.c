#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/ctype.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/kernel.h>

#include <linux/timekeeping.h>

// netlink
#define NETLINK_TEST 30
#define MSG_LEN 125
#define USER_PORT 100

// netlink
struct sock *nlsk = NULL;

// vni-timer
struct timer_list vni_timer;
static int cnt = 0;
// struct timeval oldtv;

// netdev
static struct net_device *vni_dev = NULL;

// VNI结构体
static struct VNI_ethhdr
{
    // 学号字段信息：1204
    unsigned char student[4];
    // VNI分组 
    unsigned short vnid;
};

// VNI统计收发统计信息
static struct VNI_states
{
    // 发送分组统计
    uint16_t vni_tx_packets;
    // 接收分组统计
    uint16_t vni_rx_packets;
};

struct VNI_states vni_states;

// netlink消息发送统计、
static int nl_cnt;

// 以太网数据包
unsigned char eth_rcv[256];

// mac地址信息
unsigned char smac[6] = {0x04, 0x33, 0xc2, 0x88, 0xd9, 0x4d};
unsigned char dmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


int send_usrmsg(char *pbuf, uint16_t len)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;

    int ret;

    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if (!nl_skb)
    {
        printk("netlink alloc failure\n");
        return -1;
    }

    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_TEST, len, 0);
    if (nlh == NULL)
    {
        printk("nlmsg_put failaure \n");
        nlmsg_free(nl_skb);
        return -1;
    }

    /* 拷贝数据发送 */
    memcpy(nlmsg_data(nlh), pbuf, len);
    ret = netlink_unicast(nlsk, nl_skb, USER_PORT, 1);

    return ret;
}


static void timer_handle(struct timer_list *tls)
{
    unsigned char buf[128];
    // 每10s统计一次VNI数据包收发次数并发送给用户态程序
    if (++cnt >= 5)
    {
        // 发送消息数增加
        nl_cnt++;
        sprintf(buf, "%4d %4d %4d", nl_cnt, vni_states.vni_tx_packets,
                vni_states.vni_rx_packets);

        send_usrmsg(buf, strlen(buf));
        cnt = 0;
    }
    mod_timer(&vni_timer, jiffies + 2 * HZ);
}


static void VNI_Reader(const unsigned char *buf)
{
    int i = 0;
    struct sk_buff *new_skb;
    // 网络设备
    struct net_device *dev = NULL;
    // IP头
    struct iphdr *iphdr = NULL;

    // 以太网头
    struct ethhdr *eth = NULL;
    // 数据包数据
    unsigned char data[51];
    // 关闭打印调试信息，避免不必要的运行负担
    // 打印数据包头部信息
    //  printk("VNI-process");
    //  for(i=0; i< 40; i++){
    //  printk("%02x-",buf[i]);
    //  if ((i + 1) % 16 == 0){
    //  printk(" ");
    //  }
    //  }
    //  构造一个sk_buff
    new_skb = dev_alloc_skb(128);
    skb_reserve(new_skb, 80); /* align IP on 16B boundary */
    new_skb->len = 0;

    // 数据包内容14+6+20
    memcpy(data, buf + 40, 50);
    skb_push(new_skb, 50);
    memcpy(new_skb->data, data, 50);

    // 数据包IP头
    iphdr = skb_push(new_skb, 20);
    skb_reset_network_header(new_skb);

    memcpy(new_skb->data, buf + 20, 20);

    iphdr->version = 4;
    iphdr->ihl = 5;
    iphdr->tos = 0;
    iphdr->tot_len = htons(0x46);

    // 数据包ethernet头
    eth = skb_push(new_skb, 14);
    skb_reset_mac_header(new_skb);

    memcpy(eth->h_source, buf + 6, 6);
    memcpy(eth->h_dest, buf, 6);
    eth->h_proto = htons(0x0800);
    printk("4");
    /* Write metadata, and then pass to the receive level */
    new_skb->dev = dev;
    new_skb->protocol = htons(0x0800);
    new_skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */

    dev = dev_get_by_name(&init_net, "vni0");
    new_skb->dev = dev;
    // 接收分组记录
    vni_states.vni_rx_packets++;
    // 提交数据至VNI0口
    netif_rx(new_skb);
}


static void netlink_rcv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    unsigned char *umsg = NULL;

    int i = 0;
    if (skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        umsg = NLMSG_DATA(nlh);
        if (umsg)
        {
            // 数据包处理，去掉VNI头部
            VNI_Reader(eth_rcv);
        }
    }
}


static unsigned int
VNI_HookLocalOUT(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
    int nret = 1;
    struct net_device *dev = NULL;
    unsigned short type = 0xf4f0;
    unsigned char *p = NULL;

    unsigned char iprotocol, ipttl;
    unsigned short ipid, iptotlen;
    unsigned int ipsaddr, ipdaddr;

    struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);

    struct iphdr *iph = ip_hdr(nskb);

    struct VNI_ethhdr *vni;

    struct ethhdr *eth;

    ipsaddr = iph->saddr;
    ipdaddr = iph->daddr;
    iprotocol = iph->protocol;
    printk("ip:%02x", iprotocol);

    ipid = iph->id;
    printk("id:%02x", ipid);

    iptotlen = iph->tot_len;
    printk("len:%04x", iptotlen);

    ipttl = iph->ttl;
    printk("ipsaddr:%08x,daddr:%08x", ipsaddr, ipdaddr);

    if (iph->protocol != IPPROTO_ICMP)
    {
        // not icmp
        printk("not icmp");
        return NF_ACCEPT;
    }
    /*添加VNI分组*/
    printk("LOCAL OUT");

    if (skb_cow_head(skb, 6) < 0)
    {
        printk("fail");
    }

    eth = (struct ethhdr *)skb_mac_header(skb);
    iph = (struct iphdr *)skb_network_header(skb);
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    skb_reserve(skb, 12);
    skb_pull(skb, 34);

    // 添加IP头部

    iph = (struct iphdr *)skb_push(skb, 20);
    skb_reset_network_header(skb);

    iph->version = 4;
    iph->protocol = iprotocol;
    iph->tos = 0;
    iph->tot_len =
        iph->frag_off = 0;
    iph->id = ipid;
    iph->ttl = ipttl;
    iph->tot_len = iptotlen;
    iph->saddr = ipsaddr;
    iph->daddr = ipdaddr;
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    // 添加VNI头部
    p = skb_push(skb, 6);
    vni = (struct VNI_ethhdr *)p;
    // memmove(skb->data,skb->data+6, ETH_HLEN);

    vni->student[0] = 0x01;
    vni->student[1] = 0x02;
    vni->student[2] = 0x04;
    vni->student[3] = 0x00;
    vni->vnid = htons(0xABCD);

    eth = (struct ethhdr *)skb_push(skb, sizeof(struct ethhdr));
    skb_reset_mac_header(skb);

    memcpy(eth->h_dest, dmac, 6);
    memcpy(eth->h_source, smac, 6);
    eth->h_proto = __constant_htons(type);

    // skb->mac_header = skb->data;
    dev = dev_get_by_name(&init_net, "wlp0s20f3");
    skb->dev = dev;

    if (dev_queue_xmit(skb) < 0)
    {
        printk("error");
        goto out;
    }

    // 发送分组统计
    vni_states.vni_tx_packets++;
    nret = 0;

out:
    if (nret != 0 && skb != NULL)
    {
        kfree_skb(skb);
        dev_put(dev);
    }

    return NF_STOLEN;
}

static struct nf_hook_ops VNI_hooks[] = {
    // netfilter-iptables IP层HOOK
    {
        .hook = VNI_HookLocalOUT,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FILTER - 1,
    }};

struct netlink_kernel_cfg cfg = {
    .input = netlink_rcv_msg, /* set recv callback */
};

static const struct net_device_ops vni_dev_ops = {
    // .ndo_start_xmit = ,
};

static int __init VNI_init(void)
{
    nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if (nlsk == NULL)
    {
        printk("netlink_kernel_create error !\n");
        return -1;
    }
    // 设置一个定时器，每隔2s触发一次，触发时调用timer_handle
    timer_setup(&vni_timer, timer_handle, 0);
    vni_timer.expires = jiffies + 2 * HZ;
    add_timer(&vni_timer);

    // 注册vni0
    vni_dev = alloc_netdev(0, "vni%d", 'e', ether_setup);
    vni_dev->netdev_ops = &vni_dev_ops;
    vni_dev->flags |= IFF_NOARP;
    vni_dev->features |= 0x4;
    register_netdev(vni_dev);

    // 注册netfilter hook函数
    nf_register_net_hooks(&init_net, VNI_hooks, ARRAY_SIZE(VNI_hooks));

    return 0;
}

static void __exit VNI_exit(void)
{
    nf_unregister_net_hooks(&init_net, VNI_hooks, ARRAY_SIZE(VNI_hooks));

    if (nlsk)
    {
        netlink_kernel_release(nlsk);
        nlsk = NULL;
    }

    del_timer(&vni_timer);

    unregister_netdev(vni_dev);
    free_netdev(vni_dev);
    printk("vni_exit!\n");
}

module_init(VNI_init);
module_exit(VNI_exit);

MODULE_LICENSE("GPL V2");
