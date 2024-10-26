#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

#define NETLINK_TEST 30
#define PAYLOAD_MAX_SIZE 1024

struct test_nlmsg
{
    struct nlmsghdr nlh;
    uint8_t msg_data[PAYLOAD_MAX_SIZE];
};

struct sock *netlink_socket = NULL;
pid_t pid = -1;

// 收到信息的回调函数
static void netlink_callback(struct sk_buff *skb)
{
    // 获取消息
    struct test_nlmsg *msg = (struct test_nlmsg *)skb->data;
    pid = msg->nlh.nlmsg_pid; // 用户空间中发送进程的pid
    printk("Netlink info get!\n");
    // 构建返回的消息体
    // 使用该函数分配的内存空间会在 nlmsg_unicast 后自动释放
    struct sk_buff *skb_out = nlmsg_new(PAYLOAD_MAX_SIZE, GFP_KERNEL);
    struct nlmsghdr *nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, PAYLOAD_MAX_SIZE, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    // 将用户发送的消息复制到Netlink消息的有效负载中，也即原封不动返回
    strcpy((char *)NLMSG_DATA(nlh), msg->msg_data);
    nlmsg_unicast(netlink_socket, skb_out, pid);
}

static int test_socket_create(void)
{
    // 设置内核netlink socket所需的配置参数结构体（主要是设置回调函数）
    struct netlink_kernel_cfg cfg =
        {
            .input = netlink_callback,
        };
    // 创建netlink socket
    netlink_socket = (struct sock *)netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if (netlink_socket == NULL)
    {
        printk("Socket Create Failed!\n");
        return -1;
    }
    printk("Socket Create Succeed!\n");
    return 0;
}

static void test_socket_close(void)
{
    // 释放socket资源
    if (netlink_socket)
    {
        netlink_kernel_release(netlink_socket);
        netlink_socket = NULL;
    }
    printk("Socket Release Succeed!\n");
}
module_init(test_socket_create);
module_exit(test_socket_close);