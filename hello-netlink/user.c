#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define NETLINK_TEST 30
#define PAYLOAD_MAX_SIZE 1024

struct test_nlmsg
{
    struct nlmsghdr nlh;
    uint8_t msg_data[PAYLOAD_MAX_SIZE];
};

int netlink_socket = -1;
struct sockaddr_nl *user_addr = NULL;
struct sockaddr_nl *kernel_addr = NULL;
struct test_nlmsg *msg = NULL;

int main()
{
    // 创建netlink socket
    netlink_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if (netlink_socket == -1)
    {
        perror("Socket create failed!\n");
        return -1;
    }
    // 填充数据包头信息
    msg = (struct test_nlmsg *)malloc(sizeof(struct test_nlmsg));
    if (msg == NULL)
    {
        perror("msg malloc failed!\n");
        close(netlink_socket);
        return -1;
    }
    memset(msg, 0, sizeof(struct test_nlmsg));
    msg->nlh.nlmsg_len = sizeof(struct test_nlmsg);
    // 内核不会像UDP一样根据socket设置的源，目的地址去构造数据包的消息头，故此处需要指定
    msg->nlh.nlmsg_pid = getpid(); // 发送者的pid
    msg->nlh.nlmsg_flags = 0;

    // 填充接收端，发送端的socket地址信息
    user_addr = (struct sockaddr_nl *)malloc(sizeof(struct sockaddr_nl));
    if (user_addr == NULL)
    {
        perror("user addr malloc failed!\n");
        close(netlink_socket);
        free(msg);
        return -1;
    }
    memset(user_addr, 0, sizeof(struct sockaddr_nl));
    user_addr->nl_family = AF_NETLINK;
    user_addr->nl_pid = getpid();
    user_addr->nl_groups = 0; // 不广播
    kernel_addr = (struct sockaddr_nl *)malloc(sizeof(struct sockaddr_nl));
    if (kernel_addr == NULL)
    {
        perror("kernel addr malloc failed!\n");
        close(netlink_socket);
        free(msg);
        free(user_addr);
        return -1;
    }
    memset(kernel_addr, 0, sizeof(struct sockaddr_nl));
    kernel_addr->nl_family = AF_NETLINK;
    kernel_addr->nl_pid = 0; // 0代表内核pid
    kernel_addr->nl_groups = 0;

    int ret = bind(netlink_socket, (struct sockaddr *)user_addr, sizeof(struct sockaddr_nl));
    if (ret == -1)
    {
        perror("bind failed!\n");
        close(netlink_socket);
        free(msg);
        free(user_addr);
        free(kernel_addr);
        return -1;
    }
    // 填写数据包信息
    char *buf = "Hello netlink!";
    memset(&(msg->msg_data), 0, PAYLOAD_MAX_SIZE);
    strcpy(msg->msg_data, buf);

    // 发送消息
    printf("Send message to kernel\n");
    // 存在发送缓冲区，当缓冲区满时，sendto会阻塞直到缓冲区中有足够的空间接受数据
    ssize_t send_len = sendto(netlink_socket, msg, msg->nlh.nlmsg_len, 0,
                              (struct sockaddr *)kernel_addr, sizeof(struct sockaddr_nl));
    if (send_len == -1)
    {
        perror("send failed!\n");
        close(netlink_socket);
        free(msg);
        free(user_addr);
        free(kernel_addr);
        return -1;
    }

    // 接收消息
    struct test_nlmsg recv_msg;
    socklen_t addr_len = sizeof(struct sockaddr_nl);
    // Why? 为什么recvfrom最后一个参数是指针，而sendto最后一个参数不是呢？
    // 原因在于recvfrom需要根据实际接受到的地址信息调整addr_len的大小，故传入指针

    // 默认阻塞，其会等待直到有数据可供接收
    ssize_t recv_len = recvfrom(netlink_socket, &recv_msg, sizeof(struct test_nlmsg), 0,
                                (struct sockaddr *)kernel_addr, &addr_len);
    if (recv_len == -1)
    {
        perror("recv failed!\n");
        close(netlink_socket);
        free(msg);
        free(user_addr);
        free(kernel_addr);
        return -1;
    }
    printf("Recv from kernel: %s\n", recv_msg.msg_data);
    // 释放socket资源
    close(netlink_socket);
    free(msg);
    free(user_addr);
    free(kernel_addr);
    return 0;
}