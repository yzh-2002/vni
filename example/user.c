#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#define PROMISC 1

#define NETLINK_TEST 30
#define MSG_LEN 125
#define MAX_PLOAD 125

/*过滤条件*/
char filter_exp[] = "ether[12:2]=0xf4f0";

/*抓包设备名称*/
char *dev;

/*最大抓包长度 ：Ethernet 1500字节 + 以太网帧头部14字节 + 以太网帧尾部4字节*/
#define SNAP_LEN 1518

/*ethernet head are exactly 14 bytes*/
#define ETHERNET_HEAD_SIZE 14

/*ip头部字节数宏  取hlv低四位即头部长度*单位4bytes  然后强转为ip结构体*/
// #define IP_HEAD_SIZE(ipheader) ((ipheader->ip_hlv & 0x0f) * 4)
#define IP_HEAD_SIZE(packet) ((((struct ip *)(packet + ETHERNET_HEAD_SIZE))->ip_hlv & 0x0f) * 4)

/*ethernet address are 6 bytes*/
#define ETHERNET_ADDR_LEN 6
/*Ethernet HEADER*/

struct ethernet
{
    u_char ether_dhost[ETHERNET_ADDR_LEN];
    u_char ether_shost[ETHERNET_ADDR_LEN];
    u_short ether_type;
};

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    char msg[MSG_LEN];
} user_msg_info;

int skfd;
int ret;
user_msg_info u_info;
socklen_t len;
struct nlmsghdr *nlh = NULL;
struct sockaddr_nl saddr, daddr;

void ethernet_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,
                       const u_char *packet)
{
    unsigned char eth_skb[256];
    unsigned char *umsg = NULL;
    struct ethernet *ethheader;
    struct ip *ipptr;
    u_short protocol;
    u_int *id = (u_int *)arg;

    printf("---------------Device : %s------------------\n", dev);
    printf("---------------Filter: %s-------------------\n", filter_exp);
    printf("-----------------Analyze Info---------------\n");
    printf("Id: %d\n", ++(*id));
    printf("Packet length: %d\n", pcap_pkt->len);
    printf("Number of bytes: %d\n", pcap_pkt->caplen);

    int k;
    for (k = 0; k < 90; k++)
    {
        /*表示以16进制的格式输出整数类型的数值，
        输出域宽为2，右对齐，不足的用字符0替代*/
        printf(" %02x", packet[k]);
        if ((k + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n\n");

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    memset(nlh, 0, sizeof(struct nlmsghdr));

    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = saddr.nl_pid; // self port

    memcpy(eth_skb, packet, 90);

    for (k = 0; k < 90; k++)
    {
        /*表示以16进制的格式输出整数类型的数值，
        输出域宽为2，右对齐，不足的用字符0替代*/
        printf(" %02x", eth_skb[k]);
        if ((k + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    umsg = eth_skb;

    memcpy(NLMSG_DATA(nlh), eth_skb, 90);
    nlh->nlmsg_len = NLMSG_LENGTH(MAX_PLOAD);
    ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr,
                 sizeof(struct sockaddr_nl));
    if (!ret)
    {
        perror("sendto error\n");
        close(skfd);
        exit(-1);
    }

    printf("\nsend kernel:%s\n", umsg);

    ethheader = (struct ethernet *)packet;
    printf("\n---------------Data Link Layer-----------\n");

    printf("Mac Src Address: ");
    int i;
    for (i = 0; i < ETHERNET_ADDR_LEN; i++)
    {
        if (ETHERNET_ADDR_LEN - 1 == i)
        {
            printf("%02x\n", ethheader->ether_shost[i]);
        }
        else
        {
            printf("%02x:", ethheader->ether_shost[i]);
        }
    }

    printf("Mac Dst Address: ");
    int j;
    for (j = 0; j < ETHERNET_ADDR_LEN; j++)
    {
        if (ETHERNET_ADDR_LEN - 1 == j)
        {
            printf("%02x\n", ethheader->ether_dhost[j]);
        }
        else
        {
            printf("%02x:", ethheader->ether_dhost[j]);
        }
    }

    protocol = ntohs(ethheader->ether_type);

    printf("eth-proto:%04x\n", protocol);

    printf("---------------------Done--------------------\n\n\n");
}

int main(int argc, char **argv)
{

    char *umsg = "hello netlink!! this is from user\n";

    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr hdr;
    pcap_if_t *alldevs;

    struct bpf_program bpf_p;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    int nl_time;
    int rx_packets, tx_packets;
    unsigned char nl_data[16];
    unsigned char temp[4];

    /* 创建NETLINK socket */
    skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if (skfd == -1)
    {
        perror("create socket error\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK; // AF_NETLINK
    saddr.nl_pid = 100;           // 端口号(port ID)
    saddr.nl_groups = 0;
    if (bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        perror("bind() error\n");
        close(skfd);
        return -1;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel
    daddr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = saddr.nl_pid; // self port

    printf("send kernel:%s\n", umsg);

    /*find the device to capture packet*/
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        printf("no device !\n");
    }

    // 选择“wlp0s20f3”接口
    dev = "wlp0s20f3";
    printf("eth:%s\n", dev);
    /*open the device*/
    pcap = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
    if (pcap == NULL)
    {
        printf("open error!\n");
        return 0;
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        printf("Could not get netmask for device!\n");
        net = 0;
        mask = 0;
    }

    if (pcap_compile(pcap, &bpf_p, filter_exp, 0, net) == -1)
    {
        printf("Could not parse filter\n");
        return 0;
    }
    if (pcap_setfilter(pcap, &bpf_p) == -1)
    {
        printf("Could not install filter\n");
        return 0;
    }

    pid_t child_pid;
    /* 创建一个子进程 */
    child_pid = fork();

    if (child_pid == 0)
    {
        // 发送0xf4f0数据包
        int id = 0;
        printf("this is sniffer\n");
        // 无限捕获数据包直至出错
        // 每捕获一个数据包便调用ethernet_callback函数
        pcap_loop(pcap, -1, ethernet_callback, (u_char *)&id);

        pcap_close(pcap);
    }
    else
    {
        // 接收netlink 消息
        while (1)
        {
            memset(&u_info, 0, sizeof(u_info));
            len = sizeof(struct sockaddr_nl);
            ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0,
                           (struct sockaddr *)&daddr, &len);
            if (!ret)
            {
                perror("recv form kernel error\n");
                close(skfd);
                exit(-1);
            }
            // 打印VNI模块发送 or 接收的信息
            printf("from kernel:%s\n", u_info.msg);
            strcpy(nl_data, u_info.msg);

            // VNI模块运行时间 nltime*10=秒数
            strncpy(temp, nl_data, 4);
            nl_time = atoi(temp);

            // VNI模块发送分组
            strncpy(temp, nl_data + 5, 4);
            tx_packets = atoi(temp);

            // VNI模块接收分组
            strncpy(temp, nl_data + 10, 4);
            rx_packets = atoi(temp);

            printf("\n---------------VNI发送情况------------------\n");
            printf("\nvni tx:%d packets\n", tx_packets);
            printf("vni tx rate:%.2f pps\n", (float)(tx_packets * 1.0) / (10 * nl_time));
            printf("\n---------------VNI接收情况------------------\n");
            printf("\nvni rx:%d packets\n", rx_packets);
            printf("vni rx rate:%.2f pps\n", (float)(rx_packets * 1.0) / (10 * nl_time));
            sleep(5);
        }
        close(skfd);

        free((void *)nlh);
    }

    return 0;
}
