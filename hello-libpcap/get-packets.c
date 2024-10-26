#include <stdio.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <time.h>

void get_packet(
    __u_char *arg,
    const struct pcap_pkthdr *pkthdr,
    const __u_char *packet)
{
    int *id = (int *)arg;
    printf("id: %d\n", ++(*id));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));
    // 遍历数据包内容，以16进制输出，每打印16个字节换行，便于阅读
    int i;
    for (i = 0; i < pkthdr->len; ++i)
    {
        printf(" %02x", packet[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n\n");
}

int main()
{
    char dev[10] = "wlp0s20f3"; // 无线网口
    char errbuf[1024];
    pcap_t *device = pcap_open_live(dev, 65535, 1, 0, errbuf);
    if (!device)
    {
        printf("Couldn't open the net device: %s\n", errbuf);
        return -1;
    }
    printf("Start capturing!\n");
    // 捕获数据包
    int id = 0;
    pcap_loop(device, -1, get_packet, (__u_char *)&id);
}