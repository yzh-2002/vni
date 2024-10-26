#include <stdio.h>
#include <pcap/pcap.h>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE] = "\0";
    pcap_if_t *devsp = NULL;
    pcap_if_t *temp = NULL;
    printf("start libpcap\n");
    // 查找所有可用网卡，devsp为可用网卡链表头指针
    int ret = pcap_findalldevs(&devsp, errbuf);
    int i = 0;
    if (ret == 0 && devsp)
    {
        for (temp = devsp; temp; temp = temp->next)
        {
            printf("%d : interface name %s\n", i++, temp->name);
        }
    }
    else
    {
        printf("pcap_findalldevs error : %s\n", errbuf);
    }
    return 0;
}