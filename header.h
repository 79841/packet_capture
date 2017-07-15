#include <pcap.h>
struct ether_header
{
	unsigned char ether_dhost[6];      
	unsigned char ether_shost[6];
	unsigned short ether_type;
};
struct ip
{
	unsigned char dump[12];
	unsigned char ip_src[4];
	unsigned char ip_dst[4];
};
struct tcp
{
	unsigned char pt_src[2];
	unsigned char pt_dst[2];
	unsigned char dump[20];
	unsigned char data[100];
};
struct pket
{
	struct ether_header ethhd;
	struct ip iphd;
	struct tcp tcphd;
};

void grab_pket(pcap_t * handle, struct pcap_pkthdr *header, const u_char *packet);
