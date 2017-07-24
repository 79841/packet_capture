#include <pcap.h>
#include <arpa/inet.h>
#define ETHERTYPE_IP 0x0800
#define PROTO_TCP 0x06 
struct ether_header
{
	unsigned char ether_dhost[6];      
	unsigned char ether_shost[6];
	unsigned char ether_type[2];
};
struct ip
{
	uint8_t ip_hl:4;
	uint8_t ip_v:4;
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	uint32_t ip_src,ip_dst;
};
struct tcp
{
	uint16_t th_sport;
	uint16_t th_dport;
	uint32_t th_seq;
	uint32_t th_ack;
	uint8_t th_off:4;
	uint8_t th_x2:4;
	uint8_t th_flags;
	uint16_t th_win;
	uint16_t th_sum;
	uint16_t th_urp;
};

/*struct pket
{
	struct ether_header ethhd;
	struct ip iphd;
	struct tcp tcphd;
};*/

void grab_pket(pcap_t * handle, struct pcap_pkthdr *header, const u_char *packet);
