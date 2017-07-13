#include <pcap.h>
#include <stdio.h>
struct ether_header
{
	unsigned char ether_dhost[6];      
	unsigned char ether_shost[6];
	unsigned short ether_type;
};
struct ip
{
	unsigned char dump[12];               /* header length */
	unsigned char ip_src[4];
	unsigned char ip_dst[4];
};
struct tcp
{
	unsigned char pt_src[2];
	unsigned char pt_dst[2];
	unsigned char dump[16];
};
struct pket
{
	struct ether_header ethhd;
	struct ip iphd;
	struct tcp tcphd;
};
	 int main(int argc, char *argv[])
	 {
		struct pket *pket;
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */
		int i=0, j=0, k=0;
		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		/* Grab a packet */
		while(1){
		i = pcap_next_ex(handle, &header,&packet);
		if(i==1)
		{
			/* Print its length */
	     	   	pket = (struct pket *)packet;
			printf("--------------- Source ---------------\n");
			printf("Source Mac = ");
			for(j=0;j<6;j++){
			printf("%02x%c",pket->ethhd.ether_shost[j], (j == 5) ? '\n' : ':');
			}
			/* And close the session */
			//while(){printf("%c",packet[j]);j++;}
			//printf("%s\n",ip_header->ip_src.s_addr);
			printf("Source IP = ");
			for(j=0;j<3;j++){
			printf("%d%c",(int)pket->iphd.ip_src[j],(j == 2) ? '\n' : '.');
			}
			printf("Source Port = ");
			printf("%d\n\n",196*(int)pket->tcphd.pt_src[0]+(int)pket->tcphd.pt_src[1]);			
			printf("------------- Destination ------------\n");
			printf("Destination Mac = ");
			for(j=0;j<6;j++){
			printf("%02x%c",pket->ethhd.ether_dhost[j], (j == 5) ? '\n' : ':');
			}
			printf("Destination IP = ");
			for(j=0;j<3;j++){
			printf("%d%c",(int)pket->iphd.ip_dst[j],(j == 2) ? '\n' : '.');
			}
			printf("Destination Port = ");
			printf("%d\n\n",196*(int)pket->tcphd.pt_dst[0]+(int)pket->tcphd.pt_dst[1]);			
			}
		}
		pcap_close(handle);
		return(0);
	 }
