#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "header.h"

void grab_pket(pcap_t * handle, struct pcap_pkthdr *header, const u_char *packet){	
		/* Grab a packet */
		unsigned char databuffer[1024];
		int i=0, j=0, k=1;
		char test[16];
		int iphd_len,tcphd_len, data_len, data_size;
		
		struct tcp * tcphd;
		struct ip * iphd;
		struct ether_header * ethhd;
		unsigned char * data_ptr;
		while(1){
		i = pcap_next_ex(handle, &header,&packet);
		if(i==1)
		{
			/* Print its length */
			ethhd = (struct ether_header *)packet;
			if(0!=ethhd->ether_type[1])continue;
			printf("%d------------------- Source --------------------\n",k);
			printf("Source Mac = ");
			for(j=0;j<6;j++){
			printf("%02x%c",ethhd->ether_shost[j], (j == 5) ? '\n' : ':');
			}
			iphd = (struct ip *)(packet+14);
			inet_ntop(AF_INET,&iphd->ip_src,test,sizeof(test));
			printf("Source IP = %s\n",test);
					
			iphd_len = (iphd->ip_hl)*4; 

			tcphd = (struct tcp *)(packet+14+iphd_len);
			printf("Source Port = %d\n",ntohs(tcphd->th_sport));
			tcphd_len = tcphd->th_off >> 2;
			
			printf("%d----------------- Destination -----------------\n",k);
			printf("Destination Mac = ");
			for(j=0;j<6;j++){
			printf("%02x%c",ethhd->ether_dhost[j], (j == 5) ? '\n' : ':');
			}

			inet_ntop(AF_INET,&iphd->ip_dst,test,sizeof(test));
			printf("Destination IP = %s\n",test);
						
			printf("Destination Port = %d\n",ntohs(tcphd->th_dport));
			printf("%d-------------------- Data ---------------------\n",k);
			
			data_len = ntohs(iphd->ip_len)-tcphd_len-iphd_len;
			data_ptr = (unsigned char *)tcphd+tcphd_len;
			//data_size = (data_len > 100)?100:data_len;
			//printf("%d %d %d %d\n",sizeof(struct ether_header),sizeof(struct ip),sizeof(struct tcp),sizeof(struct pket));
			for(j=0;j<data_len;j++){
				printf("%c",data_ptr[j]);
			}
			printf("\n\n");
			k++;
			}
		}
}
