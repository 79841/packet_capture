#include <stdio.h>
#include <pcap.h>
#include "header.h"

void grab_pket(pcap_t * handle, struct pcap_pkthdr *header, const u_char *packet){	
		/* Grab a packet */
		int i=0, j=0, k=1;
		struct pket *pket;
		while(1){
		i = pcap_next_ex(handle, &header,&packet);
		if(i==1)
		{
			/* Print its length */
	     	   	pket = (struct pket *)packet;
			//if(NULL!=pket->ethhd.ether_type[1])continue;
			printf("%d------------------- Source --------------------\n",k);
			printf("Source Mac = ");
			for(j=0;j<6;j++){
			printf("%02x%c",pket->ethhd.ether_shost[j], (j == 5) ? '\n' : ':');
			}
			/* And close the session */
			//while(){printf("%c",packet[j]);j++;}
			//printf("%s\n",ip_header->ip_src.s_addr);
			printf("Source IP = ");
			for(j=0;j<4;j++){
			printf("%d%c",(int)pket->iphd.ip_src[j],(j == 3) ? '\n' : '.');
			}
			printf("Source Port = ");
			printf("%d\n\n",196*(int)pket->tcphd.pt_src[0]+(int)pket->tcphd.pt_src[1]);			
			printf("%d----------------- Destination -----------------\n",k);
			printf("Destination Mac = ");
			for(j=0;j<6;j++){
			printf("%02x%c",pket->ethhd.ether_dhost[j], (j == 5) ? '\n' : ':');
			}
			printf("Destination IP = ");
			for(j=0;j<4;j++){
			printf("%d%c",(int)pket->iphd.ip_dst[j],(j == 3) ? '\n' : '.');
			}
			printf("Destination Port = ");
			printf("%d\n\n",196*(int)pket->tcphd.pt_dst[0]+(int)pket->tcphd.pt_dst[1]);			
			printf("%d-------------------- Data ---------------------\n",k);
			for(j=0;j<100;j++){
			printf("%02x %c",pket->tcphd.data[j],((j+1)%8==0) ? ' ' : '\0');
			if((j+1)%16==0)printf("\n");
			}
			printf("\n\n");
			k++;
			}
		}
}
