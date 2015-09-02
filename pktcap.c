/* Program to print the packet data in hex */
          
#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include"types.h"

void load_capture(char fname[])
{
     int i,count;
     char errbuf[PCAP_ERRBUF_SIZE];  
     pcap_t* descr;                     /*packet descriptor */
     const u_char *packet;              

     /*   struct pcap_pkthdr 
      *   {
      *       struct timeval ts;    time stamp
      *       bpf_u_int32 caplen;   length of portion present
      *       bpf_u_int32 len;      length of this packet 
      *   }
      */
     struct pcap_pkthdr hdr; 
     

     printf("\n Load_capture() called\n");                 
     printf("\nFile opened:%s\n",fname);

     /*open saved file for reading */
     descr = pcap_open_offline(fname,errbuf);
     if (descr == NULL) {
         printf("pcap_open_offline(): %s\n",errbuf);     /*Print appropriate message if operation fails */
         return;
     }


     for(count = 1; packet != NULL; count++) {
         /*
          * Reads the next packet and returns a u_char 
          * pointer to the data in that packet
          */
         packet = pcap_next(descr,&hdr);
                                            
         if (packet == NULL) {
             /*if no packets are left */
             printf("\nTotal number of packets        = %d\n", count - 1);
             printf("Number of packets classified   = %d\n",packet_classified);
             printf("Number of packets unclassified = %d\n", packet_unclassified);
             printf("\n No more packets\n");
             return;
         }

         printf("\nPacket count= %d\n",count); 
         printf("Packet length= %d\n",hdr.caplen);
         if (debug_flag) {
             printf("Contents\n");
             for (i = 0; i < hdr.caplen; i++) {  
                 printf("%02x ",packet[i]);        
                 if(((i + 1) % 16 == 0 && i != 0) || i == hdr.len - 1) {                            
                     /* if no packets are left */
                     /* Print newline after 16 bytes or after all bytes of packet are read */
                     printf("\n");
                 }
             }
         }
         identify_packet(packet,hdr.caplen);
        sleep(2);

     } 
}
