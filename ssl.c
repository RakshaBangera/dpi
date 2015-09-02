#include<stdio.h>
#include<netinet/in.h>
#include"types.h"

int check_sslv3(unsigned char *p_start, unsigned char *p_current, unsigned int 
                pkt_len, unsigned int payload_len, unsigned long bigger_ip, 
                unsigned long smaller_ip, unsigned char ip_protocol,
                unsigned short bigger_port, unsigned short smaller_port) 
{
     unsigned char *payload = p_current;
     unsigned short record_len;
     NODE p_tuple = NULL;
     
     /* Check for minimum 5 bytes of data in payload */ 
     if (!end_of_pkt(p_start, p_current, 5, pkt_len)) {
         p_current += 3;
         record_len = ntohs(*((unsigned short *)p_current));
     } else {
         return 0;
     }
     
     if (debug_verbose) {

        printf("Matching signature for SSLv3...\n");

     }
     /* Using client hello as signature for SSL */
     if ((payload[0] == 0x16) &&              /* Content type is handshake */
         (payload[1] == 0x03) &&              /* Version is SSL version 3  */
         (payload[2] == 0x00) &&
         (record_len == (payload_len - 5))) { /* record_len read matches the
                                                 SSL record length */
        
         p_tuple = search(bigger_ip, smaller_ip, ip_protocol,  bigger_port,                               smaller_port);
         if (p_tuple != NULL) {

             /* Update the protocol_type field as SSL */
             p_tuple->protocol_type = SSL;

         }
         if (debug_verbose) {

             printf("Signature match succeeded\n\n");

         }
         return 1;
     } 
     if (debug_verbose) {

         printf("Signature match failed\n\n");

     }   
     return 0;
}    

int check_sslv2( unsigned char *p_start, unsigned char *p_current, unsigned int
                 pkt_len, unsigned int payload_len, unsigned long bigger_ip,
                 unsigned long smaller_ip, unsigned char ip_protocol, 
                 unsigned short bigger_port, unsigned short smaller_port)
{
     unsigned short record_len;
     NODE p_tuple = NULL;
     
     if (debug_verbose) {
 
         printf("Matching signature for SSLv2...\n");

     }     
     /* 2 byte record length */
     if ((*p_current & 0x80) && 
         (!end_of_pkt(p_start, p_current, 2, pkt_len))) {
    
         record_len = ((p_current[0] & 0x7f) << 8) | p_current[1];
         if (record_len == (payload_len - 2)) {

             p_tuple = search(bigger_ip, smaller_ip, ip_protocol, bigger_port, 
             smaller_port);
             if (p_tuple != NULL) {
                 p_tuple->protocol_type = SSL;
             }
             if (debug_verbose) {

                 printf("Signature match succeeded\n\n");
     
             }
             return 1;

         } else {
             
             if (debug_verbose) {
 
                 printf("Signature match failed\n\n"); 
 
             }
             return 0;

         }

     /* 3 byte record length */
     } else if (!(*p_current & 0x40) &&
                (!end_of_pkt(p_start, p_current, 3, pkt_len))) {
      
         record_len = ((p_current[0] & 0x3f) << 8 ) | p_current[1];
         if (record_len == (payload_len -3)) {
          
             p_tuple = search(bigger_ip, smaller_ip, ip_protocol, bigger_port,
             smaller_port); 
             if (p_tuple != NULL) {

                 p_tuple->protocol_type = SSL;

             }
             if (debug_verbose) {

                 printf("Signature match succeeded\n\n");

             }
             return 1;

         } else {
             
             if (debug_verbose) {
 
                 printf("Signature match failed\n\n");

             }  
             return 0;

         }

     } else {

         if (debug_verbose) {
 
             printf("signature match failed\n\n");
         }
         return 0;

     }
}
