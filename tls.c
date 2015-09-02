#include<stdio.h>	
#include<netinet/in.h>
#include"types.h"

int check_tls(unsigned char *p_start, unsigned char *p_current, unsigned int 
                pkt_len, unsigned int payload_len, unsigned long bigger_ip, 
                unsigned long smaller_ip, unsigned char ip_protocol,
                unsigned short bigger_port, unsigned short smaller_port) 
{
     unsigned char *payload = p_current;
     unsigned short record_len;
     NODE p_tuple = NULL;
      
     if (debug_verbose) {

         printf("Matching signature for TLS...\n");

     }     
     /* Check for minimum 5 bytes of data in payload */ 
     if (!end_of_pkt(p_start, p_current, 5, pkt_len)) {

         p_current += 3;
         record_len = ntohs(*((unsigned short *)p_current));

     } else {
         
         if (debug_verbose) {
 
             printf("Signature match failed...\n");

         }
         return 0;

     }
     
     /* Using client hello as signature for TLS */
     if ((payload[0] == 0x16) &&              /* Content type is handshake  */
         (payload[1] == 0x03) &&              /* Version is TLS version 1.0 */
         ((payload[2] == 0x01)||              /* or 1.1 or 1.2              */
         (payload[2] == 0x02) ||         
         (payload[2] == 0x03)) &&
         (record_len == (payload_len - 5))) { /* record_len read matches the
                                                 TLS record length */
        
         p_tuple = search(bigger_ip, smaller_ip, ip_protocol,  bigger_port,                               smaller_port);
         if (p_tuple != NULL) {

             /* Update the protocol_type field as TLS */
             p_tuple->protocol_type = TLS;

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

