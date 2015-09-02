#include<stdio.h>
#include"types.h"

int check_telnet(unsigned char *p_current, unsigned int payload_len, 
               unsigned long bigger_ip, unsigned long smaller_ip,
               unsigned char ip_protocol, unsigned short bigger_port, 
               unsigned short smaller_port)
{
     unsigned char *payload = p_current;
     int i = 0;
     NODE p_tuple = NULL;
     
     if (debug_verbose) {

         printf("Matching signature for Telnet...\n");

     }
     if (payload_len < 3) {
         
         if (debug_verbose) {
    
             printf("Signature match failed\n\n");

         }
         return 0;

     }
     while ( i <= payload_len - 3) {

         /* Check for telnet option negotiation */
         if ((payload[i] == 0xFF) &&
             (payload[i+1] >= 0xFB && payload[i+1] <= 0xFE) &&
             (payload[i+2] >= 0x00 && payload[i+2] <= 0x31) ||
             (payload[i+2] >= 0x8A && payload[i+2] <= 0x8C) ||
             (payload[i+2] == 0xFF)) {
             
             i = i + 3;

         /* Check for telnet sub-option negotiation */
         } else if ((payload[i] == 0xFF) &&
                    (payload[i+1] == 0xFA) &&
                    (payload[i+2] >= 0x00 && payload[i+2] <= 0x31) ||
                    (payload[i+2] >= 0x8A && payload[i+2] <= 0x8c) ||
                    (payload[i+2] == 0xFF)) {
             
             i = i + 3;
             /* Parameter for sub-option negotiation is of variable length.
              * Hence iterate till IAC SE is reached. */
             while ((i <= payload_len - 3) &&
                    (payload[i+1] != 0xFF) &&
                    (payload[i+2] != 0xF0)) {
               
                 i++;

             }
             i = i + 3;

         } else {
             
             if (debug_verbose) {

                 printf("Signature match failed\n\n");

             }
             return 0;

         }
       
    }
    p_tuple = search(bigger_ip, smaller_ip, ip_protocol, bigger_port, 
    smaller_port);
    if (p_tuple != NULL) {
                     
        /* Update protocol type field in ACK tuple */
        p_tuple->protocol_type = TELNET;

    }
    if (debug_verbose) {
     
        printf("Signature match succeeded\n\n");

    }
    return 1;
}                     
