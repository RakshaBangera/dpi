#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<regex.h>
#include"types.h"

int check_skype(unsigned char *p_current, unsigned int payload_len, 
                unsigned long bigger_ip, unsigned long smaller_ip,
                unsigned char ip_protocol, unsigned short bigger_port, 
                unsigned short smaller_port)
{
     regex_t regex;
     const char *pattern = "getlatestversion|getnewestversion";
     unsigned char *payload = (char *)malloc(payload_len + 1);
     int skype = 0;
     NODE p_tuple = NULL;
 
     if (debug_verbose) {

         printf("Matching signature for skype...\n");

     }
     if (payload == NULL) {

         printf("Out of memory\n");
         return 0;

     }
     memcpy(payload, p_current, payload_len);
     payload[payload_len] = '\0';
     if (!regcomp(&regex, pattern, REG_EXTENDED) && !regexec(&regex, payload, 0, 0, 0)) {

         skype = 1;
         p_tuple = search(bigger_ip, smaller_ip, ip_protocol, bigger_port, smaller_port);
         if (p_tuple != NULL) {
       
             p_tuple->protocol_type = SKYPE;

         }
     } else if (payload_len >=5 && 
                (payload[0] == 0x16 || payload[0]==0x17) &&
                (payload[1] == 0x03) && (payload[2] == 0x01) &&
                (payload[3] == 0x00) && (payload[4] == 0x00)) {
             
         skype=1;
         
         p_tuple = search(bigger_ip, smaller_ip, ip_protocol, bigger_port, smaller_port);
         if (p_tuple != NULL) {
                     
            /* Update protocol type field in ACK tuple */
            p_tuple->protocol_type = SKYPE;
         }
    }
    if (debug_verbose && skype) {
    
        printf("Signature match succeeded...\n\n");

    }
    if (debug_verbose && !skype) {

        printf("Signature match failed...\n\n");

    }
    regfree(&regex);
    free(payload);
    payload = NULL;
    return skype;

}                     
