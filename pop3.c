#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<regex.h>
#include"types.h"

int check_pop3(unsigned char *p_current, unsigned int payload_len, 
               unsigned long bigger_ip, unsigned long smaller_ip,
               unsigned char ip_protocol, unsigned short bigger_port, 
               unsigned short smaller_port)
{
     regex_t regex;
     NODE p_tuple = NULL;
     const char *pattern = "^([+]OK)|^([-]ERR)";
     char *payload = (char *)malloc(payload_len + 1);
     int pop3 = 0;

     if ( payload == NULL) {
 
         printf("Out of memory\n");

     } else {

         memcpy(payload, p_current, payload_len);
         payload[payload_len] = '\0';
         if (debug_verbose) {

             printf("Matching signature for POP3...\n");

         }
         if (!regcomp(&regex, pattern, REG_EXTENDED)) {

             if (!regexec(&regex, payload, 0,0,0)) {                            

                 pop3 = 1;
                 p_tuple =  search(bigger_ip, smaller_ip, ip_protocol, bigger_port, smaller_port);
                 if (p_tuple != NULL) {
                     
                     /* Update protocol type field in ACK tuple */
                     p_tuple->protocol_type = POP3;

                 }
            
             }
         }
    }
    if (debug_verbose && pop3) {
 
        printf("Signature match succeeded\n\n");

    }
    if (debug_verbose && !pop3) {

        printf("Signature match failed\n\n");

    }
    regfree(&regex);
    free(payload);
    payload = NULL;
    return pop3;
}
