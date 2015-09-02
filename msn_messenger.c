                                   
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<regex.h>
#include"types.h"

int check_msn(unsigned char *p_current, unsigned int payload_len, 
               unsigned long bigger_ip, unsigned long smaller_ip,
               unsigned char ip_protocol, unsigned short bigger_port, 
               unsigned short smaller_port)
{
     regex_t regex;
     NODE p_tuple = NULL;
     const char *pattern = "^(VER .* MSNP|CVR)|^(USR)|^(ANS)";
     char *payload = (char *)malloc(payload_len + 1);
     int msn = 0;

     if ( payload == NULL) {

         printf("Out of memory\n");

     } else {

         memcpy(payload, p_current, payload_len);
         payload[payload_len] = '\0';
         if (debug_verbose) {

             printf("Matching signature for MSN Messenger...\n");

         }
         if (!regcomp(&regex, pattern, REG_EXTENDED)) {

             if (!regexec(&regex, payload, 0,0,0)) {                   

                 msn = 1;
                 p_tuple = search(bigger_ip, smaller_ip, ip_protocol,                                             bigger_port, smaller_port);
                 if (p_tuple != NULL) {
                     
                     /* Update protocol type field in the tuple */
                     p_tuple->protocol_type = MSN;

                 }
            
             }
         }
    }
    if (debug_verbose && msn) {

        printf("Signature match succeeded\n\n");

    }
    if (debug_verbose && !msn) {

        printf("Signature match failed\n\n");

    }
    regfree(&regex);
    free(payload);
    payload = NULL;
    return msn;
}

int check_msn_control(unsigned char *p_current, unsigned int payload_len,
               unsigned long bigger_ip, unsigned long smaller_ip,
               unsigned char ip_protocol, unsigned short bigger_port,
               unsigned short smaller_port)
{
     unsigned char *pos = NULL;
     NODE p_tuple = NULL;
     int msn_ctrl = 0;
     unsigned char pattern[26] = {'"','v','o','i','c','e','.','m','e','s','s','e','n','g','e','r','.','l','i','v','e','.','c','o','m','"'};
     if (debug_verbose) {
 
         printf("Matching signature for MSN audio/video control...\n");
     }
     pos = (unsigned char *)memchr(p_current, 34, payload_len);
     if (pos != NULL) {

         if (!memcmp(pattern, pos, 26)) {
        
             msn_ctrl = 1;
             p_tuple = search(bigger_ip, smaller_ip, ip_protocol, bigger_port, smaller_port);
             if (p_tuple != NULL) {

                 p_tuple->protocol_type = MSN_CTRL;
             }
        }  
     }
     if (debug_verbose && msn_ctrl) {

         printf("Signature match succeeded\n\n");

     }

     if (debug_verbose && !msn_ctrl) {
    
         printf("Signature match failed\n\n");

     }
     return msn_ctrl;
}


