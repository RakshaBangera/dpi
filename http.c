                                   
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<regex.h>
#include"types.h"

int check_http(unsigned char *p_current, unsigned int payload_len, 
               unsigned long bigger_ip, unsigned long smaller_ip,
               unsigned char ip_protocol, unsigned short bigger_port, 
               unsigned short smaller_port)
{
     regex_t regex;
     NODE p_tuple = NULL;
     const char *pattern1 = "^(DELETE|GET|HEAD|LINK|OPTIONS|PATCH|POST|PUT|TRACE|UNLINK.*HTTP/[0-9]+[.][0-9]+)";
     const char *pattern2 = "(Host:.*youtube[.]com.*)|(Referer:.*youtube[.]com.*)";
     char *payload = (char *)malloc(payload_len + 1);
     int http = 0, youtube = 0;

     if ( payload == NULL) {

         printf("Out of memory\n");

     } else {

         memcpy(payload, p_current, payload_len);
         payload[payload_len] = '\0';
         if (debug_verbose) {

            printf("Matching signature for HTTP...\n");

         }
         if (!regcomp(&regex, pattern1, REG_EXTENDED)) {

             if (!regexec(&regex, payload, 0,0,0)) {                             
                 if (!regcomp(&regex, pattern2, REG_EXTENDED)) {

                     if (!regexec(&regex, payload, 0,0,0)) {

                         youtube = 2;
                         p_tuple = search(bigger_ip, smaller_ip, ip_protocol,
                         bigger_port, smaller_port);
                         if (p_tuple != NULL) {

                             /* Update protocol type field as YOUTUBE */
                             p_tuple->protocol_type = YOUTUBE;

                         }
                         if (debug_verbose) {

                             printf("Signature matched for HTTP [Youtube]\n\n");

                         }
                         regfree(&regex);
                         free(payload);
                         payload = NULL;
                         return youtube;

                     }
                 }
                 http = 1;
                 p_tuple = search(bigger_ip, smaller_ip, ip_protocol, 
                 bigger_port, smaller_port);
                 if (p_tuple != NULL) {
                     
                     /* Update protocol type field as HTTP */
                     p_tuple->protocol_type = HTTP;

                 }
            
             }

         }
    }
    if (debug_verbose && http) {

        printf("Signature matched for HTTP\n\n");

    }
    if (debug_verbose && !http) {

        printf("Signature match failed for HTTP\n\n");

    }
    regfree(&regex);
    free(payload);
    payload = NULL;
    return http;
}
