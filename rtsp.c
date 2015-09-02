                                   
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<regex.h>
#include"types.h"

int check_rtsp_over_udp(unsigned char *p_current, unsigned int payload_len)
{
     regex_t regex;
     const char * pattern = "^(DESCRIBE|ANNOUNCE|GET_PARAMETER|OPTIONS|PAUSE|PLAY|RECORD|REDIRECT|SETUP|SET_PARAMETER|TEARDOWN .* RTSP/[0-9]+[.][0-9]+)|^(RTSP/[0-9]+[.][0-9]+ [1-5][0-9][0-9] .*)";
     char *payload = (char *)malloc(payload_len + 1);
     int rtsp = 0;

     if ( payload == NULL) {

         printf("Out of memory\n");

     } else {

         memcpy(payload, p_current, payload_len);
         payload[payload_len] = '\0';
         if (debug_verbose) {

             printf("Matching signature for RTSP...\n");

         }
         if (!regcomp(&regex, pattern, REG_EXTENDED)) {

             if (!regexec(&regex, payload, 0,0,0)) {

                 rtsp = 1;

             }
         }
     }
     if (debug_verbose && rtsp) {

         printf("Signature match succeeded\n\n");

     }
     if (debug_verbose && !rtsp) {

         printf("Signature match failed\n\n");

     }
     regfree(&regex);
     free(payload);
     payload = NULL;
     return rtsp;
}

int check_rtsp_over_tcp(unsigned char *p_current, unsigned int payload_len, 
                        unsigned long bigger_ip, unsigned long smaller_ip,
                        unsigned char ip_protocol, unsigned short bigger_port, 
                        unsigned short smaller_port)
{
     regex_t regex;
     NODE p_tuple = NULL;
     const char *pattern = "^(DESCRIBE|ANNOUNCE|GET_PARAMETER|OPTIONS|PAUSE|PLAY|RECORD|REDIRECT|SETUP|SET_PARAMETER|TEARDOWN .* RTSP/[0-9][.][0-9])|^(RTSP/[0-9][.][0-9].*[1-5][0-9][0-9].*)";
     char *payload = (char *)malloc(payload_len + 1);
     int rtsp = 0;

     if ( payload == NULL) {

         printf("Out of memory\n");

     } else {

         memcpy(payload, p_current, payload_len);
         payload[payload_len] = '\0';
         if (debug_verbose) {

             printf("Matching signature for RTSP...\n");

         }
         if (!regcomp(&regex, pattern, REG_EXTENDED)) {

             if (!regexec(&regex, payload, 0,0,0)) {                                             
                 rtsp = 1;
                 p_tuple = search(bigger_ip, smaller_ip, ip_protocol,
                 bigger_port, smaller_port);
                 if (p_tuple != NULL) {
                     
                     /* Update protocol type field in the tuple */
                     p_tuple->protocol_type = RTSP;

                 }
            
             }
         }
    }
    if (debug_verbose && rtsp) {

        printf("Signature match succeeded\n\n");

    }

    if (debug_verbose && !rtsp) {

        printf("Signature match failed\n\n");

    }
    regfree(&regex);
    free(payload);
    payload = NULL;
    return rtsp;
}
