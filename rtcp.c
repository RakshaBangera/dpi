#include<stdio.h>
#include<sys/types.h>
#include<netinet/in.h>
#include"types.h"

int check_rtcp(unsigned char *p_current, unsigned int payload_len)
{

     int rtcp = 0;
     int length = 0;
     
     if (debug_verbose) {

         printf("Matching signature for RTCP...\n");

     } 
     if (payload_len < 4) {
         
         if (debug_verbose) {

             printf("Signature match failed\n\n");

         }
         return 0;

     }
     if (*p_current && 0x80) {
        
        length = ntohs(*((unsigned short *)(p_current + 2)));
        length = (length + 1) * 4;
        if (length == payload_len) {
         
           rtcp = 1;

        }
     }
     if (debug_verbose && rtcp) {

         printf("Signature match succeeded\n\n");

     }
     if (debug_verbose && !rtcp) {

         printf("Signature match failed\n\n");

     }
     return rtcp;
}
