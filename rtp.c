#include<stdio.h>
#include<sys/types.h>
#include<netinet/in.h>
#include"types.h"

int check_rtp(unsigned char *p_current, unsigned int payload_len)
{
    int version1 = (*p_current) & 0x80;
    int version2 = (*p_current) & 0x40;
    int payload_type = 0; 
    int rtp = 0;

    if (debug_verbose) {

        printf("Matching signature for RTP...\n");

    }
    if (payload_len < 12) {

        return 0;

    }
    payload_type = *(p_current + 1) & 0x7F;
 
    if ( version1 && !version2 && payload_type >=0 && payload_type < 128) {

        rtp = 1;
    }
    if (debug_verbose && rtp) {

        printf("Signature match succeeded\n\n");

    }
    if (debug_verbose && !rtp) {

        printf("Signature match failed\n\n");

    }
    return rtp;
}
