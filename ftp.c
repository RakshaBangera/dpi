#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<regex.h>
#include"types.h"

int check_ftp_ctrl(unsigned char *p_current, unsigned int payload_len,
                   unsigned long bigger_ip, unsigned long smaller_ip,
                   unsigned char ip_protocol, unsigned short bigger_port,
                   unsigned short smaller_port)
{
     regex_t regex;
     NODE p_tuple = NULL;
     const char *pattern = "PORT|227 Entering Passive Mode";
     char *payload = (char *)malloc(payload_len + 1);
     unsigned char *ptr = NULL, temp[4];
     unsigned short p1, p2, data_port;
     int i = 0, count = 0, ftp = 0;
     
     if (payload == NULL) {

         printf("Out of memory\n");

     } else {

         memcpy(payload, p_current, payload_len);
         payload[payload_len] = '\0';
         if (debug_verbose) {

             printf("Matching signature for FTP control...\n");

         }
         if (!regcomp(&regex, pattern, REG_EXTENDED)) {

             if (!regexec(&regex, payload, 0, 0, 0)) {

                 ftp = 1;

                 /* 
                  * ptr points to the beginning of argument field of
                  * FTP active or passive connection.
                  */

                 if (payload[0] == '2') {
                     
                     if (debug_verbose) {

                         printf("Signature match succeeded\n");
                         printf("FTP opens data connection in passive mode\n\n");

                     }
                     ptr = &payload[27];

                 } else {
                  
                     if (debug_verbose) {

                         printf("Signature match succeeded\n");
                         printf("FTP opens data connection in active mode\n\n");

                     }
                     ptr = &payload[5];

                 }
                 
                 /* Skip ip address */

                 while (count < 4) {

                     if (*ptr == ',') {

                         count++;

                     }
                     ptr++;

                 }
                 
                 /* Extract port number where FTP data connection will be
                  * opened. */ 

                 while (*ptr != ',') {

                     temp[i++] = *ptr++;

                 }
                 temp[i]='\0';
                 p1 = (unsigned short)atoi(temp);
                 ptr++;
                 i=0;
                 while ((*ptr !=')') && (*ptr != 0x0d)) {

                     temp[i++] = *ptr++;

                 }
                 temp[i]='\0';
                 p2 =(unsigned short)atoi(temp);
                 data_port = p1 * 256 + p2;
                 
                 /* 
                  * Insert the tuple determining the possible FTP data
                  * connection into FTP linked list.
                  */
                 ftp_insert(bigger_ip, smaller_ip, ip_protocol, data_port);
                 p_tuple = search(bigger_ip, smaller_ip, ip_protocol, 
                 bigger_port, smaller_port);
                 if (p_tuple != NULL) {

                     p_tuple->protocol_type = FTP_CTRL;

                 }
             }   
         }
     }
     if (debug_verbose && !ftp) {

         printf("Signature match failed\n\n");

     }
     regfree(&regex);
     free(payload);
     payload = NULL;
     return ftp;
}

int check_ftp_data(unsigned long bigger_ip, unsigned long smaller_ip,
                   unsigned char ip_protocol, unsigned short bigger_port,
                   unsigned short smaller_port)
{
     int ftp=0;
     NODE p_tuple = NULL;
     
     /*
      * If current tuple finds a match in FTP linked list then it is an
      * indication of FTP data
      */
     if (debug_verbose) {

         printf("Matching signature for FTP data...\n");

     }
     if (ftp_search(bigger_ip, smaller_ip, ip_protocol, bigger_port,
         smaller_port)) {
 
         p_tuple = search(bigger_ip, smaller_ip, ip_protocol, bigger_port,
         smaller_port);
         if (p_tuple != NULL) {

             p_tuple->protocol_type = FTP_DATA;
             ftp_delete(bigger_ip, smaller_ip, ip_protocol, bigger_port,
             smaller_port);
             ftp = 1;

         }
     }
     if (debug_verbose && ftp) {

         printf("Current tuple found in FTP linked list\n\n");

     }
     if (debug_verbose && !ftp) {
   
         printf("Current tuple not found in FTP linked list\n\n");

     }
     return ftp;
}
     
