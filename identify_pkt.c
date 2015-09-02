/* Program to decode protocols */
                                   
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include"types.h"

void identify_packet(unsigned char *p_start, unsigned int pkt_len);
void parse_ip_header(unsigned char *p_start, unsigned char *p_current, 
                     unsigned int pkt_len);
void parse_udp_header(unsigned char *p_start, unsigned char *p_current, 
                      unsigned int pkt_len);
void parse_tcp_header(unsigned char *p_start, unsigned char *p_current, 
                      unsigned int pkt_len, unsigned long src_ip, 
                      unsigned long dest_ip,unsigned char protocol);

/* Check for end of packet */
int end_of_pkt(unsigned char *p_start, unsigned char *p_current, 
               unsigned int offset, unsigned int pkt_len)
{
     if ((p_current - p_start + 1 + offset ) > pkt_len) {

         return 1;

     } else {

         return 0;

     }
}

void identify_packet(unsigned char *p_start, unsigned int pkt_len)
{
     unsigned short e_type;
     unsigned char *p_current = p_start;

     if (!end_of_pkt(p_start, p_current, 14, pkt_len)) { 
         
         if (debug_verbose) {
             
             printf("\nParsing ethernet frame...\n");
             printf("Looking up ether type field...\n");
 
         } 
         /* Move p_current to the ether type field */
         p_current += 12;
         e_type = ntohs(*((unsigned short *)p_current));

     } else {

         printf("End of packet reached before protocol identification\n");
         packet_unclassified++;
         return;
     
     }

     switch (e_type) {

         case 0x0800:
              
             if (debug_verbose) {
                 
                 printf("Next encapsulating header is IP\n");

             }
             /* Move p_current to the beginning of IP header */ 
             p_current += 2;
             parse_ip_header(p_start, p_current, pkt_len);
             break;

         case 0x0806:
             
             if (debug_verbose) {

                 printf("Next encapsulating header is ARP\n\n");

             }
             printf("Protocol Type: Address Resolution Protocol(ARP)\n");
             packet_classified++;
             break;

         default:

             printf("Protocol Type: Unknown\n");
             packet_unclassified++;
             break;
     }
 }        

void parse_ip_header(unsigned char *p_start, unsigned char *p_current, 
                     unsigned int pkt_len)
{  
     /* Extract IHL-Internet Header Length. Turn off the higher nibble which 
      * represents the version. Multiply by 4 to obtain the length in bytes */
     unsigned char hdr_len = ((*p_current) & 0x0f) * 4;
     unsigned char protocol;
     unsigned short total_len;
     unsigned long src_ip, dest_ip;
    
     if (!end_of_pkt(p_start, p_current, hdr_len, pkt_len)) {  
         
         if (debug_verbose) {

             printf("\nParsing IP header...\n");
             printf("Looking up protocol field in IP header...\n");

         }   
         /* Extract total length of IP header and data */
         total_len = ntohs(*((unsigned short *)p_current + 1));
         pkt_len = total_len + 14;
         /* Extract protocol field value */
         protocol = *(p_current + 9);   

     } else {

         printf("End of packet reached before protocol identification\n");
         packet_unclassified++;
         return;

     }

     switch (protocol) {

         case 1:
             
             if (debug_verbose) {

                 printf("Next encapsulating header is ICMP\n\n");  
        
             }
             printf("Protocol Type: Internet Control Message Protocol(ICMP)\n");
             packet_classified++;
             break;

         case 6:

             if (debug_verbose) {
            
                 printf("Next encapsulating header is TCP\n\n");

             } 
             src_ip = ntohl(*((unsigned long *)p_current + 3));
             dest_ip = ntohl(*((unsigned long *)p_current + 4));
             /* Move p_current to the beginning of TCP header */
             p_current = p_current + hdr_len;
             parse_tcp_header(p_start, p_current, pkt_len, src_ip, dest_ip, 
                              protocol);
             break;

         case 17:            
             
             if (debug_verbose) {

                 printf("Next encapsulating header is UDP\n\n");

             }
             /* Move p_current to the beginning of UDP header */
             p_current = p_current + hdr_len; 
             parse_udp_header(p_start, p_current, pkt_len);
             break;

         default:

             printf("Protocol Type: Unknown\n");
             packet_unclassified++;
             break;

     }
}

void parse_udp_header(unsigned char *p_start, unsigned char *p_current, 
                      unsigned int pkt_len)
{
     unsigned short src_port, dest_port,udp_len;
     unsigned int payload_len;

     if (!end_of_pkt(p_start, p_current, 8,  pkt_len)) {

         if (debug_verbose) {

             printf("Parsing UDP header...\n");

         } 
         src_port = ntohs(*((unsigned short *)p_current));
         p_current += 2;
         dest_port = ntohs(*((unsigned short *)p_current));
         p_current += 2;
         udp_len = ntohs(*((unsigned short *)p_current));
         payload_len = udp_len - 8;
         p_current += 4; 

     } else {

         printf("End of packet reached before protocol identification\n");
         packet_unclassified++;
         return;

     }

     if (check_sip_over_udp(p_current, payload_len)) {

         printf("Protocol Type : Session Initiation Protocol(SIP)\n");
         packet_classified++;

     } else if (check_rtcp(p_current, payload_len)) {

         printf("Protocol Type: Real Time Transport Control Protocol(RTCP)\n");
         packet_classified++;

     } else if (check_rtsp_over_udp(p_current, payload_len)) {

         printf("Protocol Type: Real Time Streaming Protocol(RTSP)\n");
         packet_classified++;

     } else if (check_iana_port(src_port, dest_port)) {

         packet_classified++;

     } else if (check_rtp(p_current, payload_len)) {

         printf("Protocol Type :Real Time Transport Protocol(RTP)\n");
         packet_classified++;

     } else {

         printf("Protocol Type: Unknown\n"); 
         packet_unclassified++;

     }
}

void parse_tcp_header(unsigned char *p_start, unsigned char *p_current, 
                      unsigned int pkt_len, unsigned long src_ip, 
                      unsigned long dest_ip, unsigned char ip_protocol)
{
     unsigned char hdr_len, syn, ack, fin;
     unsigned short src_port, dest_port, bigger_port, smaller_port;
     unsigned long bigger_ip, smaller_ip;
     unsigned int payload_len, len_upto_tcp, ip_addr1, ip_addr2;
     /* Maps enum values to string */
     char *protocol_map[21] = {"UNKNOWN",
                              "BitTorrent",
                              "File Transfer Protocol(FTP) Control",
                              "File Transfer Protocol(FTP) Data",
                              "GTALK",
                              "Hyper Text Transfer Protocol(HTTP)",
                              "Internet Message Access Protocol(IMAP)",
                              "MSN Messenger",
                              "MSN Messenger audio/video control",
                              "Network News Transfer Protocol(NNTP)",
                              "Post Office Protocol(POP3)",
                              "Real Time Streaming Protocol(RTSP)",
                              "Session Initiation Protocol(SIP)",
                              "SKYPE",
                              "Simple Mail Transfer Protocol(SMTP)",
                              "Secure Shell(SSH)",
                              "Secure Socket Layer(SSL)",
                              "TELNET",
                              "Tranport Layer Security(TLS)",
                              "Yahoo Messenger",
                              "HTTP [Youtube]"};
     NODE p_tuple = NULL;
     int return_val;
     struct in_addr ip1, ip2;
     char *ip_string = NULL, *ip1_string = NULL, *ip2_string = NULL;

     if (debug_verbose) {

         printf("Parsing TCP header...\n");

     }

     if (!end_of_pkt(p_start, p_current, 3, pkt_len)) {

         src_port = ntohs(*((unsigned short *)p_current));
         p_current += 2;
         dest_port = ntohs(*((unsigned short *)p_current));

     } else {

         printf("End of packet reached before protocol identification\n");
         packet_unclassified++;
         return;

     }

     /* Normalisation of tuples */
     if (dest_ip > src_ip) {

         bigger_ip = dest_ip;
         smaller_ip = src_ip;

     } else {

         bigger_ip = src_ip;
         smaller_ip = dest_ip;

     }

     if (dest_port > src_port) {

         bigger_port = dest_port;
         smaller_port = src_port;

     } else {

         bigger_port = src_port;
         smaller_port = dest_port;

     }
     
     ip_addr1 = htonl(bigger_ip);
     ip_addr2 = htonl(smaller_ip);
     ip1.s_addr = ip_addr1;
     ip2.s_addr = ip_addr2;
     ip_string = inet_ntoa(ip1);
     ip1_string = (char *)malloc(strlen(ip_string) + 1);
     strcpy(ip1_string, ip_string);
     ip_string = inet_ntoa(ip2);
     ip2_string = (char *)malloc(strlen(ip_string) + 1);
     strcpy(ip2_string, ip_string);

     /* 
      * Read TCP header length, SYN, ACK and FIN field.
      */  
     if (!end_of_pkt(p_start, p_current, 11,pkt_len)) {

         p_current += 10;
         hdr_len = ((((*p_current) & 0xf0))>>4) * 4;
         p_current++;
         syn = ((*p_current) & 0x02) ? 1 : 0;
         ack = ((*p_current) & 0x10) ? 1 : 0;
         fin = ((*p_current) & 0x01) ? 1 : 0;

     } else {

         printf("End of packet reached before protocol identification\n");
         packet_unclassified++;
         return;

     }

     /* No of bytes inclusive of TCP header and exclusive of payload and
      * Ethernet FCS 
      */
     len_upto_tcp = p_current + (hdr_len -13) - p_start;
     
     p_tuple = search(bigger_ip, smaller_ip, ip_protocol, bigger_port,
                      smaller_port);
     if (syn == 1 && ack == 0 ) {

         /* Insert new tuple into the hash table */
         if (p_tuple == NULL) {

             insert(bigger_ip, smaller_ip, ip_protocol, bigger_port, 
             smaller_port,1, 0, 0, UNKNOWN);
             if (debug_verbose) {

                 printf("Received SYN for the tuple(%s, %s, %d, %hu, %hu)\n",ip1_string, ip2_string, ip_protocol, bigger_port, smaller_port);

             }

         }
         if (len_upto_tcp == pkt_len) {

             printf("Protocol Type: TCP [SYN]\n");
             packet_classified++;

         }

     } else if (syn == 1 && ack == 1 && p_tuple != NULL) {
 
         /* Set syn_ack field if syn is set */
         if (p_tuple->syn == 1 && p_tuple->syn_ack == 0) {

             p_tuple->syn_ack = 1;
             if (debug_verbose) {

                 printf("Received SYN-ACK for the tuple (%s, %s, %d, %hu, %hu)\n", ip1_string, ip2_string, ip_protocol, bigger_port, smaller_port);

             }

         }

         if (len_upto_tcp == pkt_len) {

             printf("Protocol Type: TCP [SYN-ACK]\n");
             packet_classified++;

         }
             
     } else if (fin == 1 ) {

         /*
          * TCP connection tear down
          * Delete the entry from hash table on receipt of FIN segment
          */
         if (p_tuple != NULL) {

             delete(bigger_ip, smaller_ip, ip_protocol, bigger_port,smaller_port);
             if (debug_verbose) {

                 printf("Received FIN for the tuple (%s, %s, %d, %hu, %hu)\n", ip1_string, ip2_string, ip_protocol, bigger_port, smaller_port);

             }
         }

         if (len_upto_tcp == pkt_len) {

             if (ack == 1) {

                 printf("Protocol Type: TCP [FIN-ACK]\n");

             } else {

                 printf("Protocol Type: TCP [FIN]\n");

             }
             packet_classified++;

         }

     } else if (ack == 1) {
         
         if (p_tuple != NULL) {

             /* Set ack field if syn and syn_ack is set */
             if ((p_tuple->syn == 1)&&
                 (p_tuple->syn_ack == 1) &&
                 (p_tuple->ack == 0)) {

                 p_tuple->ack = 1;
                 if (debug_verbose) {

                     printf("Received ACK for the tuple (%s, %s, %d, %hu, %hu)\n", ip1_string, ip2_string, ip_protocol, bigger_port, smaller_port);

                 }
             }

         }
         if (len_upto_tcp == pkt_len) {

             printf("Protocol Type: TCP [ACK]\n");
             packet_classified++;

         }

     } else if (len_upto_tcp == pkt_len) {

         printf("Protocol Type: Unknown\n");
         packet_unclassified++;

     }
 
     if (!end_of_pkt(p_start, p_current, hdr_len - 13, pkt_len)) {

         p_current += hdr_len - 13;

     } else { 

         return;

     }

     payload_len = pkt_len - (p_current - p_start);

     if (p_tuple != NULL) {
         
         if ((p_tuple->syn == 1) &&
             (p_tuple->syn_ack == 1) &&
             (p_tuple->ack == 1)) { 
              
             if (debug_verbose) {

                 printf("Looking up hash table if packet is already classified...\n\n");

             }
             if (p_tuple->protocol_type != UNKNOWN) {

                 printf("Protocol Type: %s\n",protocol_map[p_tuple->protocol_type]);
                 packet_classified++;

             } else if (check_bittorrent(p_current, payload_len,bigger_ip, 
                        smaller_ip, ip_protocol, bigger_port,smaller_port)) {

                 printf("Protocol Type: BitTorrent\n");
                 packet_classified++; 

             } else if (check_ftp_ctrl(p_current, payload_len, bigger_ip,
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: File Transfer Protocol(FTP) Control\n");
                 packet_classified++;

             } else if (check_ftp_data(bigger_ip, smaller_ip, ip_protocol,
                        bigger_port,  smaller_port)) {

                 printf("Protocol Type: File transfer Protocol(FTP) Data\n");
                 packet_classified++;

             } else if (check_gtalk(p_current, payload_len, bigger_ip,
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: GTALK\n");
                 packet_classified++;

             } else if (check_skype(p_current, payload_len, bigger_ip, 
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: SKYPE\n");
                 packet_classified++;

             }  else if (return_val = check_http(p_current, payload_len,
                        bigger_ip, smaller_ip, ip_protocol, bigger_port,
                        smaller_port)) {

                 if (return_val == 1) {
                     printf("Protocol Type: Hyper Text Transfer Protocol(HTTP)\n");
                     packet_classified++;

                 } else if (return_val == 2) {

                     printf("Protocol Type: HTTP [Youtube]\n");
                     packet_classified++;

                 }

             } else if (check_msn(p_current, payload_len, bigger_ip, smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: MSN Messenger\n");
                 packet_classified++;

             } else if (check_msn_control(p_current, payload_len, bigger_ip, smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: MSN Messenger audio/video control\n");
                 packet_classified++;

             } else if (check_nntp(p_current, payload_len, bigger_ip, smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: Network News Transfer Protocol(NNTP)\n");
                 packet_classified++;

             }  else if (check_pop3(p_current, payload_len, bigger_ip,
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: Post Office Protocol(POP3)\n");
                 packet_classified++;

             } else if (check_rtsp_over_tcp(p_current, payload_len, bigger_ip,
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: Real Time Streaming Protocol(RTSP)\n");
                 packet_classified++;

             } else if (check_sip_over_tcp(p_current, payload_len, bigger_ip,
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {
                
                 printf("Protocol Type : Session Initiation Protocol(SIP)\n");
                 packet_classified++;

             } else if (check_smtp(p_current, payload_len, bigger_ip, 
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: Simple Mail Transfer Protocol(SMTP)\n");
                 packet_classified++;

             } else if (check_ssh(p_current, payload_len, bigger_ip,
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: Secure Shell(SSH)\n");
                 packet_classified++;

             } else if (check_sslv2(p_start, p_current, pkt_len, payload_len,
                        bigger_ip, smaller_ip, ip_protocol, bigger_port,
                        smaller_port)) {
                 
                 printf("Protocol Type: Secure Socket Layer(SSL)\n");
                 packet_classified++;

             } else if (check_sslv3(p_start, p_current, pkt_len, payload_len,
                        bigger_ip, smaller_ip, ip_protocol, bigger_port, 
                        smaller_port)) {
                 
                 printf("Protocol Type: Secure Socket Layer(SSL)\n");
                 packet_classified++;

             } else if (check_telnet(p_current, payload_len, bigger_ip, 
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {
                 
                 printf("Protocol Type: TELNET\n");
                 packet_classified++;

             } else if (check_tls(p_start, p_current, pkt_len, payload_len,
                        bigger_ip, smaller_ip, ip_protocol, bigger_port,
                        smaller_port)) {

                 printf("Protocol Type: Transport Layer Security(TLS)\n");
                 packet_classified++;

             } else if (check_yahoo(p_current, payload_len, bigger_ip,
                        smaller_ip, ip_protocol, bigger_port, smaller_port)) {
 
                 printf("Protocol Type: Yahoo Messenger\n");
                 packet_classified++;

             } else if (check_imap(p_current, payload_len, bigger_ip, smaller_ip, ip_protocol, bigger_port, smaller_port)) {

                 printf("Protocol Type: Internet Message Access Protocol(IMAP)\n");
                 packet_classified++;

             }  else if (check_iana_port(src_port, dest_port)) {
                
                 packet_classified++;
             
             } else {

                 printf("Protocol Type: Unknown\n");
                 packet_unclassified++;

             }
         } else {

             printf("Protocol Type: Unknown\n");
             packet_unclassified++;

         }
    } else if (check_iana_port(src_port, dest_port)) {

        packet_classified++;
   
    }  else {
        
        printf("Protocol Type: Unknown\n");
        packet_unclassified++;

    }
}


     
    
