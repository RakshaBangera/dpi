struct node_
{
     unsigned long bigger_ip;
     unsigned long smaller_ip;
     unsigned char ip_protocol;
     unsigned short bigger_port;
     unsigned short smaller_port;
     unsigned int syn:1;
     unsigned int syn_ack:1;
     unsigned int ack:1;
     int protocol_type;
     struct node_ * next;
};

typedef struct node_ * NODE;

enum protocol { UNKNOWN, BITTORRENT, FTP_CTRL, FTP_DATA, GTALK, HTTP, IMAP, MSN, MSN_CTRL, NNTP, POP3,RTSP, SIP, SKYPE, SMTP, SSH, SSL, TELNET, TLS, YAHOO, YOUTUBE };

extern int packet_classified, packet_unclassified;

extern int debug_flag, debug_verbose;

NODE search(unsigned long bigger_ip, unsigned long smaller_ip,
            unsigned char ip_protocol, unsigned short bigger_port,
            unsigned short smaller_port);


