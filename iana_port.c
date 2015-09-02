#include<stdio.h>
#include"types.h"

int check_iana_port(unsigned short src_port, unsigned short dest_port)
{

     if (( src_port == 1) || (dest_port == 1)) {

         printf("Protocol Type: TCP Port Service Multiplexer(TCPMUX)\n");
         return 1;

     } else if (( src_port == 7) || (dest_port == 7)) {

         printf("Protocol Type: Echo\n");
         return 1;

     } else if (( src_port == 11) || (dest_port == 11)) {

         printf("Protocol Type: SYSTAT\n");
         return 1;

     } else if (( src_port == 13) || (dest_port == 13)) {

         printf("Protocol Type: Daytime Protocol\n");
         return 1;

     } else if (( src_port == 17) || (dest_port == 17)) {

         printf("Protocol Type: Quote of the Day(QOTD)\n");
         return 1;

     } else if (( src_port == 18) || (dest_port == 18)) {

         printf("Protocol Type: Message Send Protocol (MSP)\n");
         return 1;

     } else if (( src_port == 19) || (dest_port == 19)) {

         printf("Protocol Type: Character Generator Protocol(Chargen)\n");
         return 1;

     } else if (( src_port == 20) || (dest_port == 20)) {

         printf("Protocol Type: File Transfer Protocol(FTP) data\n");
         return 1;

     } else if (( src_port == 21) || (dest_port == 21)) {

         printf("Protocol Type: File Transfer Protocol(FTP) control\n");
         return 1;

     } else if ((src_port == 22) || (dest_port == 22)) {

         printf("Protocol Type: Secure Shell(SSH)l\n");
         return 1;

     } else if (( src_port == 23) || (dest_port == 23)) {

         printf("Protocol Type: TELNET\n");
         return 1;

     } else if (( src_port == 25) || (dest_port == 25)) {

         printf("Protocol Type: Simple Mail Transfer Protocol(SMTP)\n");
         return 1;

     } else if (( src_port == 33) || (dest_port == 33)) {

         printf("Protocol Type: Display Support Protocol(DSP)\n");
         return 1;

     } else if (( src_port == 37) || (dest_port == 37)) {

         printf("Protocol Type: Time Protocol\n");
         return 1;

     } else if ((src_port == 38) || (dest_port == 38)) {

         printf("Protocol Type: Route Access Protocol(RAP)\n");
         return 1;

     } else if ((src_port == 39) || (dest_port == 39)) {

         printf("Protocol Type: Resource Location Protocol(RLP)\n");
         return 1;

     }  else if (( src_port == 42) || (dest_port == 42)) {

         printf("Protocol Type: Internet Name Server\n");
         return 1;

     } else if ((src_port == 43) || (dest_port == 43)) {

         printf("Protocol Type: Whois\n");
         return 1;

     }  else if (( src_port == 45) || (dest_port == 45)) {

         printf("Protocol Type: Internet Message Protocol\n");
         return 1;

     } else if (( src_port == 49) || (dest_port == 49)) {

         printf("Protocol Type: Login Host Protocol\n");
         return 1;

     } else if ((src_port == 50) || (dest_port == 50)) {

         printf("Protocol Type: Remote Mail Checking Protocol(RMCP)\n");
         return 1;

     } else if (( src_port == 52) || (dest_port == 52)) {

         printf("Protocol Type: XNS Time Protocol\n");
         return 1;

     } else if (( src_port == 53) || (dest_port == 53)) {

         printf("Protocol Type: Domain Name System(DNS)\n");
         return 1;

     } else if  ((src_port == 67) || (dest_port == 67)) {

         printf("Protocol Type: BOOTP Server\n");
         return 1;

     } else if ((src_port == 68) || (dest_port == 68)) {

         printf("Protocol Type: BOOTP Client\n");
         return 1;

     } else if ((src_port == 69) || (dest_port == 69)) {

         printf("Protocol Type: Trivial File Transfer(TFTP)\n");
         return 1;

     } else if ((src_port == 70) || (dest_port == 70)) {

         printf("Protocol Type: Gopher\n");
         return 1;

     } else if ((src_port == 79) || (dest_port == 79)) {

         printf("Protocol Type: Finger\n");
         return 1;

     }  else if (( src_port == 80) || (dest_port == 80)) {

         printf("Protocol Type: Hyper Text Transfer Protocol(HTTP)\n");
         return 1;

     } else if (( src_port == 88) || (dest_port == 88)) {

         printf("Protocol Type: Kerberos\n");
         return 1;

     } else if (( src_port == 92) || (dest_port == 92)) {

         printf("Protocol Type: Network Printing Protocol\n");
         return 1;

     } else if (( src_port == 93) || (dest_port == 93)) {

         printf("Protocol Type: Device Control Protocol(DCP)\n");
         return 1;

     } else if (( src_port == 95) || (dest_port == 95)) {

         printf("Protocol Type: SUPDUP\n");
         return 1;

     }  else if (( src_port == 97)|| (dest_port == 97)) {

         printf("Protocol Type: Swift Remote Virtual File Protocol\n");
         return 1;

     } else if (( src_port == 101) || (dest_port == 101)) {

         printf("Protocol Type: HOSTNAME\n");
         return 1;

     } else if (( src_port == 107) || (dest_port == 107)) {

         printf("Protocol Type: Remote Telnet Service\n");
         return 1;

     } else if (( src_port == 109) || (dest_port == 109)) {

         printf("Protocol Type: Post Office Protocol(POP2)\n");
         return 1;

     } else if (( src_port == 110) || (dest_port == 110)) {

         printf("Protocol Type: Post Office Protocol(POP3)\n");
         return 1;

     } else if (( src_port == 115) || (dest_port == 115)) {

         printf("Protocol Type: Simple File  Transfer Protocol(SFTP)\n");
         return 1;

     } else if (( src_port == 117) || (dest_port == 117)) {

         printf("Protocol Type: Unix to Unix Copy(UUCP)\n");
         return 1;

     }  else if (( src_port == 119) || (dest_port == 119)) {

         printf("Protocol Type: Network News Transfer Protocol(NNTP)\n");
         return 1;

     } else if (( src_port == 123) || (dest_port == 123)) {

         printf("Protocol Type: Network Time Protocol(NTP)\n");
         return 1;

     } else if (( src_port == 129) || (dest_port == 129)) {

         printf("Protocol Type: Password Generator Protocol(PWDGEN)\n");
         return 1;

     } else if (( src_port == 133) || (dest_port == 133)) {

         printf("Protocol Type: Statistics Service\n");
         return 1;

     }  else if (( src_port == 137) || (dest_port == 137)) {

         printf("Protocol Type: NETBIOS Name Service\n");
         return 1;

     } else if (( src_port == 138) || (dest_port == 138)) {

         printf("Protocol Type: NETBIOS Datagram Service\n");
         return 1;

     } else if (( src_port == 139) || (dest_port == 139)) {

         printf("Protocol Type: NETBIOS Session Service\n");
         return 1;

     } else if (( src_port == 143) || (dest_port == 143)) {

         printf("Protocol Type: Internet Message Access Protocol(IMAP)\n");
         return 1;

     } else if (( src_port == 152) || (dest_port == 152)) {

         printf("Protocol Type: Background File Transfer Program(BFTP)\n");
         return 1;

     }  else if (( src_port == 153) || (dest_port == 153)) {

         printf("Protocol Type: Simple Gateway Monitiring Protocol(SGMP)\n");
         return 1;

     } else if (( src_port == 161) || (dest_port == 161)) {

         printf("Protocol Type: Simple Network Management Protocol(SNMP)\n");
         return 1;

     } else if (( src_port == 162) || (dest_port == 162)) {

         printf("Protocol Type: SNMP TRAP\n");
         return 1;

     } else if (( src_port == 179) || (dest_port == 179)) {

         printf("Protocol Type: Border Gateway Protocol(BGP)\n");
         return 1;

     } else if (( src_port == 190) || (dest_port == 190)) {

         printf("Protocol Type: Gateway Access Control Protocol(GACP)\n");
         return 1;

     } else if (( src_port == 194) || (dest_port == 194)) {

         printf("Protocol Type: Internet Relay Chat(IRC)\n");
         return 1;

     } else if (( src_port == 197) || (dest_port == 197)) {

         printf("Protocol Type: Directory Location Service(DLS)\n");
         return 1;

     } else if (( src_port == 198) || (dest_port == 198)) {

         printf("Protocol Type: Directory Location Service Monitor (DLS-mon)\n");
         return 1;

     } else if (( src_port == 199) || (dest_port == 199)) {

         printf("Protocol Type: SMUX\n");
         return 1;

     } else if (( src_port == 209) || (dest_port == 209)) {

         printf("Protocol Type: Quick Mail Transfer Protocol(QMTP)\n");
         return 1;

     }  else if (( src_port == 218) || (dest_port == 218)) {

         printf("Protocol Type: Message Posting Protocol(MPP)\n");
         return 1;

     } else if (( src_port == 220) || (dest_port == 220)) {

         printf("Protocol Type: Internet Mail Access Protocol(IMAP v3)\n");
         return 1;

     } else if (( src_port == 246) || (dest_port == 246)) {

         printf("Protocol Type: Display Systems Protocol\n");
         return 1;

     } else if (( src_port == 257) || (dest_port == 257)) {

         printf("Protocol Type: Secure Electronics Transaction(SET)\n");
         return 1;

     } else if (( src_port == 259) || (dest_port == 259)) {

         printf("Protocol Type: Efficient Short Remote Operations(ESRO)\n");
         return 1;

     } else if (( src_port == 264) || (dest_port == 264)) {

         printf("Protocol Type: Border Gateway Multicast Protocol(BGMP)\n");
         return 1;

     }  else if (( src_port == 318) || (dest_port == 318)) {

         printf("Protocol Type: Time Stamp Protocol\n");
         return 1;

     } else if (( src_port == 321) || (dest_port == 321)) {

         printf("Protocol Type: PIP\n");
         return 1;

     } else if (( src_port == 322) || (dest_port == 322)) {

         printf("Protocol Type: RTSPS\n");
         return 1;

     } else if (( src_port == 359) || (dest_port == 359)) {

         printf("Protocol Type: Network Security Risk Management Protocol(NSRMP)\n");
         return 1;

     } else if (( src_port == 363) || (dest_port == 363)) {

         printf("Protocol Type: RSVP Tunnel\n");
         return 1;

     } else if (( src_port == 366) || (dest_port == 366)) {

         printf("Protocol Type: On Demand Mail Relay(ODMR)\n");
         return 1;

     } else if (( src_port == 389) || (dest_port == 389)) {

         printf("Protocol Type: Lightweight Directory Access Protocol(LDAP)\n");
         return 1;

     } else if (( src_port == 406) || (dest_port == 406)) {

         printf("Protocol Type: Interactive Mail Support Protocol(IMSP)\n");
         return 1; 

     } else if (( src_port == 413) || (dest_port == 413)) {

         printf("Protocol Type: Storage Management Services Protocol(SMSP)\n");
         return 1;

     } else if (( src_port == 427) || (dest_port == 427)) {

         printf("Protocol Type: Server Location\n");
         return 1;

     } else if (( src_port == 440) || (dest_port == 440)) {

         printf("Protocol Type: Simple Gateway Control Protocol(SGCP)\n");
         return 1;

     } else if (( src_port == 443) || (dest_port == 443)) {

         printf("Protocol Type: HTTPS\n");
         return 1;

     } else if (( src_port == 444) || (dest_port == 444)) {

         printf("Protocol Type: Simple Network Paging Protocol(SNPP)\n");
         return 1;

     } else if (( src_port == 468) || (dest_port == 468)) {

         printf("Protocol Type: Photuris\n");
         return 1;

     } else if (( src_port == 469) || (dest_port == 469)) {

         printf("Protocol Type: Radio Control Protocol(RCP)\n");
         return 1;

     } else if (( src_port == 501) || (dest_port == 501)) {

         printf("Protocol Type: STMF\n");
         return 1;

     } else if (( src_port == 510) || (dest_port == 510)) {

         printf("Protocol Type: FirstClass Protocol(FCP)\n");
         return 1;

     } else if (( src_port == 520) || (dest_port == 520)) {

         printf("Protocol Type: Routing Information Protocol(RIP)\n");
         return 1;

     } else if (( src_port == 521) || (dest_port == 521)) {

         printf("Protocol Type: RIPng\n");
         return 1;

     } else if (( src_port == 537) || (dest_port == 537)) {

         printf("Protocol Type: Networked Media Streaming Protocol(NMSP)\n");
         return 1;

     } else if (( src_port == 554) || (dest_port == 554)) {

         printf("Protocol Type: Real Time Streaming Protocol(RTSP)\n");
         return 1;

     } else if (( src_port == 563) || (dest_port == 563)) {

         printf("Protocol Type: Networks News Transfer Protocol over TLS/SSL\n");
         return 1;

     }  else if (( src_port == 575) || (dest_port == 575)) {

         printf("Protocol Type: VErsatile MultiMedia Interface(VEMMI)\n");
         return 1;

     } else if (( src_port == 581) || (dest_port == 581)) {

         printf("Protocol Type: Bundle Discovery Protocol(BDP)\n");
         return 1;

     } else if (( src_port == 603) || (dest_port == 603)) {

         printf("Protocol Type: Intrusion Detection Exchange Protocol(IDXP)\n");
         return 1;

     } else if (( src_port == 604) || (dest_port == 604)) {

         printf("Protocol Type: TUNNEL\n");
         return 1;

     } else if (( src_port == 605) || (dest_port == 605)) {

         printf("Protocol Type: Simple Object Access Protocol(SOAP) over BEEP\n");
         return 1;

     } else if (( src_port == 608) || (dest_port == 608)) {

         printf("Protocol Type: Sender-Initiated/Unsolicited File Transfer(SIFT/UFT)\n");
         return 1;

     } else if (( src_port == 614) || (dest_port == 614)) {

         printf("Protocol Type: SSLshell\n");
         return 1;

     } else if (( src_port == 631) || (dest_port == 631)) {

         printf("Protocol Type: Internet Printing Protocol(IPP)\n");
         return 1;

     } else if (( src_port == 639) || (dest_port == 639)) {

         printf("Protocol Type: Multicast Source Discovery Protocol(MSDP)\n");
         return 1;

     } else if (( src_port == 646) || (dest_port == 646)) {

         printf("Protocol Type: Label Distribution Protocol(LDP)\n");
         return 1;

     } else if (( src_port == 647) || (dest_port == 647)) {

         printf("Protocol Type: DHCP Failover\n");
         return 1;

     } else if (( src_port == 648) || (dest_port == 648)) {

         printf("Protocol Type: Registry Registrar Protocol(RRP)\n");
         return 1;

     } else if (( src_port == 674) || (dest_port == 674)) {

         printf("Protocol Type: Application Configuration Access Protocol(ACAP)\n");
         return 1;

     } else if (( src_port == 677) || (dest_port == 677)) {

         printf("Protocol Type: Virtual Presence Protocol(VPP)\n");
         return 1;

     } else if (( src_port == 698) || (dest_port == 698)) {

         printf("Protocol Type: Optimized Link State Routing(OLSR)\n");
         return 1;

     } else if (( src_port == 700) || (dest_port == 700)) {

         printf("Protocol Type: Extensible Provisioning Protocol(EPP)\n");
         return 1;

     } else if (( src_port == 701) || (dest_port == 701)) {

         printf("Protocol Type: Link Management Protocol(LMP)\n");
         return 1;

     } else if (( src_port == 702) || (dest_port == 702)) {

         printf("Protocol Type: IRIS over BEEP\n");
         return 1;

     } else if (( src_port == 706) || (dest_port == 706)) {

         printf("Protocol Type: Secure Internet Live Conferencing(SILC)\n");
         return 1;

     } else if (( src_port == 716) || (dest_port == 716)) {

         printf("Protocol Type: Protocol for Carrying Authentication for Network Access(PANA)\n");
         return 1;

     } else if (( src_port == 829) || (dest_port == 829)) {

         printf("Protocol Type: Certificate Management Protocol(CMP)\n");
         return 1;

     } else if (( src_port == 830) || (dest_port == 830)) {

         printf("Protocol Type: Network Configuration Protocol(NETCONF) over SSH\n");
         return 1;

     } else if (( src_port == 831) || (dest_port == 831)) {

         printf("Protocol Type: Network Configuration Protocol(NETCONF) over BEEP\n");
         return 1;

     } else if (( src_port == 832) || (dest_port == 832)) {

         printf("Protocol Type: Network Configuration Protocol(NETCONF) for SOAP over HTTPS\n");
         return 1;

     } else if (( src_port == 833) || (dest_port == 833)) {

         printf("Protocol Type: Network Configuration Protocol(NETCONF) for SOAP over BEEP\n");
         return 1;

     } else if (( src_port == 847) || (dest_port == 847)) {

         printf("Protocol Type: DHCP Failover 2\n");      
         return 1;

     } else if (( src_port == 848) || (dest_port == 848)) {

         printf("Protocol Type: Group Domain of Interpretation(GDOI)\n");
         return 1;

     }  else if (( src_port == 860) || (dest_port == 860)) {

         printf("Protocol Type: Internet Small Computer System Interface(iSCSI)\n");
         return 1;

     } else if (( src_port == 861) || (dest_port == 861)) {

         printf("Protocol Type: One-way Active Measurement Protocol(OWAMP)\n");
         return 1;

     } else if (( src_port == 862) || (dest_port == 862)) {

         printf("Protocol Type: Two-way Active Measurement Protocol(TWAMP) Control\n");
         return 1;

     } else if (( src_port == 873) || (dest_port == 873)) {

         printf("Protocol Type: rsync\n");
         return 1;

     } else if (( src_port == 910) || (dest_port == 910)) {

         printf("Protocol Type: Kerberized Internet Negotiation of Keys(KINK)\n");
         return 1;

     } else if (( src_port == 912) || (dest_port == 912)) {

         printf("Protocol Type: Application Exchange Core(APEX) relay-relay service\n");
         return 1;

     } else if (( src_port == 913) || (dest_port == 913)) {

         printf("Protocol Type: Application Exchange Core(APEX) endpoint-relay service\n");
         return 1;

     }  else if (( src_port == 989) || (dest_port == 989)) {

         printf("Protocol Type: FTP data over TLS/SSL\n");
         return 1;

     } else if (( src_port == 990) || (dest_port == 990)) {

         printf("Protocol Type: FTP control over TLS/SSL\n");
         return 1;

     } else if (( src_port == 991) || (dest_port == 991)) {

         printf("Protocol Type: Netnews Administration System\n");
         return 1;

     } else if (( src_port == 992) || (dest_port == 992)) {

         printf("Protocol Type: TELNET over TLS/SSL\n");
         return 1;

     } else if (( src_port == 993) || (dest_port == 993)) {

         printf("Protocol Type: IMAP4 over TLS/SSL\n");
         return 1;

     } else if (( src_port == 994) || (dest_port == 994)) {

         printf("Protocol Type: IRC over TLS/SSL\n");
         return 1;

     } else if (( src_port == 995) || (dest_port == 995)) {

         printf("Protocol Type: POP3 over TLS/SSL\n");
         return 1;

     } else if (( src_port == 1010) || (dest_port == 1010)) {

         printf("Protocol Type: SURF\n");
         return 1;

     } else if (( src_port == 1026) || (dest_port == 1026)) {

         printf("Protocol Type: Calendar Access Protocol(CAP)\n");
         return 1;

     } else if (( src_port == 1036) || (dest_port == 1036)) {

         printf("Protocol Type: Nebula Secure Segment Transfer Protocol(NSSTP) \n");
         return 1;

     } else if (( src_port == 1037) || (dest_port == 1037)) {

         printf("Protocol Type: AMS\n");
         return 1;

     } else if (( src_port == 1038) || (dest_port == 1038)) {

         printf("Protocol Type: Message Tracking Query Protocol(MTQP)\n");
         return 1;

     } else if (( src_port == 1045) || (dest_port == 1045)) {

         printf("Protocol Type: Fingerprint Image Transfer Protocol(FPITP)\n");
         return 1;

     } else if (( src_port == 1052) || (dest_port == 1052)) {

         printf("Protocol Type: Dynamic DNS Tools\n");
         return 1;

     } else if (( src_port == 1077) || (dest_port == 1077)) {

         printf("Protocol Type: IMGames\n");
         return 1;

     } else if ((src_port == 1080) || (dest_port == 1080)) {

         printf("Protocol Type: SOCKS\n");
         return 1;

     } else if (( src_port == 1096) || (dest_port == 1096)) {

         printf("Protocol Type: Common Name Resolution Protocol(CNRP)\n");
         return 1;

     } else if (( src_port == 1112) || (dest_port == 1112)) {

         printf("Protocol Type: Intelligent Communication Protocol(ICP)\n");
         return 1;

     } else if (( src_port == 1118) || (dest_port == 1118)) {

         printf("Protocol Type: Securily Available Credentails(SACRED)\n");
         return 1;

     } else if (( src_port == 1155) || (dest_port == 1155)) {

         printf("Protocol Type: Network File Access\n");
         return 1;

     } else if (( src_port == 1214) || (dest_port == 1214)) {

         printf("Protocol Type: KAZAA\n");
         return 1;

     } else if (( src_port == 1344) || (dest_port == 1344)) {

         printf("Protocol Type: Internet Content Adaption Protocol(ICAP)\n");
         return 1;

     } else if ((src_port == 1626) || (dest_port == 1626)) {

         printf("Protocol Type: shock wave\n");
         return 1;

     }  else if (( src_port == 1649) || (dest_port == 1649)) {

         printf("Protocol Type: Kermit\n");
         return 1;

     }  else if (( src_port == 1723) || (dest_port == 1723)) {

         printf("Protocol Type: Point-to-Point Tunneling Protocol(PPTP)\n");
         return 1;

     } else if (( src_port == 1818) || (dest_port == 1818)) {

         printf("Protocol Type: Enhanced Trivial File Transfer Protocol(ETFTP)\n");
         return 1;

     } else if (( src_port == 1847) || (dest_port == 1847)) {

         printf("Protocol Type: Service Location Protocol(SLP)-Notification\n");
         return 1;

     } else if ((src_port == 1863) || (dest_port == 1863)) {

         printf("Protocol Type: MSNP\n");
         return 1;

     }  else if (( src_port == 1900) || (dest_port == 1900)) {

         printf("Protocol Type: Simple Service Discovery Protocol(SSDP)\n");
         return 1;

     } else if (( src_port == 1973) || (dest_port == 1973)) {

         printf("Protocol Type: Data Link Switching Remote Access Protocol(DLSRAP)\n");
         return 1;

     } else if (( src_port == 1985) || (dest_port == 1985)) {

         printf("Protocol Type: Hot Standby Router Protocol(HSRP)\n");
         return 1;

     } else if (( src_port == 2049) || (dest_port == 2049)) {

         printf("Protocol Type: Network File System(NFS)\n");
         return 1;

     } else if (( src_port == 2090) || (dest_port == 2090)) {

         printf("Protocol Type: Load Report Protocol\n");
         return 1;

     } else if (( src_port == 2106) || (dest_port == 2106)) {

         printf("Protocol Type: Multicast-Scope Zone Announcement Protocol(MZAP)\n");
         return 1;

     } else if (( src_port == 2110) || (dest_port == 2110)) {

         printf("Protocol Type: Unified Memory Space Protocol(UMSP)\n");
         return 1;

     } else if (( src_port == 2142) || (dest_port == 2142)) {

         printf("Protocol Type: TDM over IP(TDMoIP)\n");
         return 1;

     } else if (( src_port == 2164) || (dest_port == 2164)) {

         printf("Protocol Type: Dynamic DNS Version 3\n");
         return 1;

     } else if (( src_port == 2313) || (dest_port == 2313)) {

         printf("Protocol Type: Inter Access Point Protocol(IAPP)\n");
         return 1;

     }  else if (( src_port == 2427) || (dest_port == 2427)) {

         printf("Protocol Type: Multicast Gateway Control Protocol(MGCP)-gateway\n");
         return 1;

     } else if (( src_port == 2535) || (dest_port == 2535)) {

         printf("Protocol Type: Multicast Address Dynamic Client Allocation Protocol(MADCAP)\n");
         return 1;

     } else if (( src_port == 2587) || (dest_port == 2587)) {

         printf("Protocol Type: Multicast Address-Set Claim(MASC)\n");
         return 1;

     } else if (( src_port == 2641) || (dest_port == 2641)) {

         printf("Protocol Type: Handle System Protocol\n");
         return 1;

     } else if (( src_port == 2727) || (dest_port == 2727)) {

         printf("Protocol Type: Media Gateway Control Protocol Call Agent\n");
         return 1;

     } else if (( src_port == 2775) || (dest_port == 2775)) {

         printf("Protocol Type: Short Message Peer-to-Peer Protocol(SMPP)\n");
         return 1;

     } else if (( src_port == 2855) || (dest_port == 2855)) {

         printf("Protocol Type: Message Session Relay Protcol(MSRP)\n");
         return 1;

     } else if (( src_port == 2935) || (dest_port == 2935)) {

         printf("Protocol Type: Quick Transaction Protocol(QTP)\n");
         return 1;

     } else if (( src_port == 2980) || (dest_port == 2980)) {

         printf("Protocol Type: Instant Messaging Service\n");
         return 1;

     } else if (( src_port == 3088) || (dest_port == 3088)) {

         printf("Protocol Type: eXtensible Data Transfer Protocol(XDTP)\n");
         return 1;

     } else if (( src_port == 3130) || (dest_port == 3130)) {

         printf("Protocol Type: Internet Cache Protocol(ICP)\n");
         return 1;

     } else if (( src_port == 3145) || (dest_port == 3145)) {

         printf("Protocol Type: Light-weight Flow Admisssion Protocol(LFAP)\n");
         return 1;

     } else if (( src_port == 3205) || (dest_port == 3205)) {

         printf("Protocol Type: Internet Storage Name Service(iSNS)\n");
         return 1;

     } else if (( src_port == 3225) || (dest_port == 3225)) {

         printf("Protocol Type: Fibre Channel Over TCP/IP(FCIP)\n");
         return 1;

     }  else if (( src_port == 3260) || (dest_port == 3260)) {

         printf("Protocol Type: Internet Small Computer System Interface(iSCSI)\n");
         return 1;

     } else if (( src_port == 3305) || (dest_port == 3305)) {

         printf("Protocol Type: ODETTE-FTP\n");
         return 1;

     } else if (( src_port == 3372) || (dest_port == 3372)) {

         printf("Protocol Type: Transaction Internet Protocol(TIP)\n");
         return 1;

     } else if (( src_port == 3420) || (dest_port == 3420)) {

         printf("Protocol Type: Internet Fibre Channel Protocol(iFCP)\n");
         return 1;

     } else if (( src_port == 3478) || (dest_port == 3478)) {

         printf("Protocol Type: Session Traversal Utilities for NAT(STUN)\n");
         return 1;

     } else if (( src_port == 3550) || (dest_port == 3550)) {

         printf("Protocol Type: Secure SMPP\n");
         return 1;

     } else if (( src_port == 3567) || (dest_port == 3567)) {

         printf("Protocol Type: Object Access Protocol\n");
         return 1;

     } else if (( src_port == 3130) || (dest_port == 3130)) {

         printf("Protocol Type: Internet Cache Protocol(ICP)\n");
         return 1;

     } else if (( src_port == 3653) || (dest_port == 3653)) {

         printf("Protocol Type: Tunnel Setup Protocol(TSP) \n");
         return 1;

     }  else if (( src_port == 3693) || (dest_port == 3693)) {

         printf("Protocol Type: Generic Tunnel Tracing Protocol(GTTP)\n");
         return 1;
 
     } else if (( src_port == 3713) || (dest_port == 3713)) {

         printf("Protocol Type: TFTP over TLS\n");
         return 1;

     } else if (( src_port == 3740) || (dest_port == 3740)) {

         printf("Protocol Type: Heartbeat Protocol\n");
         return 1;

     } else if (( src_port == 3761) || (dest_port == 3761)) {

         printf("Protocol Type: Group Secure Association Key Management Protocol(GSAKMP)\n");
         return 1;

     } else if (( src_port == 3860) || (dest_port == 3860)) {

         printf("Protocol Type: Server/Application State Protocol(SASP)\n");
         return 1;

     } else if (( src_port == 3863) || (dest_port == 3863)) {

         printf("Protocol Type: Aggregate Server Access Protocol(ASAP)\n");
         return 1;

     } else if (( src_port == 3864) || (dest_port == 3864)) {

         printf("Protocol Type: ASAP over TLS\n");
         return 1;

     } else if (( src_port == 3905) || (dest_port ==3905)) {
 
         printf("Protocol Type: Mailbox Update(MUPDATE)\n");
         return 1;

     } else if (( src_port == 4043) || (dest_port == 4043)) {

         printf("Protocol Type: Neighbour Identitiy Resolution Protocol(NIRP)\n");
         return 1;

     } else if (( src_port == 4044) || (dest_port == 4044)) {

         printf("Protocol Type: Location Tracking Protocol(LTP)\n");
         return 1;

     } else if (( src_port == 4045) || (dest_port == 4045)) {

         printf("Protocol Type: Network Paging Protocol(NPP)\n");
         return 1;

     } else if (( src_port == 4069) || (dest_port == 4069)) {

         printf("Protocol Type: Minger\n");
         return 1;

     } else if (( src_port == 4189) || (dest_port == 4189)) {

         printf("Protocol Type: Path Computation Element Communication Protocol\n");
         return 1;

     } else if (( src_port == 4321) || (dest_port == 4321)) {

         printf("Protocol Type: Remote Who is\n");
         return 1;

     } else if (( src_port == 4486) || (dest_port == 4486)) {

         printf("Protocol Type: Integrated Client Message Service\n");
         return 1;

     } else if (( src_port == 4500) || (dest_port == 4500)) {

         printf("Protocol Type: IPsec NAT-Traversal\n");
         return 1;

     } else if (( src_port == 4555) || (dest_port == 4555)) {

         printf("Protocol Type: Realm Specific IP(RSIP)\n");
         return 1;

     }  else if (( src_port == 4590) || (dest_port == 4590)) {

         printf("Protocol Type: Real-time Inter-network Defense(RID) over HTTP/TLS\n");
         return 1;

     } else if (( src_port == 4739) || (dest_port == 4739)) {

         printf("Protocol Type: IP Flow Information Export(IPFIX)\n");
         return 1;

     } else if (( src_port == 4744) || (dest_port == 4744)) {

         printf("Protocol Type: Internet File Synchronization Protocol(IFSP)\n");
         return 1;

     } else if (( src_port == 4750) || (dest_port == 4750)) {

         printf("Protocol Type: Simple Service Auto Discovery(SSAD)\n");
         return 1;

     } else if (( src_port == 4751) || (dest_port == 4751)) {

         printf("Protocol Type: Simple Policy Control Protocol(SPOCP)\n");
         return 1;

     } else if (( src_port == 4752) || (dest_port == 4752)) {

         printf("Protocol Type: Simple Network Audio Protocol\n");
         return 1;

     } else if (( src_port == 4827) || (dest_port == 4827)) {

         printf("Protocol Type: Hyper Text Caching Protocol(HTCP)\n");
         return 1;

     } else if (( src_port == 5004) || (dest_port == 5004)) {

         printf("Protocol Type: Real Time Transport Protocol(RTP)\n");
         return 1;

     } else if (( src_port == 5005) || (dest_port == 5005)) {

         printf("Protocol Type: Real Time Transport Control Protocol(RTCP)\n");
         return 1;

     } else if (( src_port == 5031) || (dest_port == 5031)) {

         printf("Protocol Type: Direct Message Protocol(DMP)\n");
         return 1;

     } else if (( src_port == 5059) || (dest_port == 5059)) {

         printf("Protocol Type: SIP Directory Services(SDS)\n");
         return 1;

     } else if (( src_port == 5060) || (dest_port == 5060)) {

         printf("Protocol Type: Session Initiation Protocol(SIP)\n");
         return 1;

     } else if (( src_port == 5061) || (dest_port == 5061)) {

         printf("Protocol Type: SIP-TLS\n");
         return 1;

     } else if (( src_port == 5150) || (dest_port == 5150)) {

         printf("Protocol Type: Ascend Tunnel Management Protocol\n");
         return 1;

     } else if (( src_port == 5161) || (dest_port == 5161)) {

         printf("Protocol Type: SNMP over SSH\n");
         return 1;

     } else if (( src_port == 5162) || (dest_port == 5162)) {

         printf("Protocol Type: SNMP traps over SSH\n");
         return 1;

     } else if (( src_port == 5222) || (dest_port == 5222)) {

         printf("Protocol Type: eXtensible Messaging and Presence Protocol(XMPP client)\n");
         return 1;

     } else if (( src_port == 5269) || (dest_port == 5269)) {

         printf("Protocol Type: eXtensible Messaging and Presence Protocol(XMPP server)\n");
         return 1;

     }  else if (( src_port == 5349) || (dest_port == 5349)) {

         printf("Protocol Type: STUN over TLS\n");
         return 1;

     }  else if (( src_port == 5350) || (dest_port == 5350)) {

         printf("Protocol Type: NAT-PMP Status Announcements\n");
         return 1;

     } else if (( src_port == 5351) || (dest_port == 5351)) {

         printf("Protocol Type: NAT Port Mapping Port(NAT-PMP)\n");
         return 1;

     }  else if (( src_port == 5353) || (dest_port == 5353)) {

         printf("Protocol Type: Multicast DNS(MDNS)\n");
         return 1;

     }  else if (( src_port == 5355) || (dest_port == 5355)) {

         printf("Protocol Type: Link Local Multicast Name Resolution(LLMNR)\n");
         return 1;

     }  else if (( src_port == 5567) || (dest_port == 5567)) {

         printf("Protocol Type: Multicast Object Access Protocol(M-OAP)\n");
         return 1;

     }  else if (( src_port == 5568) || (dest_port == 5568)) {

         printf("Protocol Type: Session Data Transport Multicast(SDT)\n");
         return 1;

     }  else if (( src_port == 5573) || (dest_port == 5573)) {

         printf("Protocol Type: SAS Domain Management Messaging Protocol(SDMMP)\n");
         return 1;

     }  else if (( src_port == 5900) || (dest_port == 5900)) {

         printf("Protocol Type: Remote Framebuffer Protocol(RFP)\n");
         return 1;

     } else if (( src_port == 6069) || (dest_port == 6069)) {

         printf("Protocol Type: Telephone Routing over IP(TRIP)\n");
         return 1;

     } else if (( src_port == 6346) || (dest_port == 6346)) {

         printf("Protocol Type: Gnutella-svc\n");
         return 1;

     }  else if (( src_port == 6347) || (dest_port == 6347)) {

         printf("Protocol Type: Gnutella-rtr\n");
         return 1;

     }  else if (( src_port == 6513) || (dest_port == 6513)) {

         printf("Protocol Type: Network Configuration Protocol(NETCONF) over TLS\n");
         return 1;

     } else if (( src_port == 6622) || (dest_port == 6622)) {

         printf("Protocol Type: Multicast FTP\n");
         return 1;

     } else if (( src_port == 7070) || (dest_port == 7070)) {

         printf("Protocol Type: ARCP\n");
         return 1;

     } else if (( src_port == 7549) || (dest_port == 7549)) {

         printf("Protocol Type: Network Layer Signaling Transport layer\n");
         return 1;

     } else if (( src_port == 7560) || (dest_port == 7560)) {

         printf("Protocol Type: Sniffer Command Protocol(SNCP)\n");
         return 1;

     } else if (( src_port == 7626) || (dest_port == 7626)) {

         printf("Protocol Type: SImple Middlebox COnfiguration(SIMCO)\n");
         return 1;

     } else if (( src_port == 7744) || (dest_port == 7744)) {

         printf("Protocol Type: Real-time Application Quality-of-Service Monitoring(RAQMON)\n");
         return 1;

     } else if (( src_port == 7801) || (dest_port == 7801)) {

         printf("Protocol Type: Secure Server Protocol(SSP)\n");
         return 1;

     } else if (( src_port == 8087) || (dest_port == 8087)) {

         printf("Protocol Type: Simplify Media SPP Protocol\n");
         return 1;

     } else if (( src_port == 8128) || (dest_port == 8128)) {

         printf("Protocol Type: PayCash Online Protocol\n");
         return 1;

     } else if (( src_port == 8148) || (dest_port == 8148)) {

         printf("Protocol Type: i-SDD File Transfer\n");
         return 1;

     } else if (( src_port == 8416) || (dest_port == 8416)) {

         printf("Protocol Type: eSpeech Session Protocol\n");
         return 1;

     } else if (( src_port == 8417) || (dest_port == 8417)) {

         printf("Protocol Type: eSpeech RTP Protocol\n");
         return 1;

     } else if (( src_port == 8770) || (dest_port == 8770)) {

         printf("Protocol Type: Digital Photo Access Protocol(DPAP)\n");
         return 1;

     } else if (( src_port == 9598) || (dest_port == 9598)) {

         printf("Protocol Type: Very Simple Control Protocol(VSCP)\n");
         return 1;

     } else if (( src_port == 9875) || (dest_port == 9875)) {

         printf("Protocol Type: Session Announcement Protocol(SAP)\n");
         return 1;

     } else if (( src_port == 19999) || (dest_port == 19999)) {

         printf("Protocol Type: Distributed Network Protocol-secure\n");
         return 1;

     } else if (( src_port == 20000) || (dest_port == 20000)) {

         printf("Protocol Type: Distributed Network Protocol(DNP)\n");
         return 1;

     } else if (( src_port == 44323) || (dest_port == 44323)) {

         printf("Protocol Type: Port Control Protocol(PCP)\n");
         return 1;

     } else if (( src_port == 47000) || (dest_port == 47000)) {

         printf("Protocol Type: Message Bus(Mbus)\n");
         return 1;

     } else {

         return 0;
     }
}  
