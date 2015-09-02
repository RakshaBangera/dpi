#include<stdio.h>
#include<stdlib.h>

struct ftp_node
{
    unsigned long ip1;
    unsigned long ip2;
    unsigned char ip_protocol;
    unsigned short port;
    struct ftp_node *link;
};
typedef struct ftp_node *p_node;
p_node first = NULL;

void ftp_insert(unsigned long ip1, unsigned long ip2, unsigned char ip_protocol,
            unsigned short port)
{   
     p_node temp, cur;
     temp = (p_node)malloc(sizeof(struct ftp_node));

     if (temp != NULL) {

         temp->ip1 = ip1;
         temp->ip2 = ip2;
         temp->ip_protocol = ip_protocol;
         temp->port = port;
         temp->link = NULL;

     } else {

         printf("Out of memory\n");
         return;

     } 
     if (first == NULL) {

         first = temp;

     } else {

         cur = first;
         while (cur->link != NULL) {
             cur = cur->link;
         }
         cur->link = temp;

     }
}

int ftp_search(unsigned long ip1, unsigned long ip2, unsigned char ip_protocol,
               unsigned short p1, unsigned short p2)
{
     p_node cur;
     
     if (first == NULL) {
         return 0;
     }
     cur = first;
     while (cur != NULL) {

         if (((cur->ip1 == ip1)||(cur->ip1 == ip2)) &&
             ((cur->ip2 == ip1)||(cur->ip2 == ip2)) &&
             (cur->ip_protocol == ip_protocol) &&
             ((cur->port == p1) || (cur->port == p2))) {
             return 1;
         } else {
             cur = cur->link;
         }
     }
     return 0;
}

void ftp_delete(unsigned long ip1, unsigned long ip2, unsigned char ip_protocol,              unsigned short p1, unsigned short p2)
{
     p_node cur, prev;
      
     if (first == NULL) {
         return;
     }
     cur = first;
     prev = NULL;
     while (cur != NULL) {

         if (((cur->ip1 == ip1)||(cur->ip1 == ip2)) &&
             ((cur->ip2 == ip1)||(cur->ip2 == ip2)) &&
             (cur->ip_protocol == ip_protocol) &&
             ((cur->port == p1) || (cur->port == p2))) {

             if (cur == first) {

                 first = cur->link;
                 free(cur);
                 cur = first;

             } else {

                 prev->link = cur->link;
                 free(cur);
                 cur = cur->link;

             }
             return;

         } else {

             prev = cur;
             cur = cur->link;

         }
     }
}


    
     
                
