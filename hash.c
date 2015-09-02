#include <stdio.h>
#include <stdlib.h>
#include"types.h"
#define hsize 2048

unsigned int hkey;
int count;
NODE htable[hsize];

NODE search(unsigned long bigger_ip, unsigned long smaller_ip,
            unsigned char ip_protocol, unsigned short bigger_port,
            unsigned short smaller_port);


void init_hash()
{
     int i;
     
     /* Initialize the hash table */
     for (i=0; i<hsize; i++) {
         htable[i] = NULL;
     }
}

NODE getnode()
{
     NODE x;
     x = (NODE) malloc (sizeof(struct node_));
     return x;
}

unsigned int hash(NODE x)
{
     unsigned int sum = 0;     
     unsigned int key = 0;
     
     sum = x->bigger_ip + x->smaller_ip + x->ip_protocol + x->bigger_port + 
           x->smaller_port;
     key = sum % hsize;
     return key;
}

void insert(unsigned long bigger_ip, unsigned long smaller_ip, 
            unsigned char ip_protocol, unsigned short bigger_port, 
            unsigned short smaller_port, unsigned int syn, 
            unsigned int syn_ack, unsigned int ack,
            unsigned int protocol_type)
{    
     NODE temp, cur;

     temp = getnode();
     if (temp == NULL) {                 

          printf("Out of Memory\n");

     } else {

          temp->bigger_ip = bigger_ip;
          temp->smaller_ip = smaller_ip;
          temp->ip_protocol = ip_protocol;
          temp->bigger_port = bigger_port;
          temp->smaller_port = smaller_port;
          temp->syn = syn;
          temp->syn_ack = syn_ack;
          temp->ack = ack;
          temp-> protocol_type = protocol_type;
          temp->next=NULL;

          hkey = hash(temp);
          if (htable[hkey] == NULL) {

              htable[hkey] = temp;

          } else {

	      cur = htable[hkey];
	      while (cur->next != NULL) {
	          cur = cur->next;
	      }       
              cur->next = temp;

          }
     }
}

void delete(unsigned long bigger_ip, unsigned long smaller_ip, 
            unsigned char ip_protocol, unsigned short bigger_port, 
            unsigned short smaller_port)
{
     NODE temp, prev, cur;

     temp = getnode();
     if (temp == NULL) {

          printf("Out of memory\n");

     } else {

          temp->bigger_ip = bigger_ip;
          temp->smaller_ip = smaller_ip;
          temp->ip_protocol = ip_protocol;
          temp->bigger_port = bigger_port;
          temp->smaller_port = smaller_port;

          hkey = hash(temp);
          cur = htable[hkey];
          prev = NULL;
          
          if (cur == NULL) {

              printf("The bucket is empty\n");
              return;

          }
          
          if ((temp->bigger_ip == cur->bigger_ip) &&
              (temp->smaller_ip == cur->smaller_ip) &&
              (temp->ip_protocol == cur->ip_protocol) &&
              (temp->bigger_port == cur->bigger_port) &&
              (temp->smaller_port == cur->smaller_port)) {
                  
              htable[hkey] = cur->next;
              free(cur);
              return;

          }
          while (cur != NULL) {

              if ((temp->bigger_ip == cur->bigger_ip) &&
                  (temp->smaller_ip == cur->smaller_ip) &&
                  (temp->ip_protocol == cur->ip_protocol) &&
                  (temp->bigger_port == cur->bigger_port) &&
                  (temp->smaller_port == cur->smaller_port)) {

                  break;  

              }
              prev = cur;
              cur = cur->next;

          }
          if (cur == NULL) {

              printf("Specified tuple was not found\n");

          } else {

              prev->next = cur->next;
              free(cur);

          }
     }
}

NODE search(unsigned long bigger_ip, unsigned long smaller_ip, 
            unsigned char ip_protocol, unsigned short bigger_port, 
            unsigned short smaller_port)
{    
      NODE temp,cur;

      temp = getnode();
      if (temp == NULL) {

          printf("Out of memory\n");
          return NULL;

      } else {

          temp->bigger_ip = bigger_ip;
          temp->smaller_ip = smaller_ip;
          temp->ip_protocol = ip_protocol;
          temp->bigger_port = bigger_port;
          temp->smaller_port = smaller_port;
          hkey = hash(temp);
          cur = htable[hkey];
          while (cur != NULL) {

              if ((temp->bigger_ip == cur->bigger_ip)&&
                  (temp->smaller_ip == cur->smaller_ip)&&
                  (temp->ip_protocol == cur->ip_protocol)&&
                  (temp->bigger_port == cur->bigger_port)&&
                  (temp->smaller_port == cur->smaller_port)) {

                  return cur;

	      } else {

	          cur = cur->next;

	      } 
          }
          return NULL;
    }
}

void display()
{
      NODE temp;
         
      for (hkey = 0; hkey < hsize; hkey++) {

          temp = htable[hkey];
          if (htable[hkey] != NULL) {

              printf("\nhtable[ %d ]\n",hkey);

          }
          while(temp != NULL) {

              printf("\nBigger ip = %x\n",temp->bigger_ip);
              printf("Smaller ip = %x\n",temp->smaller_ip);
              printf("IP protocol = %x\n",temp->ip_protocol);
              printf("Bigger port = %hu\n",temp->bigger_port);
              printf("Smaller port = %hu\n",temp->smaller_port);
              printf("SYN = %d\n", temp->syn);
              printf("SYN-ACK = %d\n", temp->syn_ack);
              printf("ACK = %d\n", temp->ack);
              printf("Protocol type=%d\n",temp->protocol_type);
              getchar();
              temp = temp->next;

          }
      }
}
