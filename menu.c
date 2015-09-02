#include<string.h>
#include<stdlib.h>
#include<stdio.h>
int debug_flag, debug_verbose, packet_classified, packet_unclassified;

display_menu()
{  
    int i;
    char s[100];
    char f[100];

    printf("\nRouter> ");
    gets(s);             /*read the command */
               
    switch(s[0]) 
    {
    case '?':
    case 'h':
        if (!strcmp(s,"help") || !strcmp(s,"?"))                /* help command */
        {      
            printf("\nList of available commands:\n");
            printf("load cap<filename>    - Load file\n");
            printf("enable debug verbose  - displays verbose statements\n");
            printf("disable debug verbose - hides verbose statements\n");
            printf("set debug mode        - dumps packet contents\n");
            printf("reset debug mode      - hides packet contents\n");
            printf("quit                  - exit program\n");
        }
        else
        {
            printf("You have typed\n");
            puts(s);
        }
        break;

    case 'l':
        printf("You have typed %s\n", s);                 /*load cap command */
        
        if (strcmp(s,"load cap")>0) 
        {
            for (i = 0;i < 90;i++)
            {
                f[i]=s[i+9];
            }
            printf("\nFile Name : %s\n",f);
            packet_classified = packet_unclassified = 0;
            load_capture(f);
        } 
        else 
        {
             printf("You have typed %s\n", s);
        }
         break;

    case 'd':
        if (!strcmp(s,"disable debug verbose")) {
            debug_verbose = 0;
        } else {
            printf("You have typed %s\n", s);
        }
        break;

    case 'e':
        if (!strcmp(s,"enable debug verbose")) {
            debug_verbose = 1;
        } else {
            printf("You have typed %s\n", s);
        }
        break;

    case 'r':
        if (!strcmp(s,"reset debug mode")) {
            debug_flag = 0;
        } else {
            printf("You have typed %s\n", s);
        }
        break;

    case 's':        
        if (!strcmp(s,"set debug mode")) {
            debug_flag = 1;
        } else {
            printf("You have typed %s\n", s);
        }
        break;

    case 'q':
        if (!strcmp(s,"quit"))
        {                         /* quit command */
            exit(0);
        }

    default:
        printf("You have typed\n");
        puts(s);
        break;
    }
}

