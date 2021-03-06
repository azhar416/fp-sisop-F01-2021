#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#define PORT 8080

char namaUser[1024];
  
int main(int argc, char const *argv[]) 
{
    struct sockaddr_in address;
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buffer[1024] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        printf("\n Socket creation error \n");
        return -1;
    }
        
    memset(&serv_addr, '0', sizeof(serv_addr));
        
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
        
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    
    int uid = getuid();    
    char struid[10]; 
    sprintf(struid, "%d", uid);
    send(sock, struid, strlen(struid), 0); // Ngirim UID
        
    if (uid != 0) 
    {
        read(sock, buffer, 1024); 
        bzero(buffer, 1024);
        sprintf(buffer, "%s:%s\n", argv[2], argv[4]);
        send(sock, buffer, strlen(buffer), 0);
    }
        
    if (uid == 0)
		strcpy(namaUser, "Root");
	else 
		strcpy(namaUser, argv[2]);

    bzero(buffer, 1024);
    read(sock, buffer, 1024);
    
    printf("%s\n", buffer);
    
    if (strcmp(buffer, "Invalid Username or Password!") == 0) {
            return 0;
    }
    char query[255];
    // Start Here
    while (1) 
    {
        printf("Acces[%s]> ", namaUser);
        scanf(" %[^\n]", query);
        send(sock, query, strlen(query), 0);

        bzero(buffer, 1024);
        read(sock, buffer, 1024);

        printf("%s\n", buffer);
    }
    
    return 0;
}