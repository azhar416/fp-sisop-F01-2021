#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dirent.h>
#define PORT 8080

int server_fd, new_socket, valread;
struct sockaddr_in address;
int opt = 1;
int addrlen = sizeof(address);
 
char folderDatabase[] = "Database";
char fileUser[] = "Database/user/user.txt";
char currentDB[1024] = {0};
int isRoot = 0;
int acc = 0;
 
struct login {
    char id[1024];
    char password[1024];
} login;

// login
void reconnect();
int autentikasi(char str[]);

// query
char* create_user(char str[]);
char* use(char str[]);
char* grant_permission(char str[]);
char* create_database(char str[]);
char* drop_database(char str[]);

// common use
void create_file(char filePath[], char str[], char mode[]);
 
int main() 
{
    // pid_t pid, sid;
    // pid = fork();

    // if (pid < 0) {
    //         exit(EXIT_FAILURE);
    // }
    
    // if (pid > 0) {
    //         exit(EXIT_SUCCESS);
    // }
    
    // umask(0);

    // sid = setsid();
    // if (sid < 0) {
    //         exit(EXIT_FAILURE);
    // }

    // if ((chdir("/")) < 0) {
    //     exit(EXIT_FAILURE);
    // }
    
    // close(STDIN_FILENO);
    // close(STDOUT_FILENO);
    // close(STDERR_FILENO);

    char buffer[1024] = {0}, msg[1024] = {};
        
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
        
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
        
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
        
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
        
    reconnect();
        
    mkdir("Database", 0777);
    mkdir("Database/user", 0777);
    FILE* file = fopen(fileUser, "a");
    if(file) fclose(file);
       
    while (1) {
        bzero(buffer, 1024);
        valread = read(new_socket, buffer, 1024);
        
        // kalo client 
        if (!valread)
        {
            acc = 0;
            isRoot = 0;
            reconnect();
            continue;
        }
        // debug
        printf("<%s>\n", buffer);

        if (buffer[strlen(buffer) - 1] != ';')
        {
			// printf("%c\n", buffer[strlen(buffer) - 1]);
            strcpy(msg, "SYNTAX ERROR!");
        }
        else if (!strncmp(buffer, "CREATE USER", 11))
        {
            if (isRoot)
            {
                strcpy(msg, create_user(buffer));
            }
            else
            {
                strcpy(msg, "COMMAND DENIED!");
            }
        }
        else if (!strncmp(buffer, "GRANT PERMISSION", 16))
        {
            if (isRoot)
            {
                strcpy(msg, grant_permission(buffer));
            }
            else
            {
                strcpy(msg, "COMMAND DENIED");
            }
        }
        else if (!strncmp(buffer, "USE", 3))
        {
            strcpy(msg, use(buffer));
        }
		else if (!strncmp(buffer, "CREATE DATABASE", 15))
		{
			strcpy(msg, create_database(buffer));
		}
		else if (!strncmp(buffer, "DROP DATABASE", 13))
		{
			strcpy(msg, drop_database(buffer));
		}
        else
        {
            strcpy(msg, "QUERY NOT AVAILABLE!");
        }
        /////////////////////////////////////
        send(new_socket, msg, strlen(msg), 0);
    }

    return 0;
}

int remove_directory(const char *path) {
	DIR* d = opendir(path);
	size_t path_len = strlen(path);
	int r = -1;
	if (!d)
		return 1;
   	if (d) {
		struct dirent *p;

		r = 0;
		while (!r && (p=readdir(d))) {
          	int r2 = -1;
			char *buf;
			size_t len;

			/* Skip the names "." and ".." as we don't want to recurse on them. */
			if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
				continue;

			len = path_len + strlen(p->d_name) + 2; 
			buf = malloc(len);

			if (buf) {
				struct stat statbuf;

				snprintf(buf, len, "%s/%s", path, p->d_name);
				if (!stat(buf, &statbuf)) {
					if (S_ISDIR(statbuf.st_mode))
					r2 = remove_directory(buf);
					else
					r2 = unlink(buf);
				}
				free(buf);
			}
			r = r2;
		}
		closedir(d);
	}

	if (!r)
		r = rmdir(path);

	return r;
}

char* drop_database(char str[])
{
	char* ptr;
	char msg[1024];

	// namadb
	char namadb[1024];
	bzero(namadb, 1024);

	// parse
	int i;
	char parse[1024];
	strcpy(parse, str);
	char* parseptr = parse;
	char* token;

	// DROP DATABASE [nama_database];
	for (i = 0; token = strtok_r(parseptr, " ", &parseptr); i++)
	{
		if (i == 2)
		{
			strncpy(namadb, token, strlen(token) - 1);
			// printf("aasadssadads\n");
		}
	}
	// printf("db : %s\n", namadb);

	char databasepath[1024];
	sprintf(databasepath, "%s/%s", folderDatabase, namadb);
	char* pathdbptr = databasepath;

	if (!opendir(databasepath))
	{
		strcpy(msg, "DATABASE NOT EXIST!");
		ptr = msg;
		return ptr;
	}

	// printf("%s\n", databasepath);
	char permissionfile[1024];
	strcpy(permissionfile, databasepath);
	strcat(permissionfile, "/granted_user.txt");

	printf("%s\n", databasepath);

	FILE* file = fopen(permissionfile, "r");
	char line [1024];
	bzero(line, 1024);
	int perm = 0;

	// printf("%s\n", login.id);
	while (fgets(line, 1024, file))
	{
		if (!strncmp(line, login.id, strlen(login.id)))
		{
			perm = 1;
			break;
		}
	}

	// printf("%d\n", perm);

	if (perm)
	{
		int rm = remove_directory(databasepath);
		strcpy(msg, "DROP DATABASE SUCCESS!");
		ptr = msg;
		return ptr;
	}

	strcpy(msg, "USER HAS NO PERMISSION!");
	ptr = msg;
	return ptr;
}

char* create_database(char str[])
{
	char* ptr;
	char msg[1024];

	// namadb
	char namadb[1024];
	bzero(namadb, 1024);

	// parse
	int i;
	char parse[1024];
	strcpy(parse, str);
	char* parseptr = parse;
	char* token;

	// CREATE DATABASE [nama_database];
	for (i = 0; token = strtok_r(parseptr, " ", &parseptr); i++)
	{
		if (i == 2)
		{
			strncpy(namadb, token, strlen(token) - 1);
			// printf("aasadssadads\n");
		}
	}
	// printf("db : %s\n", namadb);

	char databasepath[1024];
	sprintf(databasepath, "%s/%s", folderDatabase, namadb);
	char* pathdbptr = databasepath;

	// printf("%s\n", databasepath);

	if (mkdir(pathdbptr, 0777) != 0)
	{
		strcpy(msg, "CANNOT CREATE DATABASE!");
		ptr = msg;
		return ptr;
	}

	char permissionfile[1024];
	strcpy(permissionfile, databasepath);
	strcat(permissionfile, "/granted_user.txt");

	create_file(permissionfile, login.id, "a");

	strcpy(msg, "DATABASE SUCCESSFULLY CREATED!");
	ptr = msg;
	return ptr;
}

char* use(char str[])
{
    char* ptr;
    char msg[1024];
    bzero(msg, 1024);

    // database
    char* dbptr = str + 4;
    char namadb[1024];
    bzero(namadb, 1024);
    strncpy(namadb, dbptr, strlen(dbptr) - 1);

    char permissionFile[1024];
    bzero(permissionFile, 1024);
    sprintf(permissionFile, "%s/%s/granted_user.txt", folderDatabase, namadb);

    FILE* file = fopen(permissionFile, "r");
    if (!file)
    {
        strcpy(msg, "DATABASE NOT FOUND");
		ptr = msg;
		return ptr;
    }

    char line[1024];
    while (fgets(line, 1024, file))
    {
        if (!strncmp(line, login.id, strlen(login.id)))
        {
            fclose(file);
            strcpy(msg, "SUCCESSFULLY ACCESS DATABASE");
            ptr = msg;
            strcpy(currentDB, namadb);
            return ptr;
        }
    }
    fclose(file);
    strcpy(msg, "ACCESS DATABASE DENIED");
    ptr = msg;
    return ptr;
}

char* grant_permission(char str[])
{
    char* ptr;
    char msg[1024];
    bzero(msg, 1024);

    // db
    char namadb[1024];
    bzero(namadb, 1024);

    // user
    char userid[1024];
    bzero(userid, 1024);

    // GRANT PERMISSION [nama_database] INTO [nama_user];
    int i;
    char parse[1024];
    strcpy(parse, str);
    char* parseptr = parse;
    char* token;

    for (i = 0; token = strtok_r(parseptr, " ", &parseptr); i++)
    {
        if (i == 2)
        {
            strcpy(namadb, token);
        }
        else if (i == 4)
        {
            strncpy(userid, token, strlen(token) - 1);
        }
        else if (i == 3 && strcmp(token, "INTO"))
        {
            strcpy(msg, "SYNTAX ERROR!");
            ptr = msg;
            return ptr;
        }
    }

    // cek user
    FILE* file = fopen(fileUser, "r");
    char line[1024];
    int ada = 0;

    while (fgets(line, 1024, file))
    {
        if (!strncmp(line, userid, strlen(userid)))
        {
            ada = 1;
            break;
        }
    }
    fclose(file);

    if (!ada)
    {
        strcpy(msg, "USER NOT FOUND!");
        ptr = msg;
        return ptr;
    }

    char namafile[1024];
    sprintf(namafile, "%s/%s/granted_user.txt", folderDatabase, namadb);
    
    file = fopen(namafile, "a");
    if (!file)
    {
        strcpy(msg, "DATABASE NOT FOUND");
        ptr = msg;
        return ptr;
    }
    fprintf(file, "%s\n", userid);
    fclose(file);

    strcpy(msg, "ACCESS GRANTED");
    ptr = msg;
    return ptr;
}

char* create_user(char str[])
{
    char* ptr;
    char msg[1024];
    bzero(msg, 1024);

    // new user identity
    char newuserid[1024];
    bzero(newuserid, 1024);
    char newuserpass[1024];
    bzero(newuserpass, 1024);

    // buat strtok_r
    char cmd[1024];
    strcpy(cmd, str);
    char* cmdptr = cmd;
    char* token;
    int i;

    // CREATE USER [username] IDENTIFIED BY [password]
    for (i = 0; token = strtok_r(cmdptr, " ", &cmdptr); i++)
    {
        if (i == 2)
        {
            strcpy(newuserid, token);
        }
        else if (i == 5)
        {
            strncpy(newuserpass, token, strlen(token) - 1);
			// printf("PASS : %s\n", newuserpass);
        }
        else if ((i == 3 && strcmp(token, "IDENTIFIED")) || (i == 4 && strcmp(token, "BY")) || i > 5)
        {
			strcpy(msg, "SYNTAX ERROR!");
            ptr = msg;
            return ptr;
        }
    }

	// printf("ID : %s\n", newuserid);
    bzero(cmd, 1024);
	strcpy(cmd, newuserid); strcat(cmd, ":"); strcat(cmd, newuserpass);
    // sprintf(cmd, "%s:%s", newuserid, newuserpass);
	// printf("%s", cmd);
	// printf("PASS : %s\n", newuserpass);
    create_file(fileUser, cmd, "a");
    strcpy(msg, "CREATE USER SUCCESS!");
    ptr = msg;
    return ptr;
}

void create_file(char fileName[], char str[], char mode[])
{
    FILE* file = fopen(fileName, mode);
    fprintf(file, "%s\n", str);
	// printf("LER\n");
    fclose(file);
}

void reconnect()
{
    char buffer[1024] = {0}, msg[1024] = {0};
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // ambil uid
    valread = read(new_socket, buffer, 1024);

    // root user
    if (!strcmp(buffer, "0"))
    {
        strcpy(msg, "Connection Accepted. Connected As Root!");
        strcpy(login.id, "root");
        acc = 1;
        isRoot = 1;
    }

    if (!acc)
    {
        // handle read di client
        send(new_socket, "DUARR", 10, 0);
        bzero(buffer, 1024);

        // username:password
        valread = read(new_socket, buffer, 1024);

        if (autentikasi(buffer))
        {
            char strbackup[1024];
            strcpy(strbackup, buffer);
            char* ptr = strbackup;
            char* token;

            int i;
            for (i = 0; token = strtok_r(ptr, ":", &ptr); i++)
            {
                if (i == 0)
                {
                    strcpy(login.id, token);
                }
                else if (i == 1)
                {
                    strcpy(login.password, token);
                }
            }
            acc = 1;
            strcpy(msg, "Connection Accepted. Welcome ");
			strcat(msg, login.id);
        }
        else
        {
            strcpy(msg, "Invalid Username or Password!");
        }
    }
    send(new_socket, msg, strlen(msg), 0);
}

int autentikasi(char str[])
{
    FILE* file = fopen(fileUser, "r");

    char line[1024];
    while (fgets(line, 1024, file))
    {
        if (!strcmp(line, str))
        {
            fclose(file);
            return 1;
        }
    }
    fclose(file);

    return 0;
}