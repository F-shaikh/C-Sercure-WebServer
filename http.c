/**
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without
 * the express written permission of the copyright holder.
 */


/**
 * Before Running:
 * Ensure you have a users file named users(no extension) that properly follows the format specified in the instructions
 * Have directories already made for users from the users file.
 * Instructions to run:
 * Type Make
 * Type ./server PORT
 * On another terminal (client side), try out basic commands such as the following...
 * Test login: curl -i -X POST "localhost:PORT/login?username=<X>&password=<Y>"
 *      - This should print out a cookie for you on the client side.
 * Test GET: curl -H "Authorization: <cookie>" -X GET "localhost:PORT/user/file"
 *      - Authorization should be spelled as above, there should be a space after the semicolon.
 *      - This follows the HTTP basic authorization method. It is sent in the header hence the "-H".
 *      - <cookie> is what you should have received on the client side from logging in. 
 * Test POST: curl -H "Authorization: <cookie>" -d "some text" -X POST "localhost:PORT/user/file"
 *      - -d is used to specify what text you would like in the file.
 *      - If the file does not exist already, it is created.
 *      - I made this server such that if the file exists already, it is overwritten with the new data.
 * Feel free to test using other commands as well, these are just sample instructions.
 */


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>

#define BYTES 2048

static void binary(int sock, char *fname) {
    int fd;
    int bytes;
    void *buffer[BYTES];
    if ((fd = open(fname, O_RDONLY)) != -1) {
        while ((bytes = read(fd, buffer, BYTES)) > 0)
            write(sock, buffer, bytes);
   }
}

void httpRequest(int sock, char *request)
{
    char* authCopy = malloc(sizeof(request) * strlen(request));
    authCopy = strncpy(authCopy, request, strlen(request));

    char* userCopy = malloc(sizeof(request) * strlen(request));
    userCopy = strncpy(userCopy, request, strlen(request));

    char* body = strstr(request, "\r\n\r\n");
    char* command = strtok(request, " "); //This holds the command
    char* path = strtok(NULL, " "); //This holds the path
    if (path[0] == '/') path++;

    // Added fix if the client sends a "bad" request that does not follow HTTP/1.1 protocol that caused a seg fault
    char* version = strtok(NULL, " \n"); //This holds the version
    if (strncmp(version, "HTTP/1.1", 8))
    {
        write(sock,"HTTP/1.1 505 HTTP Version Not Supported\n", 40);
        return;
    }

    char* authorize = strtok(authCopy, "\n"); //This holds the The Authorization Sent Over
    authorize = strtok(NULL, "\n");
    authorize = strtok(NULL, "\n");
    authorize = strtok(NULL, "\n");
    authorize = strtok(NULL, "\n");
    authorize = strstr(authorize, " ");
    authorize = strtok(authorize, " ");

    char* realPath = strtok(userCopy, " "); //This extracts the username from the path
    realPath = strtok(NULL, " ");
    realPath = strtok(realPath, "/");

    if ((strncmp(command, "POST", 4) == 0) && (strcmp(body, "\r\n\r\n") == 0))
    {
        char* username = strstr(path, "="); // This holds the username
        char* password = strstr(path, "&"); // This holds the password
        username = strtok(username, "=&");
        password = strtok(NULL, "\r\n");
        password= strstr(password, "=");
        password = strtok(password, "=");

        // Added fix if username and password were blank that caused a seg fault
        if(username == NULL || password == NULL)
        {
            write(sock,"The Username or Password cannot be left blank\n", 46);
            return;
        }
        // Added fix if the username is too long that previously caused a seg fault
        if(strlen(username) >= 100)
        {
            write(sock, "The Username must be less than 100 characters\n", 46);
            return;
        }
        // Added fix if the password is too long that previously caused a seg fault
        if(strlen(password) >= 100)
        {
            write(sock, "The Password must be less than 100 characters\n", 46);
            return;
        }

        char* userPass = strcat(username, ":");
        userPass = strcat(userPass, password);

        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;

        fp = fopen("./users", "r");
        if (fp == NULL)
        {
            exit(EXIT_FAILURE);
        } 
        int flag = 1;
        while ((read = getline(&line, &len, fp)) != -1)
        {
            if (strncmp(line, userPass, (strlen(line) - 1)) == 0)
            {
                char* cookie = malloc((sizeof(char) * 40) + strlen(line));
                sprintf(cookie, "HTTP/1.1 200 OK\nSet-Cookie: cookie-name=%s", line);
                write(sock, cookie, strlen(cookie));
                write(sock,"\n",1);
                flag = 0;
                break;
            }
        }
        // Added return statement to avoid crashing 
        if (flag == 1)
        {
            write(sock,"HTTP/1.1 401 Unauthorized\n", 26);
            return;
        }
        fclose(fp);
        if (line)
        {
            free(line);
        }
    }

    else if (strncmp(command, "GET", 3) == 0)
    {
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        // Added this check to avoid crashing upon requests that do not include authentication token (cookie)
        if (authorize == NULL)
        {
            write(sock,"HTTP/1.1 401 Unauthorized\n", 26);
            return;
        }

        fp = fopen("./users", "r");
        if (fp == NULL)
        {
            exit(EXIT_FAILURE);
        }
        int flag = 1;
        while ((read = getline(&line, &len, fp)) != -1)
        {
            if ((strncmp(line, authorize, (strlen(line) - 1)) == 0) && strlen(line) == strlen(authorize))
            {
                char* userLine = strtok(line, ":");
                if ((strncmp(userLine, realPath, strlen(realPath)) == 0))
                {
                    binary(sock, path);
                    write(sock,"\n",1);
                    flag = 0;
                    break;
                }
            }
        }
        // Added return statement to avoid crashing 
        if (flag == 1)
        {
            write(sock,"HTTP/1.1 401 Unauthorized\n", 26);
            return;
        }
        fclose(fp);
        if (line)
        {
            free(line);
        }
    }

    else if (strncmp(command, "POST", 4) == 0)
    {
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        // Added this check to avoid crashing upon requests that do not include authentication token (cookie)
        if (authorize == NULL)
        {
            write(sock,"HTTP/1.1 401 Unauthorized\n", 26);
            return;
        }
        

        fp = fopen("./users", "r");
        if (fp == NULL)
        {
            exit(EXIT_FAILURE);
        }
        int flag = 1;
        while ((read = getline(&line, &len, fp)) != -1)
        {
            if ((strncmp(line, authorize, (strlen(line) - 1)) == 0) && strlen(line) == strlen(authorize))
            {
                char* userLine = strtok(line, ":");
                if ((strncmp(userLine, realPath, strlen(realPath)) == 0))
                {
                    FILE *postfp;
                    postfp= fopen(path, "w");
                    if(strlen(path) >= 1000)
                    {
                        write(sock, "500 Internal Server Error\n", 26);
                        return;
                    }
                    fprintf(postfp, "%s", body);
                    fclose(postfp);
                    write(sock,"201 Created\n", 12);
                    flag = 0;
                    break;
                }
            }
        }
        // Added return statement to avoid crashing
        if (flag == 1)
        {
            write(sock,"HTTP/1.1 401 Unauthorized\n", 26);
            return;
        }
        fclose(fp);
        if (line)
        {
            free(line);
        }
    }
    // Added this final check to just return if user sends something strange that I have not specified
    else
    {
        write(sock, "HTPP/1.1 401 Unauthorized\n", 26);
        return;
    }
}