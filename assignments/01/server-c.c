/*****************************************************************************
 *
 *     This file is part of Purdue CS 422.
 *
 *     Purdue CS 422 is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     Purdue CS 422 is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with Purdue CS 422. If not, see <https://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

/*
 * server-c.c
 * Name:  Otavio Sartorelli de Toledo Piza
 * PUID:  0032690213
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define QUEUE_LENGTH 10
#define RECV_BUFFER_SIZE 2048

/* Open socket and wait for client to connect
 *
 * THIS CODE IS HEAVILY INSPIRED BY THAT PROVIDED IN THE RECOMMENDED GUIDE
 *
 * Print received message to stdout
 * Return 0 on success, non-zero on failure
 */
int server(char *server_port)
{
  // Allocate data structures for server socket.
  struct addrinfo *server_info, *hints = calloc(1, sizeof(struct addrinfo));
  hints->ai_family = AF_INET;
  hints->ai_socktype = SOCK_STREAM;
  hints->ai_flags = AI_PASSIVE;

  // Try to get the server address info.
  if (getaddrinfo(NULL, server_port, hints, &server_info) != 0)
  {
    free(hints);
    perror("server: getaddrinfo");
    return 1;
  }

  // Free hints.
  free(hints);
  hints = NULL;

  // Bind to first valid result on server_info.
  struct addrinfo *server_addr;
  int server_socket_fd;
  for (server_addr = server_info; server_addr != NULL; server_addr = server_addr->ai_next)
  {
    int yes = 1;

    // Try to open a socket.
    if ((server_socket_fd = socket(
             server_addr->ai_family, server_addr->ai_socktype, server_addr->ai_protocol)) == -1)
    {
      perror("server: socket");
      continue;
    }

    // Set socket options.
    if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
      perror("server: setsockopt");
      return 1;
    }

    // Try to bind the socket.
    if (bind(server_socket_fd, server_addr->ai_addr, server_addr->ai_addrlen) == -1)
    {
      close(server_socket_fd);
      server_socket_fd = -1;
      perror("server: bind");
      continue;
    }

    // Break if everything worked;
    break;
  }

  // Free server_info.
  freeaddrinfo(server_info);

  // Check for valid server address.
  if (server_addr == NULL)
  {
    return 1;
  }

  // Try to listen.
  if (listen(server_socket_fd, QUEUE_LENGTH) == -1)
  {
    return 1;
  }

  // Infinitely accept connections.
  while (1)
  {
    // Accept connection.
    struct sockaddr_storage client_addr;
    socklen_t sin_size = sizeof(client_addr);
    int client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_addr, &sin_size);

    // Listen for message.
    char buffer[RECV_BUFFER_SIZE];
    int read;
    while ((read = recv(client_socket_fd, buffer, sizeof(buffer), 0)) > 0)
    {
      // Print message.
      buffer[read] = '\0';
      fprintf(stdout, "%s", buffer);
      fflush(stdout);
    }

    // Close client socket.
    close(client_socket_fd);
    client_socket_fd = -1;

    // Check for read errors.
    if (read == -1)
    {
      perror("server: recv");
      continue;
    }
  }

  // Return 0.
  return 0;
}

/*
 * main():
 * Parse command-line arguments and call server function
 */
int main(int argc, char **argv)
{
  char *server_port;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: ./server-c (server port)\n");
    exit(EXIT_FAILURE);
  }

  server_port = argv[1];
  return server(server_port);
}
