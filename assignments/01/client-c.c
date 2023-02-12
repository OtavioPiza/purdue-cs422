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
 * client-c.c
 * Name:  Otavio Sartorelli de Toledo Piza
 * PUID:  0032690213
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SEND_BUFFER_SIZE 2048

/* TODO: client()
 *
 * THIS CODE IS HEAVILY INSPIRED BY THAT PROVIDED IN THE RECOMMENDED GUIDE
 *
 * Open socket and send message from stdin.
 * Return 0 on success, non-zero on failure
 */
int client(char *server_ip, char *server_port)
{
  // Allocate data structures for socket.
  struct addrinfo *server_info, *hints = calloc(1, sizeof(struct addrinfo));
  hints->ai_family = AF_INET;
  hints->ai_socktype = SOCK_STREAM;

  // Try to connect.
  if (getaddrinfo(server_ip, server_port, hints, &server_info) != 0)
  {
    free(hints);
    perror("client: getaddrinfo");
    return 1;
  }

  // Loop through results and accept the first valid one.
  struct addrinfo *server_addr;
  int server_socket_fd;
  for (server_addr = server_info; server_addr != NULL; server_addr = server_addr->ai_next)
  {
    // Try to open the socket.
    if ((server_socket_fd = socket(
             server_addr->ai_family, server_addr->ai_socktype, server_addr->ai_protocol)) == -1)
    {
      perror("client: socket");
      continue;
    }

    // Set connect to socket.
    if (connect(server_socket_fd, server_addr->ai_addr, server_addr->ai_addrlen) == -1)
    {
      close(server_socket_fd);
      server_socket_fd = -1;
      perror("client: connect");
      continue;
    }

    // If everything above worked break;
    break;
  }

  // Free server_info.
  freeaddrinfo(server_info);

  // Check for valid address.
  if (server_addr == NULL)
  {
    return 1;
  }

  // Read from stdin.
  char buffer[SEND_BUFFER_SIZE];
  size_t read;
  while ((read = fread(buffer, sizeof(char), SEND_BUFFER_SIZE, stdin)) > 0)
  {
    send(server_socket_fd, buffer, read, 0);
  }

  // Close connection.
  close(server_socket_fd);
  server_socket_fd = -1;

  // Check for io error.
  if (ferror(stdin) || ferror(stdout))
  {
    perror("client-io:");
  }

  // Return 0.
  return 0;
}

/*
 * main()
 * Parse command-line arguments and call client function
 */
int main(int argc, char **argv)
{
  char *server_ip;
  char *server_port;

  if (argc != 3)
  {
    fprintf(stderr, "Usage: ./client-c (server IP) (server port) < (message)\n");
    exit(EXIT_FAILURE);
  }

  server_ip = argv[1];
  server_port = argv[2];
  return client(server_ip, server_port);
}
