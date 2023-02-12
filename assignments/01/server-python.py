############################################################################
##
##     This file is part of Purdue CS 422.
##
##     Purdue CS 422 is free software: you can redistribute it and/or modify
##     it under the terms of the GNU General Public License as published by
##     the Free Software Foundation, either version 3 of the License, or
##     (at your option) any later version.
##
##     Purdue CS 422 is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##     GNU General Public License for more details.
##
##     You should have received a copy of the GNU General Public License
##     along with Purdue CS 422. If not, see <https://www.gnu.org/licenses/>.
##
#############################################################################

# server-python.py
# Name: Otavio Sartorelli de Toledo Piza
# PUID: 0032690213

import sys
import socket

RECV_BUFFER_SIZE = 2048
QUEUE_LENGTH = 10


def server(server_port):
    """Listen on socket and print received message to sys.stdout"""
    
    # Allocate data structures for server socket.
    hints = socket.getaddrinfo(None, server_port, socket.AF_INET, socket.SOCK_STREAM)

    # Try to get the server address info.
    server_info = hints[0]
    if not server_info:
        sys.stderr.write("server: getaddrinfo")
        return 1

    # Bind to first valid result on server_info.
    server_socket_fd = None
    for server_addr in hints:
        yes = 1

        # Try to open a socket.
        try:
            server_socket_fd = socket.socket(server_addr[0], server_addr[1], server_addr[2])
        except socket.error as error:
            sys.stderr.write("server: socket")
            continue

        # Set socket options.
        try:
            server_socket_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, yes)
        except socket.error as error:
            sys.stderr.write("server: setsockopt")
            return 1

        # Try to bind the socket.
        try:
            server_socket_fd.bind(server_addr[4])
        except socket.error as error:
            server_socket_fd.close()
            server_socket_fd = None
            sys.stderr.write("server: bind")
            continue

        # Break if everything worked.
        break

    # Check for valid server address.
    if not server_socket_fd:
        return 1

    # Try to listen.
    try:
        server_socket_fd.listen(QUEUE_LENGTH)
    except socket.error as error:
        return 1

    # Infinitely accept connections.
    while True:
        # Accept connection.
        client_socket_fd, client_addr = server_socket_fd.accept()

        # Listen for message.
        buffer = []
        while True:
            read = client_socket_fd.recv(RECV_BUFFER_SIZE)
            if not read:
                break
            buffer.append(read)

        # Print message.
        sys.stdout.write(''.join(buffer))
        sys.stdout.flush()

        # Close client socket.
        client_socket_fd.close()

    # Return 0.
    return 0


def main():
    """Parse command-line argument and call server function """
    if len(sys.argv) != 2:
        sys.exit("Usage: python server-python.py (Server Port)")
    server_port = int(sys.argv[1])
    server(server_port)


if __name__ == "__main__":
    main()
