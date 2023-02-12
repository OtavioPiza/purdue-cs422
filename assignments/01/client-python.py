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

# client-python.py
# Name: Otavio Sartorelli de Toledo Piza
# PUID: 0032690213

import sys
import socket

SEND_BUFFER_SIZE = 2048

def client(server_ip, server_port):
    """Open socket and send message from sys.stdin"""
    
    # Allocate data structures for socket.
    hints = socket.getaddrinfo(server_ip, server_port, socket.AF_INET, socket.SOCK_STREAM)

    # Loop through results and accept the first valid one.
    server_socket = None
    for res in hints:
        af, socktype, proto, canonname, sa = res
        try:
            # Try to open the socket.
            server_socket = socket.socket(af, socktype, proto)
        except socket.error as msg:
            server_socket = None
            continue

        # Set connect to socket.
        try:
            server_socket.connect(sa)
        except socket.error as msg:
            server_socket.close()
            server_socket = None
            continue

        # If everything above worked break;
        break

    # Check for valid address.
    if server_socket is None:
        print "Could not connect to the server."
        return 1;

    # Read from stdin and send to server.
    while True:
        buffer = sys.stdin.read(SEND_BUFFER_SIZE)
        
        if not buffer:
            break
        
        server_socket.sendall(buffer)

    # Close connection.
    server_socket.close()

    # Return 0.
    return 0


def main():
    """Parse command-line arguments and call client function """
    if len(sys.argv) != 3:
        sys.exit("Usage: python client-python.py (Server IP) (Server Port) < (message)")
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    client(server_ip, server_port)


if __name__ == "__main__":
    main()
