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
# Name:
# PUID:

import sys
import socket

RECV_BUFFER_SIZE = 2048
QUEUE_LENGTH = 10

def server(server_port):
    """TODO: Listen on socket and print received message to sys.stdout"""
    pass


def main():
    """Parse command-line argument and call server function """
    if len(sys.argv) != 2:
        sys.exit("Usage: python server-python.py (Server Port)")
    server_port = int(sys.argv[1])
    server(server_port)

if __name__ == "__main__":
    main()
