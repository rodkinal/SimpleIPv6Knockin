#!/usr/bin/python
# This is just a simple IPv6 Knocking program which use the host IP to
# as key of the knocking sequence.
# Copyright (C) 2016 Rodkinal
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from scapy.all import *
from ConfigParser import SafeConfigParser
import logging, os

# *** Configuration ***
iface = ""
dst_port = ""
proto = ""
open_addr = []
close_addr = []
openc = []
closec = []


""" Global vars """
format = "%(asctime)s - %(levelname)s - %(message)s"
log_file = '/var/log/IPv6Knocking.log'
logging.basicConfig(filename=log_file, level=logging.DEBUG, format=format)


def interfaceexists(interface):
    """
        This method verifies if the ethernet interface exists
    """
    iface_list = os.listdir('/sys/class/net/')
    if iface in iface_list:
        return True
    return False


def isvalidport(port):
    """
        This method verifies if the destination port is valid
    """
    try:
        if 0 <= int(port) <= 65535:
            return True
        return False
    except Exception as e:
        return False


def isvalidproto(transport_proto):
    """
        This method verifies if is valid transport protocol
    """
    if transport_proto.lower() == "tcp" or transport_proto.lower() == "udp":
        return True
    return False


def verifyparameters():
    """
        This method verifies the configuration parameters
    """
    no_errors = interfaceexists("/sys/class/net/list_iface")
    if no_errors:
        logging.info("Interface %s exists" %iface)
    else:
        logging.error("Interface %s does NOT exists" %iface)
        exitingprogram()

    no_errors = isvalidport(dst_port)
    if no_errors:
        logging.info("Using port %s" %dst_port)
    else:
        logging.error("Not valid port (%s)" %dst_port)
        exitingprogram()

    no_errors = isvalidproto(proto)
    if no_errors:
        logging.info("Using protocol %s" %proto)
    else:
        logging.error("Invalid protocol %s" %proto)
        exitingprogram()


def exitingprogram():
    """
        This method just exit the program if something fails
    """
    logging.error("Exiting the program...")
    sys.exit(2)


def parsingconfigfile():
    """
    This method reads the configuration in the file and assign each value to a global variable.
    Other methods will validate the configuration in order to verify if it is properlly formatted.
    :return:
    """
    global iface,dst_port,proto,open_addr,close_addr,openc,closec

    parser = SafeConfigParser()
    candidates = ['server_config.cfg',]
    found = parser.read(candidates)
    missing = set(candidates) - set(found)
    logging.info('Found config files: %s' % str(sorted(found)))
    if missing:
        logging.error('Missing config files: %s' % str(sorted(missing)))
        exitingprogram()

    iface = parser.get('network_config', 'iface')
    dst_port = parser.get('network_config', 'destination_port')
    proto = parser.get('network_config', 'protocol')

    open_addr = parser.get('valid_sequences', 'open_sequence').split(",")
    close_addr = parser.get('valid_sequences', 'close_sequence').split(",")

    openc = parser.get('commands', 'open_command')
    closec = parser.get('commands', 'close_command')

def listeningsuccessful(knock_addr):
    """
        This method verifies if the recieving packet complains the proper order of the sequence.
        The while loop checks if the packets are received in the proper order. If not, the counter
        (i) will return to 0, this loop will be execute until the packets are received in the
        correct order.
    """
    i = 0
    while i < len(knock_addr):
        try:
            p = sniff(iface=iface, filter="ip6 and " + proto + " and port " + dst_port, count=1)
            #p.show()
            #print str(i)


            if not p[0][IPv6].src.endswith(knock_addr[i]):
                i = 0  # Sequence out of order. Reset the counter
            #     logging.warning('Sequence refused from %s' % p[0][IPv6].src)
            #     print "NOPE!" + p[0][IPv6].src + "|||" + knock_addr[i] + "|||" + str(i)
            # else:
            #     print "YEEEAH!" + p[0][IPv6].src + "|||" + knock_addr[i] + "|||" + str(i)

            if i == len(knock_addr) - 1:
                i = 0
                logging.info('Sequence success from %s' % p[0][IPv6].src)
                return True  # Sequence successfully received
            else:
                i += 1
        except Exception as e:
            logging.error(e)


def executecommand(command):
    """
        This method is quite simple. It just execute a system command which could be anything such as
        bash script, system command, etc.
    """
    try:
        os.system(command)
        logging.info('Command "%s" executed' % command)
    except OSError as e:
        logging.error('Not command found "%s " => %s' %(command,e))


def main():
    logging.info('Starting the app...')
    parsingconfigfile()
    verifyparameters()
    while True:
        if listeningsuccessful(open_addr):
            logging.info('Open sequence received...')
            executecommand(openc)
        if listeningsuccessful(close_addr):
            logging.info('Close sequence received...')
            executecommand(closec)


if __name__ == "__main__":
        main()
