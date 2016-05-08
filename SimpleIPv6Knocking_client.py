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

import argparse,sys,time,os.path
from ConfigParser import SafeConfigParser
from scapy.all import *

# *** Configuration ***
dst_addr = ""
dst_port = ""
iface = ""
proto = ""
open_seq = []
close_seq = []
v = False
action = ""
input_files = []
usage = """
    -a  --action    Set action to be executed on a remote system [open|close]
    -f  --files     Use config files to execute commands on a remote system
    -v  --verbose   Set verbose mode

examples:
    SimpleIP6Knocking_client.py -a open -f config_file_1.cfg
    SimpleIP6Knocking_client.py -v -a close -f config_file_1.cfg config_file_2.cfg
"""
banner = """
                    _____ _                 _
                   /  ___(_)               | |
                   \ `--. _ _ __ ___  _ __ | | ___
                    `--. \ | '_ ` _ \| '_ \| |/ _ \\
                   /\__/ / | | | | | | |_) | |  __/
                   \____/|_|_| |_| |_| .__/|_|\___|
                                     |_|
                       ___________        ____
                      |_   _| ___ \      / ___|
                        | | | |_/ /_   _/ /___
                        | | |  __/\ \ / / ___ \\
                       _| |_| |    \ V /| \_/ |
                       \___/\_|     \_/ \_____/
                 _   __                 _    _
                | | / /                | |  (_)
                | |/ / _ __   ___   ___| | ___ _ __   __ _
                |    \| '_ \ / _ \ / __| |/ / | '_ \ / _` |
                | |\  \ | | | (_) | (__|   <| | | | | (_| |
                \_| \_/_| |_|\___/ \___|_|\_\_|_| |_|\__, |
                                                      __/ |
                                                     |___/
                           Developed by Rodkinal
                           ---------------------
"""


def parsearguments():
    """
    This method just assign the input parameters to a global variables to be used latter.
    :return:
    """
    global action,v,input_files
    parser = argparse.ArgumentParser(description='Client side of Simple IP6 Knocking. This will let you '
                                     'execute commands on a remote system. ',usage=usage)
    parser.add_argument('-a','--action', dest='action', choices=['open','close'],
                        required=True, help='Select open or close command')
    parser.add_argument('-v','--verbose', dest='verbose', action='store_true',
                        help='Verbose mode')
    parser.add_argument('-f','--files', required=True, dest='input_files', nargs='*',
                        help='Input config files to be read (Default file: client_config.cfg')

    args = parser.parse_args()
    action = args.action
    input_files = args.input_files
    v = args.verbose


def exitingprogram():
    print 'Exiting program...'
    sys.exit(2)


def isvalidproto(transport_proto):
    """
        This method verifies if is valid transport protocol
    """
    if transport_proto.lower() == "tcp" or transport_proto.lower() == "udp":
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


def interfaceexists(interface):
    """
        This method verifies if the ethernet interface exists
    """
    iface_list = os.listdir('/sys/class/net/')
    if iface in iface_list:
        return True
    return False


def verifyparameters():
    """
        This method verifies the configuration parameters
    """
    no_errors = interfaceexists("/sys/class/net/list_iface")
    if no_errors:
        if v: print "INFO: Interface %s exists" %iface
    else:
        raise Exception("ERROR: Interface %s does NOT exists" %iface)
        exitingprogram()

    no_errors = isvalidport(dst_port)
    if no_errors:
        if v: print 'INFO: Using port %s' %dst_port
    else:
        raise Exception('ERROR: Not valid port (%s)' %dst_port)
        exitingprogram()

    no_errors = isvalidproto(proto)
    if no_errors:
        if v: print 'INFO: Using protocol %s' %proto.upper()
    else:
        raise Exception('ERROR: Invalid protocol %s' %proto)
        exitingprogram()


def parsingconfigfile(file):
    """
        This method reads the configuration in the file and assign each value to a global variable.
        Other methods will validate the configuration in order to verify if it is properlly formatted.
        :return:
    """
    global dst_port,proto,open_seq,close_seq,iface,dst_addr

    parser = SafeConfigParser()
    #candidates = [file]
    parser.read(file)
    #missing = set(candidates) - set(found)
    # if missing:
    #     raise Exception('Missing config files: %s' % str(sorted(missing)))
    #     exitingprogram()

    dst_addr = parser.get('network_config', 'destination_address')
    dst_port = parser.get('network_config', 'destination_port')
    proto = parser.get('network_config', 'protocol')
    iface = parser.get('network_config', 'interface')
    open_seq = parser.get('valid_sequences', 'open_sequence').split(",")
    close_seq = parser.get('valid_sequences', 'close_sequence').split(",")

    if len(open_seq)>4 or len(close_seq)>4:
        raise Exception ('ERROR: Only /64 modification allowed')
        exitingprogram()


def getipv6sourceaddress(iface):
    """
    This method returns the IPv6 assigned to the parameter iface
    :param iface: name of the interface that will send the packets
    :return: returns th IPv6 assigned to that interface
    """
    f = os.popen('ip addr show dev '+iface)
    output = f.read()
    return output.split('inet6')[1].split('scope')[0].replace('/64','').strip()


def deletelastcharacters(ipv6,lastlong):
    return ipv6[:-lastlong]


def sendpackets(src_addr, seq_addr,dst_addr):
    for seq in seq_addr:
        src_ip = deletelastcharacters(src_addr, len(seq))+seq
        if v: print 'INFO: Source: %s => Destination: %s' %(src_ip,dst_addr)
        if proto =="tcp":
            p = Ether()/IPv6(src=src_ip, dst=dst_addr)/TCP(sport=RandShort(), dport=int(dst_port), flags="S")
        else:
            p = Ether()/IPv6(src=src_ip, dst=dst_addr)/UDP(sport=RandShort(), dport=int(dst_port))
        sendp(p,iface=iface, verbose=0)
        time.sleep(0.4)


def checkiffilesexit(files):
    existingfiles = []
    nonexistingfile = []
    for file in files:
        if os.path.isfile(file):
            existingfiles.append(file)
        else:
            nonexistingfile.append(file)
    return existingfiles,nonexistingfile


def main():
    print banner
    parsearguments()
    files = checkiffilesexit(input_files)
    if v and files[1]: print 'ERROR: Non existing files: %s' %files[1]
    for file in files[0]:
        print '\nReading file %s' %file
        print '='*(13+len(file))
        try:
            parsingconfigfile(file)
            verifyparameters()
            src_addr = getipv6sourceaddress(iface)
            if v: print 'INFO: Selected action: %s' %action.upper()
            print 'INFO: Sending packets...'
            if action == 'open':
                sendpackets(src_addr, open_seq, dst_addr)
            else:
                sendpackets(src_addr, close_seq, dst_addr)
            print 'INFO: Packets sended...'

        except IndexError as e:
            print 'ERROR: No IPv6 interface detected: %s' %e
        except Exception as e:
            print 'INFO: No readable file %s :: $s' %(file,e)

if __name__ == "__main__":
    main()
