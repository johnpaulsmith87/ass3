import os
import sys
import threading
import socket
import struct

##### ### ###
##TODO  #####
#### ###  ###
## subnet?
## IP encoding/decoding/fragmentation
## listening thread!

localhost = '127.0.0.1'
HEADERSIZE = 20 #total header size is 20 bytes
MTU = 1500
GET = True
SET = False

class Connection:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #must be non-blocking to be able to send and receive
        self.sock.setblocking(False)
        self.sock.bind((host, port))
        self.MTU = MTU
        sys.stdout.flush()
    def close(self):
        self.sock.close()
    def get_packet(self):
        result = self.sock.recvfrom(MTU)
        return result
    #will use send_packets to call this multiple times
    def send_packet(self, packet, address):
        sent = self.sock.sendto(packet, address)
    
    def send_packets(self, packets, address):
        for packet in packets:
            self.send_packet(packet, address)



class Network:
    def __init__(self, connection, ipaddr, subnet = None):
        self.connection = connection
        self.ARPTable = {}
        self.subnet = None
        self.gateway = None

    def setGW(self, gateway):
        self.gateway = gateway
    def getGW(self):
        return self.gateway
    
    def setMTU(self, mtu):
        self.connection.MTU = mtu
    def getMTU(self):
        return self.connection.MTU



    

class IPv4Header:
    def __init__(self, header):
        pass

#this will make an IP packet with known header/payload
class IPv4Packet:
    #raw format is a byte string?
    def __init__(self, flags):
        pass

#takes a packet byte string and parses it into a packet object
def parsePacket(rawFormat):
    pass

#gateway commands
def gw(args, network = None):
    if args[0] == 'set':
        network.gateway = args[1]
        return SET
    elif args[0] == 'get':
        return GET
#arp commands
def arp(args, network = None):
    if args[0] == 'set':
        network.ARPTable[args[1]] = args[2]
        return SET
    elif args[0] == 'get':
        return GET
#mtu commands
def mtu(args, network = None):
    if args[0] == 'set':
        network.setMTU(int(args[1]))
        return SET
    elif args[0] == 'get':
        return GET
#misc
def exitCommand(args, network=None):
    exit()
def msg(args, network=None):
    #generate message in IPv4 format? and send to specified port (using table)
    pass

#type is gw, arp, exit, etc...
#network to get the data
def printToScreen(context, network, message = None):
    if context == 'gw':
        print(network.getGW())
    elif context == 'mtu':
        print(network.getMTU())
    elif context == 'arp':
        if message[0] in network.ARPTable.keys():
            print(network.ARPTable[message[0]])
        else:
            print("None")
    elif context == 'msg':
        pass


CommandsToActions = {
    'gw': gw,
    'arp': arp,
    'mtu': mtu,
    'exit': exitCommand, 
    'msg': msg
}

#main function
def main():
    args = sys.argv
    #ipaddr = sys.argv[1]
    #lladdr = sys.argv[2]
    networkAddr = "192.168.1.1/24" #debug only values
    lladdr = "1024"
    temp = networkAddr.split('/')
    ipaddr = temp[0]
    subnet = temp[1]
    ## start listening thread -> this needs to be active the whole time!
    ## we'll add this later
    ## after lannching that thread, begin accepting console input.
    ## console inputs will be a loop that after rcving user input checks it against a dictionary of commands -> functions
    ## the commands will take a list(?) of parameters and be fed to the command function
    
    ####################
    #Initialise Network#
    ####################
    connection = Connection(localhost, int(lladdr))
    ###############
    #Listen Thread#
    ###############
    network = Network(connection, ipaddr, subnet)
    network.ARPTable[ipaddr] = lladdr #add entry to ARP? Not sure if needed yet
    #####
    #CLI#
    #####
    while True:
        userInput = input("> ")
        splitInput = userInput.split()
        if splitInput is not None and len(splitInput) > 0 and splitInput[0] in CommandsToActions.keys():
           isGET = CommandsToActions[splitInput[0]](splitInput[1:], network)
           if isGET:
               printToScreen(splitInput[0], network, splitInput)
        else:
            #invalid command
            continue
        
        ##any after function code




if __name__ == '__main__':
    main()


