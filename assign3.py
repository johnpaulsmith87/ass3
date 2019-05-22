import os
import sys
import threading
import socket
import struct



localhost = '127.0.0.1'
HEADERSIZE = 20 #total header size is 20 bytes
MTU = 1500
GET = True
SET = False

class Connection:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
    def __init__(self, connection, ipaddr):
        self.connection = connection
        self.ARPTable = {}
        self.subnet = None
        self.gateway = None
    def setGW(self, gateway):
        self.gateway = gateway
    def getGW(self, gateway):
        return self.gateway
    
    def setMTU(self, mtu):
        self.connection.MTU = mtu
    def getMTU(self):
        return self.connection.MTU



    

class IPv4Header:
    def __init__(self, header):
        pass

class IPv4Packet:
    #raw format is a byte string?
    def __init__(self, rawformat):
        pass

#gateway commands
def gw(args, network = None):
    if args[0] == 'set':
        pass
        return SET
    elif args[0] == 'get':
        pass
        return GET
#arp commands
def arp(args, network = None):
    if args[0] == 'set':
        pass
        return SET
    elif args[0] == 'get':
        pass
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
        pass         #look in ARP table for (use msg to pass on?)
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
    ipaddr = "192.168.1.1/24" #debug only values
    lladdr = "1024"
    ## start listening thread -> this needs to be active the whole time!
    ## we'll add this later
    ## after lannching that thread, begin accepting console input.
    ## console inputs will be a loop that after rcving user input checks it against a dictionary of commands -> functions
    ## the commands will take a list(?) of parameters and be fed to the command function
    
    ####################
    #Initialise Network#
    ####################
    connection = Connection(localhost, lladdr)
    ###############
    #Listen Thread#
    ###############
    network = Network(connection, ipaddr)
    network.ARPTable[ipaddr] = lladdr #add entry to ARP? Not sure if needed yet
    #####
    #CLI#
    #####
    while True:
        userInput = input("> ")
        splitInput = userInput.split()
        if splitInput[0] in CommandsToActions.keys():
           isGET = CommandsToActions[splitInput[0]](splitInput[1:], network)
           if isGET:
               printToScreen(splitInput[0], network, splitInput)
        else:
            #invalid command
            continue
        
        ##any after function code




if __name__ == '__main__':
    main()


