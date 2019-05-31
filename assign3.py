import os
import sys
import threading
import socket
import struct
import math

##### ### ###
##TODO  #####
#### ###  ###
## subnet?
## IP encoding/decoding/fragmentation
## listening thread!

localhost = 'localhost'
HEADERSIZE = 20 #total header size is 20 bytes
MTU = 1500
GET = True
SET = False


def chunks(l, n):
    # For item i in a range that is a length of l,
    for i in range(0, len(l), n):
        # Create an index range for l of n items:
        yield l[i:i+n]

#splits an int m with n sized chunks -> used to frag packets
def chunkInt(m, n):
    chunk = []
    while True:
        if m - n > 0:
            chunk.append(n)
            m = m - n
        else:
            chunk.append(m)
            return chunk

#given a prefix, will return a 32 bit int of (4 bytes) which is the subnet mask
def getSubnetMask(cidr):
    mask = 0
    for i in range(32):
        if i < cidr:
            mask = mask | (1 << (32-i-1))
        else:
            break
    return mask

def messageToPackets(destination, source, msg, mtu):
    packets = []
    msgBytes = bytes(msg, 'utf-8')
    rawMsgLength = len(msgBytes)
    totalLength = rawMsgLength + HEADERSIZE
    chunks = chunkInt(totalLength, mtu - HEADERSIZE)
    lastChunk = 0
    for i in range(len(chunks)):
        df = 0
        mf = 1
        '''
        if i == len(chunks) - 1:
            df = 1
        '''
        if i == len(chunks) - 1:
            mf = 0
        offset = math.ceil((mtu - HEADERSIZE)/8)*i
        header = IPv4Header(1, df, mf, offset, chunks[i] + HEADERSIZE, source, destination)
        pkt = IPv4Packet(header, msgBytes[lastChunk:lastChunk+chunks[i]])
        packets.append(pkt)
        lastChunk += chunks[i] 
    return packets


#takes a string and does all the necessary stuff
class IPAddress:
    def __init__(self, ip):
        splitip = ip.split('.')
        self.sequence = [int(x) for x in splitip]

    def getString(self):
        return '.'.join([str(x) for x in self.sequence])

    def getBytes(self):
        return bytes(self.sequence)
    #converts ip in list to ip as int (for use in bin arith)
    def getInt(self):
        result = 0
        for i in range(4):
            result |= (self.sequence[i] << 24-(i*8))
        return result

def IPAddressFromInt(ip):
    first = (ip & int('0xFF000000', 16)) >> (31 - 7)
    second = (ip & int('0x00FF0000', 16)) >> (31 - 15)
    third = (ip & int('0x0000FF00', 16)) >> (31 - 23)
    fourth = (ip & int('0x000000FF', 16))
    ipaddr = IPAddress("%d.%d.%d.%d" % (first, second, third, fourth))
    return ipaddr

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
        result = self.sock.recvfrom(self.MTU)
        return result
    #will use send_packets to call this multiple times
    def send_packet(self, packet, address):
        with threading.Lock() as lock:
            sent = self.sock.sendto(packet, address)

    def send_packets(self, packets, address):
        for packet in packets:
            self.send_packet(packet, address)



class Network:
    def __init__(self, connection, ipaddr, subnet = None):
        self.connection = connection
        self.ARPTable = {}
        self.subnet = subnet
        self.subnetMask = IPAddressFromInt(getSubnetMask(subnet))
        self.gateway = None
        self.address = IPAddress(ipaddr)
        self.networkAddr = IPAddressFromInt(self.address.getInt() & self.subnetMask.getInt())
        self.broadcast = IPAddressFromInt(self.networkAddr.getInt() | (~self.subnetMask.getInt()))


    def setGW(self, gateway):
        self.gateway = gateway
    def getGW(self):
        return self.gateway

    def setMTU(self, mtu):
        self.connection.MTU = mtu
    def getMTU(self):
        return self.connection.MTU

    def isInNetwork(self, ip):
        return ip.getInt() > self.networkAddr.getInt() and ip.getInt() < self.broadcast.getInt()



class IPv4Header:
    def __init__(self, Id, df, mf, fragoffset, totalLength, src, dest, protocol = 0):
        self.id = Id
        self.df = df
        self.mf = mf
        self.totalLength = totalLength
        self.src = src
        self.dest = dest
        self.headerRows = 5
        self.ttl = 32
        self.ihl = 5
        self.version = 4
        self.fragoffset = fragoffset
        self.protocol = protocol

    def getHeader(self):
        result = [0,0,0,0,0]
        result[4] |= self.dest.getInt()
        result[3] |= self.src.getInt()
        result[2] |= self.ttl << (31 - 7)
        result[2] |= self.protocol << (31 - 15)
        result[1] |= self.fragoffset
        result[1] |= self.df << (31 - 18)
        result[1] |= self.mf << (31 - 17)
        result[1] |= self.id << (31 - 15)
        result[0] |= self.totalLength
        result[0] |= self.ihl << (31 - 7)
        result[0] |= self.version << (31 - 3)

        byts = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        for i in range(len(result)):
            for j in range(4):
                mask = 0
                if j == 0:
                    mask = int('ff000000', 16)
                    byts[(4*i) + j] = (result[i] & mask) >> 24
                elif j == 1:
                    mask = int('00ff0000', 16)
                    byts[(4*i) + j] = (result[i] & mask) >> 16
                elif j == 2:
                    mask = int('0000ff00', 16)
                    byts[(4*i) + j] = (result[i] & mask) >> 8
                elif j == 3:
                    mask = int('000000ff', 16)
                    byts[(4*i) + j] = (result[i] & mask)
        return bytearray(byts)



#this will make an IP packet with known header/payload
class IPv4Packet:
    #raw format is a byte string?
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload
    def getBytes(self):
        h = self.header.getHeader() + self.payload
        return h


#takes a packet byte array and parses it into a packet object
def parsePacket(rawFormat):
    pkt = None
    try:
        header = rawFormat[0:20] #first 20 bytes -> header
        payload = rawFormat[20:]
        row1 = header[0:4]
        row2 = header[4:8]
        row3 = header[8:12]
        source = int.from_bytes(header[12:16], 'big')
        dest = int.from_bytes(header[16:20], 'big')
        Id = int.from_bytes(row2[0:2], 'big')
        mf = row2[2] >> 5 & int('1', 16)
        df = row2[2] >> 6 & int('1', 16)
        protocol = row3[1]
        fragoffset = int.from_bytes(row2[2:4], 'big') & int('1fff', 16)
        totalLength = int.from_bytes(row1[2:4], 'big')
        ipHeader = IPv4Header(Id, df, mf, fragoffset, totalLength, source, dest, protocol)
        pkt = IPv4Packet(ipHeader, payload)
    except:
        pass

    return pkt


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
def msg(args, network):
    #generate message in IPv4 format? and send to specified port (using table)

    #check if ip is in ARP table?
    receiver = IPAddress(args[0])

    if network.isInNetwork(receiver):
        if args[0] not in network.ARPTable.keys():
            print("No ARP entry found")
            return
        #construct the packet(s) and send to socket!
        pkts = messageToPackets(receiver, network.address, " ".join(args[1:])[1:-1], network.getMTU())
        #then send to port in ARP
        network.connection.send_packets([x.getBytes() for x in pkts], (localhost, int(network.ARPTable[args[0]])))

    else:
        #first check for gw set
        if network.getGW() is None:
            print("No gateway found")
            return
        if network.getGW() not in network.ARPTable.keys():
            print("No ARP entry found")
            return
        pkts = messageToPackets(receiver, network.address, " ".join(args[1:])[1:-1], network.getMTU())
        #but don't send to port from ARP, send to gw port
        network.connection.send_packets([x.getBytes() for x in pkts], (localhost, int(network.ARPTable[network.getGW()])))

#type is gw, arp, exit, etc...
#network to get the data
def printToScreen(context, network, message = None):
    if context == 'gw':
        print(network.getGW())
    elif context == 'mtu':
        print(network.getMTU())
    elif context == 'arp':
        if message[2] in network.ARPTable.keys():
            print(network.ARPTable[message[2]])
        else:
            print("None")
    elif context == 'msg':
        pass

#called my listenint thread

def checkPackets(pkts, mtu):
    #simplest case
    packs = sorted(pkts, key=lambda pkt: pkt.header.fragoffset)
    if len(packs) == 1 and packs[0].header.mf == 0 and packs[0].header.fragoffset == 0:
        return True
    if len(packs) > 1:
        #check last packet - if it doesn't have mf = 0, we're not done!
        if packs[-1].header.mf != 0:
            return False
        #now if last pkt is the last pkt we're expecting, we need to
        #check frag offsets to ensure that each frag is there
        j = 0
        for i in range(len(packs)):
            expectedOffset = j * int((mtu - HEADERSIZE)/8)
            j += 1
            if packs[i].header.fragoffset != expectedOffset:
                return False
        return True
    return False

def generateMessage(pkts):
    packs = sorted(pkts, key=lambda pack:pack.header.fragoffset)
    ## concatenate each payload
    payloads = b''.join([x.payload for x in packs])
    payloads = str(payloads, 'utf-8')
    ## check protocol of 1?e
    protocol = packs[0].header.protocol
    src = IPAddressFromInt(packs[0].header.src)
    print('\b\b', end="", flush=True)
    if protocol == 0: 
        print("Message received from %s: \"%s\"" % (src.getString(), payloads))
        sys.stdout.flush()
    else:
        h = hex(protocol)[2:].zfill(2)
        h = '0x' + h
        print("Message received from %s with protocol %s" % (src.getString(), h))
        sys.stdout.flush()
    print('> ', end="", flush=True)


    
    

def listen(network):
    runningDict = {} #dict( ip -> dict(id -> list))
    while True:
        try:
            incoming = None
            with threading.Lock() as lock:
                incoming = network.connection.get_packet()
            if incoming is not None:
                pkt = parsePacket(incoming[0])
                #check if ip is in dict
                if pkt.header.src not in runningDict.keys():
                    runningDict[pkt.header.src] = {}
                    runningDict[pkt.header.src][pkt.header.id] = []
                    runningDict[pkt.header.src][pkt.header.id].append(pkt)
                elif pkt.header.id not in runningDict[pkt.header.src].keys():
                    runningDict[pkt.header.src][pkt.header.id] = []
                    runningDict[pkt.header.src][pkt.header.id].append(pkt)
                else:
                    runningDict[pkt.header.src][pkt.header.id].append(pkt)
                #check list to see if msg is ready to display
                if checkPackets(runningDict[pkt.header.src][pkt.header.id], network.getMTU()):
                    #>> reconstruct message and print
                    generateMessage(runningDict[pkt.header.src][pkt.header.id])
                    runningDict[pkt.header.src][pkt.header.id].clear()
                    #display message
            else:
                continue
        except socket.timeout as e:
            #no recv ->> just loop man!
            pass
        except socket.error as i:
            #not sure which one gets activated
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
    ipCIDR = "192.168.1.1/24" #debug only values
    lladdr = "1024"
    ipCIDR = sys.argv[1]
    lladdr = sys.argv[2]
    temp = ipCIDR.split('/')
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
    network = Network(connection, ipaddr, int(subnet))
    network.ARPTable[ipaddr] = lladdr #add entry to ARP? Not sure if needed yet
    #create listen thread and let it run
    listenThread = threading.Thread(target=listen, args=(network,), daemon=True)
    listenThread.start()
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


