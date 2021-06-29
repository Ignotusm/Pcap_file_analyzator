import scapy.utils

#extsubor arrays

etherTypes=[]
LSAPs=[]
ipProtocols=[]
tcpPorts=[]
udpPorts=[]

#externy icmp protokols
icmp_protokol=[]
icmp3=[]
icmp5=[]
icmp11=[]
icmp12=[]


#bod 4 filter packets

http_packets=[]
https_packets=[]
telnet_packets=[]
ssh_packets=[]
ftp_riadiace_packets=[]
ftp_datove_packets=[]
tftp_packets=[]
icmp_packets=[]
arp_packets=[]

#IPv4 packets
IPv4_packets={}

#HELP FUNCTION

def getBits(byte):

    binary = bin(byte)
    binary = binary[2:]
    binary = binary[3:]

    return int(binary,2)

def searchSynBit(byte):

    binary = "{:04b}".format(byte)
    #eltavolitsuk a 0b-t


    if(binary[-2]=="1"):
        return True

    return False

def searchFinBit(byte):
    binary = "{:04b}".format(byte)
    # eltavolitsuk a 0b-t


    if (binary[-1] == "1"):
        return True

    return False

def searchRstBit(byte):
    binary = "{:04b}".format(byte)

    if (binary[-3] == "1"):
        return True

    return False

#===========FILE HANDLING===========

#open output folder
def openTxt():

    file = open('vystup.txt','a')
    return file

#clear output folder
def clearTxt():

    file = open('vystup.txt','w')
    file.write("")

def readTypes():

    f = open("externyvstup.txt", "r")
    exterNum = 0
    for i in f:
        if (i[0] == "#"):
            exterNum = exterNum + 1
            continue
        i = i.rstrip()
        if (exterNum == 1):
            etherTypes.append(i.split(" "))
        elif (exterNum == 2):
            LSAPs.append(i.split(" "))
        elif (exterNum == 3):
            ipProtocols.append(i.split(" "))
        elif (exterNum == 4):
            tcpPorts.append(i.split(" "))
        elif (exterNum == 5):
            udpPorts.append(i.split(" "))

def readICMPTypes():

    f = open("ICMP_Codes.txt")

    for i in f:
        i = i.strip()
        icmp_protokol.append(i.split(" "))
    f.close()

    f=open("ICMP_3.txt")
    for i in f:
        i = i.strip()
        icmp3.append(i.split(" "))
    f.close()

    f=open("ICMP_5.txt")
    for i in f:
        i = i.strip()
        icmp5.append(i.split(" "))
    f.close()

    f=open("ICMP_11.txt")
    for i in f:
        i = i.strip()
        icmp11.append(i.split(" "))
    f.close()

    f=open("ICMP_12.txt")
    for i in f:
        i = i.strip()
        icmp12.append(i.split(" "))

#read pcap subor
def readPcap(nazov):

    filename = '{}'.format(nazov)
    lst = []
    mt = []

    for i, j in scapy.utils.RawPcapReader(filename):
        lst.append(i)
        mt.append(j)

    mt.clear()

    return lst

#-=-=-=-=-=-=-=-=-=-=-=-=-=- Write in output folder -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#

#!!!!!!!!!!!!!!!!!!!!!!   Altalanos infok   !!!!!!!!!!!!!!!!!!!!!!!#

#kiirja hanyadik ramecot nezzuk
def vypisRamec(i, file):
    file.write("Ramec {}\n".format(i + 1))

#kiirja milyen hosszu az adott ramec
def vypisDlzkuRamca(packet,file):

    if len(packet)<60:
        #print("dlzka ramca poskytnuta pcap API - {} B".format(len(packet)))
        file.write("dlzka ramca poskytnuta pcap API - {} B\n".format(len(packet)))
        #print("dlzka ramca poskytnuta po mediu - {} B".format(64))
        file.write("dlrzka ramca poskytnuta po mediu - {} B\n".format(64))
    else:
        #print("dlzka ramca poskytnuta pcap API - {} B".format(len(packet)))
        file.write("dlzka ramca poskytnuta pcap API - {} B\n".format(len(packet)))
        #print("dlzka ramca poskytnuta po mediu - {} B".format(len(packet)+4))
        file.write("dlzka ramca poskytnuta po mediu - {} B\n".format(len(packet)+4))

#kiirjaHexben az egesz filet
def vypisPacketToHex(packet,file):

    enter=False

    for i in range(1,len(packet)+1):
        #print("{:02x} ".format(packet[i-1]),end="")
        file.write("{:02x} ".format(packet[i-1]))

        if(i%16==0):
            #print("  ",end="")
            file.write(" ")
        if (i%32 ==0) :
            #print()
            enter=True
            file.write("\n")
            continue

        enter=False

    if(enter==False):
        #print("Nincs enter")
        file.write("\n")

    file.write("\n")

#______________________________Layer 2_____________________________#

#kiirja a MAC addreszat a kuldonek
def vypisZdrojovaMacAdresa(packet,file):
    #print("Zdrojova MAC adresa: ",end="")
    file.write("Cielova MAC adresa: ")
    for i in range(6):
        #print("{:02x} ".format(packet[i]),end="")
        file.write("{:02x} ".format(packet[i]))
    #print()
    file.write("\n")

#kiirja Cel MAC addreszat
def vypisCielovaMacAdresa(packet,file):
    #print("Cielova MAC adresa: ",end="")
    file.write("Zdrojova MAC adresa: ")
    for i in range(6):
        #print("{:02x} ".format(packet[i+6]),end="")
        file.write("{:02x} ".format(packet[i+6]))
    #print()
    file.write("\n")

#megnezzuk milyen fajta ramecrol beszelunk
def typRamca(packet,file,packet_number):

    num = int(packet[12]) * 16 * 16 + int(packet[13])

    #ethernet II
    if (num > 1500):
        file.write("Ethernet II\n")
        #nezzuk tovabb
        getEtherTyp(packet,num,file,packet_number)
    #IEEE 802.3
    else:
        #IEEE 802.3 LLC SNAP
        if(packet[14]==170 and packet[15]==170):
            file.write("IEE 802.3 - LLC + SNAP\n")
        #IEEE 802.3 RAW
        elif(packet[14]==255 and packet[15]==255):
            file.write("IEE 802.3 - Raw\n")
        #IEEE 802.3 LLC
        else:
            file.write("IEE 802.3 - LLC\n")
            #nezzuk tovabb
            getIEEETyp(packet[14],packet[15],file,packet_number)

def getEtherTyp(packet,num,file,packet_number):

    type=""

    for i in etherTypes:
        if (num == int(i[0])):
            type=i[1]
            file.write("{}\n".format(i[1]))
            break
    else:
        file.write("?\n")

    if(type=="IPv4"):
        getIPv4(packet,file,packet_number)
    elif(type=="ARP"):
        arp_packets.append([packet,packet_number])



#==========================    Layer3  =======================#
def getIEEETyp(DSAP,SSAP,file,packet_number):
    for i in LSAPs:
        if(DSAP == int(i[0]) and SSAP == int(i[0])):
            file.write("{}\n".format(i[1]))
            break
    else:
        file.write("?\n")

def getIPv4(packet,file,packet_number):

    getSourceIPv4Address(packet,file)
    getDestIPv4Address(packet,file)
    getIPv4Protocol(packet, file,packet_number)


def getIPv4Protocol(packet,file,packet_number):

    type=""

    header_Length=int(getBits(packet[14]))*4
    #print(header_Length)

    for i in ipProtocols:

        if (packet[23]==int(i[0])):
            type=i[1]
            file.write("{}\n".format(i[1]))
            break
    else:
        file.write("?\n")

    if(type=="TCP"):
        #print(header_Length)
        #print("TCP")
        getTCP(packet,header_Length,file,packet_number)
    elif(type=="UDP"):
        #print(header_Length)
        #print("UDP")
        getUDP(packet,header_Length,file,packet_number)
    elif(type=="ICMP"):
        file.write("ICMP\n")
        icmp_packets.append([packet,packet_number])



def getSourceIPv4Address(packet,file):

   # ipAddress=""

    file.write("Source IP : ")

    for i in range(0,4):
        #ipAddress+="{}".format(packet[26+i])
        file.write("{}".format(packet[26+i]))
        if i < 3:

            file.write(":")
    file.write("\n")


def getVanillaDestIPv4Address(packet,file):

    file.write("Destination IP : ")

    for i in range(0,4):
        #ipAddress+="{}".format(packet[30+i])
        file.write("{}".format(packet[30+i]))
        if i < 3:
            #ipAddress+=":"
            file.write(":")
    file.write("\n")


def getDestIPv4Address(packet,file):

    ipAddress=""
    num = 1

    file.write("Destination IP : ")

    for i in range(0,4):
        ipAddress+="{}".format(packet[30+i])
        file.write("{}".format(packet[30+i]))
        if i < 3:
            ipAddress+=":"
            file.write(":")
    file.write("\n")
    #print(ipAddress)

    if ipAddress in IPv4_packets:
        num=IPv4_packets.get(ipAddress)
        #print(num)
        num+=1

    IPv4_packets[ipAddress]=num

#==================Layer 4===========#

#TCP
def getTCP(packet,prevHeaderSize,file,packet_number):
    #print(hex(packet[14+prevHeaderSize]))
    #print(hex(packet[14+prevHeaderSize+1]))

    type=""

    num = int(packet[14+prevHeaderSize]) * 16 * 16 + int(packet[14+prevHeaderSize+1])
    #print("Port :")
   # print(num)
    file.write("Source port : {}   ".format(num))
    for i in tcpPorts:

        if (num==int(i[0])):
            type=i[1]
            file.write("{}\n".format(i[1]))
            break
    else:
        file.write("?\n")

    if (type=="HTTP"):
       # print("HTTP!!!!!!!!!!!!")
        http_packets.append([packet,packet_number])
    elif (type=="HTTPS"):
       # print("HTTPS!!!")
        https_packets.append([packet,packet_number])
    elif (type=="TELNET"):
       # print("TELNET")
        telnet_packets.append([packet,packet_number])
    elif (type=="SSH"):
       # print("SSH")
        ssh_packets.append([packet,packet_number])
    elif (type=="FTP_control"):
       # print("FTP_control")
        ftp_riadiace_packets.append([packet,packet_number])
    elif (type=="FTP_data"):
        ftp_datove_packets.append([packet,packet_number])


    type=""

    num = int(packet[14 + prevHeaderSize+2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
    #print("Dest Port :")
    #print(num)
    file.write("Destination port : {}   ".format(num))
    for i in tcpPorts:

        if (num==int(i[0])):
            type=i[1]
            file.write("{}\n".format(i[1]))
            break
    else:
        file.write("?\n")

    if (type=="HTTP"):
        #print("HTTP!!!!!!!!!!!!")
        http_packets.append([packet,packet_number])
    elif (type=="HTTPS"):
        #print("HTTPS!!!")
        https_packets.append([packet,packet_number])
    elif (type=="TELNET"):
        #print("TELNET")
        telnet_packets.append([packet,packet_number])
    elif (type=="SSH"):
       # ("SSH")
        ssh_packets.append([packet,packet_number])
    elif (type=="FTP_control"):
       # print("FTP_control")
        ftp_riadiace_packets.append([packet,packet_number])
    elif (type=="FTP_data"):
        ftp_datove_packets.append([packet,packet_number])

#UDP
def getUDP(packet,prevHeaderSize,file,packet_number):
   # print(hex(packet[14+prevHeaderSize]))
   # print(hex(packet[14+prevHeaderSize+1]))

    type=""

    num = int(packet[14+prevHeaderSize]) * 16 * 16 + int(packet[14+prevHeaderSize+1])
  #  print("Port :")
   # print(num)
    file.write("Source port : {}   ".format(num))
    for i in udpPorts:

        if (num==int(i[0])):
            type=i[1]
            file.write("{}\n".format(i[1]))
            break
    else:
        file.write("?\n")

    #print("Type :")
    #print(type)

    if (type == "TFTP"):
        tftp_packets.append([packet, packet_number])


    num = int(packet[14 + prevHeaderSize+2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
    #print("Dest Port :")
    #print(num)
    file.write("Destination port : {}   ".format(num))
    for i in udpPorts:

        if (num==int(i[0])):
            type=i[1]
            file.write("{}\n".format(i[1]))
            break
    else:
        file.write("?\n")

    #print("Dest Type :")
    #print(type)

    if (type == "TFTP"):
        tftp_packets.append([packet, packet_number])

#------------------   3)    ---------------#
def vypisZoznamIPv4Packetov(file):

    maximum=0
    ipAddress=""

    file.write("\n")

    file.write("\n\nZoznam IPv4 packetov : \n\n")

    for i in IPv4_packets:
        value = IPv4_packets.get(i)
        if maximum<value:
            maximum=value
            ipAddress=i

        #print("{} : {}".format(i,value))
        file.write("{} : {}\n".format(i,value))

   # print()

    file.write("\n")

    #print("najvacsi pocet packetov dostal adresa :{} - {}".format(ipAddress,maximum))
    file.write("najvacsi pocet packetov dostal ip adresa :{} - pocet : {}\n\n\n".format(ipAddress,maximum))

def packetAnalyzator(nazov):

    #megtisztitsuk a kimeno fajlt es megnyissuk
    clearTxt()
    file = openTxt()

    #beolvassuk a typeokat
    readTypes()

    #beolvassuk az ICMP typokat
    readICMPTypes()
    #eloszor beolvassuk a pcap subort
    packets=readPcap(nazov)

    for i in range(0,len(packets)):
        #beirja hogy hanyadik ramec
        vypisRamec(i,file)
        #beirja a ramecok hosszat
        vypisDlzkuRamca(packets[i],file)
        #kiirja a zdrojova MAC Addreszat
        vypisZdrojovaMacAdresa(packets[i],file)
        #kiirj a cielova MAC addreszat
        vypisCielovaMacAdresa(packets[i],file)
        #kirja hogy micsoda ez
        typRamca(packets[i],file,i)
        #kiirja az egesz packetot hexformatumban
        vypisPacketToHex(packets[i],file)

    vypisZoznamIPv4Packetov(file)

    httpFilter(file)
    httpsFilter(file)
    telnetFilter(file)
    sshFilter(file)
    ftp_control_Filter(file)
    ftp_data_Filter(file)

    icmp_Filter(file)


#============filterezes================

def httpFilter(file):

    syn_packets=[]
    fin_packets=[]
    rst_packets=[]
    full_comunication=[]
    almost_comunication=[]
    findit=False

    #packet_index
    syn_start=0

    #stat searching in http packets
    for i in http_packets:

        packet=i[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])

        #search syn packets
        if(searchSynBit(packet[14+prevHeaderSize+13])):
            syn_packets.append(i)
        #search fin packets
        if(searchFinBit(packet[14 + prevHeaderSize + 13])):
            fin_packets.append(i)
        #search rst packets
        try:
            if(searchRstBit(packet[14+prevHeaderSize+13])):
                rst_packets.append(i)
        except(Exception):
            print(Exception)

    #check if sync is empty
    if len(syn_packets)==0:
        file.write("No HTTP communication found from the start\n\n")
        return

    #check for full comunication
    for i in syn_packets:
        packet=i[0]

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"

        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        #set to random port
        searchPort=0

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        #nezzuk a final packetot search for fin packet
        for j in fin_packets:
            finpacket=j[0]

            fin_source_ipAddress = ""
            for i in range(0, 4):
                fin_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    fin_source_ipAddress += ":"

            fin_dest_ipAddress = ""
            for i in range(0, 4):
                fin_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    fin_dest_ipAddress += ":"

            prevHeaderSize = getBits(finpacket[14]) * 4
            fin_source_port = int(finpacket[14 + prevHeaderSize]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 1])
            fin_destination_port = int(finpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 3])

            #ha talalunk finalt akkor osszerakjuk a komunikaciot when we find final we start search for the other packeges for the kommunikation
            if(searchPort==fin_source_port or searchPort==fin_destination_port and ((source_ipAddress==fin_source_ipAddress or source_ipAddress==fin_dest_ipAddress)or(dest_ipAddress==fin_source_ipAddress or dest_ipAddress==fin_dest_ipAddress))):
                #search the randomport in http packets
                for k in http_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])
                    #if we have the exact packet we add to the full_communication
                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)
                #if we get one final like our syn we got the communication and we didnt continue searching
                findit=True
                break
            #if we findit than we break it
            if findit:
                break
        if findit:
            break

        #nezzuk az reset packetot
        for l in rst_packets:
            rstpacket=l[0]

            rst_source_ipAddress = ""
            for i in range(0, 4):
                rst_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    rst_source_ipAddress += ":"

            rst_dest_ipAddress = ""
            for i in range(0, 4):
                rst_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    rst_dest_ipAddress += ":"

            prevHeaderSize = getBits(rstpacket[14]) * 4
            rst_source_port = int(rstpacket[14 + prevHeaderSize]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 1])
            rst_destination_port = int(rstpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 3])

            if (searchPort == rst_source_port or searchPort == rst_destination_port and ((source_ipAddress==rst_source_ipAddress or source_ipAddress==rst_dest_ipAddress)or(dest_ipAddress==rst_source_ipAddress or dest_ipAddress==rst_dest_ipAddress))):
                # megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in http_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit = True

                break

            if findit:
                break

        if findit:
            break



    #keresunk egy random komunikaciot
    if(findit==False and syn_packets):

        p = syn_packets[0]
        packet=p[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])

        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"

        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        # megkeressuk az osszes olyan packetot amiben van ez a random port
        for k in http_packets:
            fullpacket = k[0]

            full_source_ipAddress = ""
            for i in range(0, 4):
                full_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    full_source_ipAddress += ":"

            full_dest_ipAddress = ""
            for i in range(0, 4):
                full_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    full_dest_ipAddress += ":"

            prevHeaderSize = getBits(fullpacket[14]) * 4
            full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
            full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(
                fullpacket[14 + prevHeaderSize + 3])

            if (searchPort == full_source_port or searchPort == full_destination_port and (
                    (source_ipAddress == full_source_ipAddress or source_ipAddress == full_dest_ipAddress) or (
                    dest_ipAddress == full_source_ipAddress or dest_ipAddress == full_dest_ipAddress))):
                full_comunication.append(k)

    file.write("\n\n")
    file.write("Comunication HTTP \n")
    file.write("\n\n")

    if len(full_comunication)!=0:
        for i in full_comunication:
            # beirja hogy hanyadik ramec
            vypisRamec(i[1], file)
            # beirja a ramecok hosszat
            vypisDlzkuRamca(i[0], file)
            # kiirja a zdrojova MAC Addreszat
            vypisZdrojovaMacAdresa(i[0], file)
            # kiirj a cielova MAC addreszat
            vypisCielovaMacAdresa(i[0], file)
            # kirja hogy micsoda ez
            typRamca(i[0], file, i[1])
            # kiirja az egesz packetot hexformatumban
            vypisPacketToHex(i[0], file)

def httpsFilter(file):

    syn_packets=[]
    fin_packets=[]
    rst_packets=[]
    full_comunication=[]
    almost_comunication=[]
    findit=False

    #packet_index
    syn_start=0

    #megnezek minden packetot
    for i in https_packets:

        packet=i[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])

        if(searchSynBit(packet[14+prevHeaderSize+13])):
            syn_packets.append(i)

        if(searchFinBit(packet[14 + prevHeaderSize + 13])):
            fin_packets.append(i)

        try:
            if(searchRstBit(packet[14+prevHeaderSize+13])):
                rst_packets.append(i)
        except(Exception):
            print(Exception)

    #check if sync is empty
    if len(syn_packets)==0:
        file.write("No HTTPS communication found from the start\n\n")
        return

    #check for full comunication
    for i in syn_packets:
        packet=i[0]

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"

        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        searchPort=0

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        #nezzuk a final packetot
        for j in fin_packets:
            finpacket=j[0]

            fin_source_ipAddress = ""
            for i in range(0, 4):
                fin_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    fin_source_ipAddress += ":"

            fin_dest_ipAddress = ""
            for i in range(0, 4):
                fin_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    fin_dest_ipAddress += ":"

            prevHeaderSize = getBits(finpacket[14]) * 4
            fin_source_port = int(finpacket[14 + prevHeaderSize]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 1])
            fin_destination_port = int(finpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 3])

            if(searchPort==fin_source_port or searchPort==fin_destination_port and ((source_ipAddress==fin_source_ipAddress or source_ipAddress==fin_dest_ipAddress)or(dest_ipAddress==fin_source_ipAddress or dest_ipAddress==fin_dest_ipAddress))):
                #megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in https_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit=True

                break

            if findit:
                break

        if findit:
            break

        #nezzuk az reset packetot
        for l in rst_packets:
            rstpacket=l[0]

            rst_source_ipAddress = ""
            for i in range(0, 4):
                rst_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    rst_source_ipAddress += ":"

            rst_dest_ipAddress = ""
            for i in range(0, 4):
                rst_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    rst_dest_ipAddress += ":"

            prevHeaderSize = getBits(rstpacket[14]) * 4
            rst_source_port = int(rstpacket[14 + prevHeaderSize]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 1])
            rst_destination_port = int(rstpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 3])

            if (searchPort == rst_source_port or searchPort == rst_destination_port and ((source_ipAddress==rst_source_ipAddress or source_ipAddress==rst_dest_ipAddress)or(dest_ipAddress==rst_source_ipAddress or dest_ipAddress==rst_dest_ipAddress))):
                # megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in https_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit = True
                break

            if findit:
                break

        if findit:
            break
    #keresunk egy random komunikaciot
    if(findit==False and syn_packets):

        p = syn_packets[0]
        packet=p[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"

        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        # megkeressuk az osszes olyan packetot amiben van ez a random port
        for k in https_packets:
            fullpacket = k[0]

            full_source_ipAddress = ""
            for i in range(0, 4):
                full_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    full_source_ipAddress += ":"

            full_dest_ipAddress = ""
            for i in range(0, 4):
                full_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    full_dest_ipAddress += ":"

            prevHeaderSize = getBits(fullpacket[14]) * 4
            full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
            full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(
                fullpacket[14 + prevHeaderSize + 3])

            if (searchPort == full_source_port or searchPort == full_destination_port and (
                    (source_ipAddress == full_source_ipAddress or source_ipAddress == full_dest_ipAddress) or (
                    dest_ipAddress == full_source_ipAddress or dest_ipAddress == full_dest_ipAddress))):
                full_comunication.append(k)

    file.write("\n\n")
    file.write("Comunication HTTPS \n")
    file.write("\n\n")

    if len(full_comunication)!=0:
        for i in full_comunication:
            # beirja hogy hanyadik ramec
            vypisRamec(i[1], file)
            # beirja a ramecok hosszat
            vypisDlzkuRamca(i[0], file)
            # kiirja a zdrojova MAC Addreszat
            vypisZdrojovaMacAdresa(i[0], file)
            # kiirj a cielova MAC addreszat
            vypisCielovaMacAdresa(i[0], file)
            # kirja hogy micsoda ez
            typRamca(i[0], file, i[1])
            # kiirja az egesz packetot hexformatumban
            vypisPacketToHex(i[0], file)

def telnetFilter(file):

    syn_packets=[]
    fin_packets=[]
    rst_packets=[]
    full_comunication=[]
    almost_comunication=[]
    findit=False

    #packet_index
    syn_start=0

    #megnezek minden packetot
    for i in telnet_packets:

        packet=i[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])

        if(searchSynBit(packet[14+prevHeaderSize+13])):
            syn_packets.append(i)

        if(searchFinBit(packet[14 + prevHeaderSize + 13])):
            fin_packets.append(i)

        try:
            if(searchRstBit(packet[14+prevHeaderSize+13])):
                rst_packets.append(i)
        except(Exception):
            print(Exception)

    #check if sync is empty
    if len(syn_packets)==0:
        file.write("No TELNET communication from start\n\n")
        return

    #check for full comunication
    for i in syn_packets:
        packet=i[0]

        source_ipAddress=""

        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"


        dest_ipAddress = ""


        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        searchPort=0

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        #nezzuk a final packetot
        for j in fin_packets:
            finpacket=j[0]

            fin_source_ipAddress = ""
            for i in range(0, 4):
                fin_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    fin_source_ipAddress += ":"

            fin_dest_ipAddress = ""
            for i in range(0, 4):
                fin_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    fin_dest_ipAddress += ":"

            prevHeaderSize = getBits(finpacket[14]) * 4
            fin_source_port = int(finpacket[14 + prevHeaderSize]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 1])
            fin_destination_port = int(finpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 3])

            if(searchPort==fin_source_port or searchPort==fin_destination_port and ((source_ipAddress==fin_source_ipAddress or source_ipAddress==fin_dest_ipAddress)or(dest_ipAddress==fin_source_ipAddress or dest_ipAddress==fin_dest_ipAddress))):
                #megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in telnet_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit=True
                break

            if findit:
                break

        if findit:
            break

        #nezzuk az reset packetot
        for l in rst_packets:
            rstpacket=l[0]

            rst_source_ipAddress = ""
            for i in range(0, 4):
                rst_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    rst_source_ipAddress += ":"

            rst_dest_ipAddress = ""
            for i in range(0, 4):
                rst_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    rst_dest_ipAddress += ":"

            prevHeaderSize = getBits(rstpacket[14]) * 4
            rst_source_port = int(rstpacket[14 + prevHeaderSize]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 1])
            rst_destination_port = int(rstpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 3])

            if (searchPort == rst_source_port or searchPort == rst_destination_port and ((source_ipAddress==rst_source_ipAddress or source_ipAddress==rst_dest_ipAddress)or(dest_ipAddress==rst_source_ipAddress or dest_ipAddress==rst_dest_ipAddress))):
                # megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in telnet_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit = True

                break

            if findit:
                break


        if findit:
            break
    #keresunk egy random komunikaciot
    if(findit==False and syn_packets):

        p = syn_packets[0]
        packet=p[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"

        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        #print(source_ipAddress)
       # print(dest_ipAddress)

        # megkeressuk az osszes olyan packetot amiben van ez a random port
        for k in telnet_packets:
            fullpacket = k[0]

            full_source_ipAddress = ""
            for i in range(0, 4):
                full_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    full_source_ipAddress += ":"

            full_dest_ipAddress = ""
            for i in range(0, 4):
                full_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    full_dest_ipAddress += ":"

            prevHeaderSize = getBits(fullpacket[14]) * 4
            full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
            full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(
                fullpacket[14 + prevHeaderSize + 3])

            if (searchPort == full_source_port or searchPort == full_destination_port and (
                    (source_ipAddress == full_source_ipAddress or source_ipAddress == full_dest_ipAddress) or (
                    dest_ipAddress == full_source_ipAddress or dest_ipAddress == full_dest_ipAddress))):
                full_comunication.append(k)


    file.write("\n\n")
    file.write("Comunication TELNET \n")
    file.write("\n\n")

    if len(full_comunication)!=0:
        for i in full_comunication:
            # beirja hogy hanyadik ramec
            vypisRamec(i[1], file)
            # beirja a ramecok hosszat
            vypisDlzkuRamca(i[0], file)
            # kiirja a zdrojova MAC Addreszat
            vypisZdrojovaMacAdresa(i[0], file)
            # kiirj a cielova MAC addreszat
            vypisCielovaMacAdresa(i[0], file)
            # kirja hogy micsoda ez
            typRamca(i[0], file, i[1])
            # kiirja az egesz packetot hexformatumban
            vypisPacketToHex(i[0], file)

def sshFilter(file):

    syn_packets=[]
    fin_packets=[]
    rst_packets=[]
    full_comunication=[]
    almost_comunication=[]
    findit=False

    #packet_index
    syn_start=0

    #megnezek minden packetot
    for i in ssh_packets:

        packet=i[0]

        prevHeaderSize=getBits(packet[14])*4

        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])

        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])

        if(searchSynBit(packet[14+prevHeaderSize+13])):
            syn_packets.append(i)

        if(searchFinBit(packet[14 + prevHeaderSize + 13])):
            fin_packets.append(i)

        try:
            if(searchRstBit(packet[14+prevHeaderSize+13])):
                rst_packets.append(i)
        except(Exception):
            print(Exception)

    #check if sync is empty
    if len(syn_packets)==0:
        #print("No comunication from start")
        file.write("No SSH communication from the start\n\n")
        return

    #check for full comunication
    for i in syn_packets:
        packet=i[0]

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"


        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        searchPort=0

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        #nezzuk a final packetot
        for j in fin_packets:
            finpacket=j[0]

            fin_source_ipAddress = ""
            for i in range(0, 4):
                fin_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    fin_source_ipAddress += ":"

            fin_dest_ipAddress = ""
            for i in range(0, 4):
                fin_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    fin_dest_ipAddress += ":"

            prevHeaderSize = getBits(finpacket[14]) * 4
            fin_source_port = int(finpacket[14 + prevHeaderSize]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 1])
            fin_destination_port = int(finpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 3])

            if(searchPort==fin_source_port or searchPort==fin_destination_port and ((source_ipAddress==fin_source_ipAddress or source_ipAddress==fin_dest_ipAddress)or(dest_ipAddress==fin_source_ipAddress or dest_ipAddress==fin_dest_ipAddress))):
                #megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in ssh_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit=True
                break

            if findit:
                break

        if findit:
            break

        #nezzuk az reset packetot
        for l in rst_packets:
            rstpacket=l[0]

            rst_source_ipAddress = ""
            for i in range(0, 4):
                rst_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    rst_source_ipAddress += ":"

            rst_dest_ipAddress = ""
            for i in range(0, 4):
                rst_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    rst_dest_ipAddress += ":"

            prevHeaderSize = getBits(rstpacket[14]) * 4
            rst_source_port = int(rstpacket[14 + prevHeaderSize]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 1])
            rst_destination_port = int(rstpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 3])

            if (searchPort == rst_source_port or searchPort == rst_destination_port and ((source_ipAddress==rst_source_ipAddress or source_ipAddress==rst_dest_ipAddress)or(dest_ipAddress==rst_source_ipAddress or dest_ipAddress==rst_dest_ipAddress))):
                # megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in ssh_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit = True
                break

            if findit:
                break

        if findit:
            break
    #keresunk egy random komunikaciot
    if(findit==False and syn_packets):

        p = syn_packets[0]
        packet=p[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"

        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        # megkeressuk az osszes olyan packetot amiben van ez a random port
        for k in ssh_packets:
            fullpacket = k[0]

            full_source_ipAddress = ""
            for i in range(0, 4):
                full_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    full_source_ipAddress += ":"

            full_dest_ipAddress = ""
            for i in range(0, 4):
                full_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    full_dest_ipAddress += ":"

            prevHeaderSize = getBits(fullpacket[14]) * 4
            full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
            full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(
                fullpacket[14 + prevHeaderSize + 3])

            if (searchPort == full_source_port or searchPort == full_destination_port and (
                    (source_ipAddress == full_source_ipAddress or source_ipAddress == full_dest_ipAddress) or (
                    dest_ipAddress == full_source_ipAddress or dest_ipAddress == full_dest_ipAddress))):
                full_comunication.append(k)

    file.write("\n\n")
    file.write("Comunication SSH \n")
    file.write("\n\n")

    if len(full_comunication)!=0:
        for i in full_comunication:
            # beirja hogy hanyadik ramec
            vypisRamec(i[1], file)
            # beirja a ramecok hosszat
            vypisDlzkuRamca(i[0], file)
            # kiirja a zdrojova MAC Addreszat
            vypisZdrojovaMacAdresa(i[0], file)
            # kiirj a cielova MAC addreszat
            vypisCielovaMacAdresa(i[0], file)
            # kirja hogy micsoda ez
            typRamca(i[0], file, i[1])
            # kiirja az egesz packetot hexformatumban
            vypisPacketToHex(i[0], file)

def ftp_control_Filter(file):

    syn_packets=[]
    fin_packets=[]
    rst_packets=[]
    full_comunication=[]
    almost_comunication=[]
    findit=False

    #packet_index
    syn_start=0

    #megnezek minden packetot
    for i in ftp_riadiace_packets:

        packet=i[0]

        prevHeaderSize=getBits(packet[14])*4

        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])

        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])

        if(searchSynBit(packet[14+prevHeaderSize+13])):
            syn_packets.append(i)

        if(searchFinBit(packet[14 + prevHeaderSize + 13])):
            fin_packets.append(i)

        try:
            if(searchRstBit(packet[14+prevHeaderSize+13])):
                rst_packets.append(i)
        except(Exception):
            print(Exception)

    #check if sync is empty
    if len(syn_packets)==0:
        #print("No comunication from start")
        file.write("No FTP Control communication from the start\n\n")
        return

    #check for full comunication
    for i in syn_packets:
        packet=i[0]

        source_ipAddress=""

        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"


        dest_ipAddress = ""


        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        searchPort=0

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        #nezzuk a final packetot
        for j in fin_packets:
            finpacket=j[0]

            fin_source_ipAddress = ""
            for i in range(0, 4):
                fin_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    fin_source_ipAddress += ":"

            fin_dest_ipAddress = ""
            for i in range(0, 4):
                fin_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    fin_dest_ipAddress += ":"

            prevHeaderSize = getBits(finpacket[14]) * 4
            fin_source_port = int(finpacket[14 + prevHeaderSize]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 1])
            fin_destination_port = int(finpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 3])

            if(searchPort==fin_source_port or searchPort==fin_destination_port and ((source_ipAddress==fin_source_ipAddress or source_ipAddress==fin_dest_ipAddress)or(dest_ipAddress==fin_source_ipAddress or dest_ipAddress==fin_dest_ipAddress))):
                #megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in ftp_riadiace_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit=True

                break

            if findit:
                break

        #nezzuk az reset packetot
        for l in rst_packets:
            rstpacket=l[0]

            rst_source_ipAddress = ""
            for i in range(0, 4):
                rst_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    rst_source_ipAddress += ":"

            rst_dest_ipAddress = ""
            for i in range(0, 4):
                rst_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    rst_dest_ipAddress += ":"

            prevHeaderSize = getBits(rstpacket[14]) * 4
            rst_source_port = int(rstpacket[14 + prevHeaderSize]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 1])
            rst_destination_port = int(rstpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 3])

            if (searchPort == rst_source_port or searchPort == rst_destination_port and ((source_ipAddress==rst_source_ipAddress or source_ipAddress==rst_dest_ipAddress)or(dest_ipAddress==rst_source_ipAddress or dest_ipAddress==rst_dest_ipAddress))):
                # megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in ftp_riadiace_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit = True
                break

            if findit:
                break

        if findit:
            break
    #keresunk egy random komunikaciot
    if(findit==False and syn_packets):

        p = syn_packets[0]
        packet=p[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"

        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        # megkeressuk az osszes olyan packetot amiben van ez a random port
        for k in ftp_riadiace_packets:
            fullpacket = k[0]

            full_source_ipAddress = ""
            for i in range(0, 4):
                full_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    full_source_ipAddress += ":"

            full_dest_ipAddress = ""
            for i in range(0, 4):
                full_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    full_dest_ipAddress += ":"

            prevHeaderSize = getBits(fullpacket[14]) * 4
            full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
            full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(
                fullpacket[14 + prevHeaderSize + 3])

            if (searchPort == full_source_port or searchPort == full_destination_port and (
                    (source_ipAddress == full_source_ipAddress or source_ipAddress == full_dest_ipAddress) or (
                    dest_ipAddress == full_source_ipAddress or dest_ipAddress == full_dest_ipAddress))):
                full_comunication.append(k)

    file.write("\n\n")
    file.write("Comunication FTP Control \n")
    file.write("\n\n")

    if len(full_comunication)!=0:
        for i in full_comunication:
            # beirja hogy hanyadik ramec
            vypisRamec(i[1], file)
            # beirja a ramecok hosszat
            vypisDlzkuRamca(i[0], file)
            # kiirja a zdrojova MAC Addreszat
            vypisZdrojovaMacAdresa(i[0], file)
            # kiirj a cielova MAC addreszat
            vypisCielovaMacAdresa(i[0], file)
            # kirja hogy micsoda ez
            typRamca(i[0], file, i[1])
            # kiirja az egesz packetot hexformatumban
            vypisPacketToHex(i[0], file)

def ftp_data_Filter(file):

    syn_packets=[]
    fin_packets=[]
    rst_packets=[]
    full_comunication=[]
    almost_comunication=[]
    findit=False

    #packet_index
    syn_start=0

    #megnezek minden packetot
    for i in ftp_datove_packets:

        packet=i[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])

        if(searchSynBit(packet[14+prevHeaderSize+13])):
            syn_packets.append(i)

        if(searchFinBit(packet[14 + prevHeaderSize + 13])):
            fin_packets.append(i)

        try:
            if(searchRstBit(packet[14+prevHeaderSize+13])):
                rst_packets.append(i)
        except(Exception):
            print(Exception)

    #check if sync is empty
    if len(syn_packets)==0:
        file.write("No FTP Data communication from the start\n\n")
        return

    #check for full comunication
    for i in syn_packets:
        packet=i[0]

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"


        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        searchPort=0

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        #nezzuk a final packetot
        for j in fin_packets:
            finpacket=j[0]

            fin_source_ipAddress = ""
            for i in range(0, 4):
                fin_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    fin_source_ipAddress += ":"

            fin_dest_ipAddress = ""
            for i in range(0, 4):
                fin_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    fin_dest_ipAddress += ":"

            prevHeaderSize = getBits(finpacket[14]) * 4
            fin_source_port = int(finpacket[14 + prevHeaderSize]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 1])
            fin_destination_port = int(finpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(finpacket[14 + prevHeaderSize + 3])

            if(searchPort==fin_source_port or searchPort==fin_destination_port and ((source_ipAddress==fin_source_ipAddress or source_ipAddress==fin_dest_ipAddress)or(dest_ipAddress==fin_source_ipAddress or dest_ipAddress==fin_dest_ipAddress))):
                #megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in ftp_datove_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit=True
                break

            if findit:
                break

        if findit:
            break

        #nezzuk az reset packetot
        for l in rst_packets:
            rstpacket=l[0]

            rst_source_ipAddress = ""
            for i in range(0, 4):
                rst_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    rst_source_ipAddress += ":"

            rst_dest_ipAddress = ""
            for i in range(0, 4):
                rst_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    rst_dest_ipAddress += ":"

            prevHeaderSize = getBits(rstpacket[14]) * 4
            rst_source_port = int(rstpacket[14 + prevHeaderSize]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 1])
            rst_destination_port = int(rstpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(rstpacket[14 + prevHeaderSize + 3])

            if (searchPort == rst_source_port or searchPort == rst_destination_port and ((source_ipAddress==rst_source_ipAddress or source_ipAddress==rst_dest_ipAddress)or(dest_ipAddress==rst_source_ipAddress or dest_ipAddress==rst_dest_ipAddress))):
                # megkeressuk az osszes olyan packetot amiben van ez a random port

                for k in ftp_datove_packets:
                    fullpacket = k[0]

                    full_source_ipAddress = ""
                    for i in range(0, 4):
                        full_source_ipAddress += "{}".format(packet[26 + i])
                        if i < 3:
                            full_source_ipAddress += ":"

                    full_dest_ipAddress = ""
                    for i in range(0, 4):
                        full_dest_ipAddress += "{}".format(packet[30 + i])
                        if i < 3:
                            full_dest_ipAddress += ":"

                    prevHeaderSize = getBits(fullpacket[14]) * 4
                    full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
                    full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 3])

                    if(searchPort==full_source_port or searchPort==full_destination_port and ((source_ipAddress==full_source_ipAddress or source_ipAddress==full_dest_ipAddress)or(dest_ipAddress==full_source_ipAddress or dest_ipAddress==full_dest_ipAddress))):
                        full_comunication.append(k)

                findit = True

                break

            if findit:
                break


        if findit:
            break
    #keresunk egy random komunikaciot
    if(findit==False and syn_packets):

        p = syn_packets[0]
        packet=p[0]

        prevHeaderSize=getBits(packet[14])*4
        source_port = int(packet[14 + prevHeaderSize]) * 16 * 16 + int(packet[14 + prevHeaderSize + 1])
        destination_port = int(packet[14 + prevHeaderSize + 2]) * 16 * 16 + int(packet[14 + prevHeaderSize + 3])
        if(source_port!=80):
            searchPort=source_port
        else:
            searchPort=destination_port

        source_ipAddress=""
        for i in range(0, 4):
            source_ipAddress+="{}".format(packet[26+i])
            if i < 3:
                source_ipAddress+=":"

        dest_ipAddress = ""
        for i in range(0, 4):
            dest_ipAddress += "{}".format(packet[30 + i])
            if i < 3:
                dest_ipAddress += ":"

        # megkeressuk az osszes olyan packetot amiben van ez a random port
        for k in ftp_datove_packets:
            fullpacket = k[0]

            full_source_ipAddress = ""
            for i in range(0, 4):
                full_source_ipAddress += "{}".format(packet[26 + i])
                if i < 3:
                    full_source_ipAddress += ":"

            full_dest_ipAddress = ""
            for i in range(0, 4):
                full_dest_ipAddress += "{}".format(packet[30 + i])
                if i < 3:
                    full_dest_ipAddress += ":"

            prevHeaderSize = getBits(fullpacket[14]) * 4
            full_source_port = int(fullpacket[14 + prevHeaderSize]) * 16 * 16 + int(fullpacket[14 + prevHeaderSize + 1])
            full_destination_port = int(fullpacket[14 + prevHeaderSize + 2]) * 16 * 16 + int(
                fullpacket[14 + prevHeaderSize + 3])

            if (searchPort == full_source_port or searchPort == full_destination_port and (
                    (source_ipAddress == full_source_ipAddress or source_ipAddress == full_dest_ipAddress) or (
                    dest_ipAddress == full_source_ipAddress or dest_ipAddress == full_dest_ipAddress))):
                full_comunication.append(k)

    file.write("\n\n")
    file.write("Comunication FTP_DATA \n")
    file.write("\n\n")

    if len(full_comunication)!=0:
        for i in full_comunication:
            # beirja hogy hanyadik ramec
            vypisRamec(i[1], file)
            # beirja a ramecok hosszat
            vypisDlzkuRamca(i[0], file)
            # kiirja a zdrojova MAC Addreszat
            vypisZdrojovaMacAdresa(i[0], file)
            # kiirj a cielova MAC addreszat
            vypisCielovaMacAdresa(i[0], file)
            # kirja hogy micsoda ez
            typRamca(i[0], file, i[1])
            # kiirja az egesz packetot hexformatumban
            vypisPacketToHex(i[0], file)

def icmp_Filter(file):


    #print("ICMP ::::")

    #print(icmp_protokol)
    #print(icmp3)
    #print(icmp5)
    #print(icmp11)
    #print(icmp12)
    #print(icmp_packets)

    if len(icmp_packets)==0:
        file.write("No ICMP packets found \n\n")
        return
    else:
        file.write("ICMP Packets :\n\n")

    for i in icmp_packets:
        packet = i[0]

        prevHeaderSize=getBits(packet[14])*4

        type = packet[14+prevHeaderSize]
        code = packet[14+prevHeaderSize+1]

        vypisRamec(i[1], file)
        vypisDlzkuRamca(i[0], file)
        vypisZdrojovaMacAdresa(i[0], file)
        vypisCielovaMacAdresa(i[0], file)
        file.write("IPv4\n")
        getSourceIPv4Address(i[0],file)
        getVanillaDestIPv4Address(i[0],file)
        file.write("ICMP\n")

        if(type == 3):
            for k in icmp3:
                if(code == int(k[0])):
                 #   print("TYPE 3  code : {}".format(k[1]))
                    file.write("Type 3  code : {}\n".format(k[1]))
                    break
            else:
                #print("Type 3 code ?\n")
                file.write("Type 3 code ?\n")
        elif(type == 5):
            for k in icmp5:
                if(code == int(k[0])):
                   # print("ICMPT Type 5 code {}".format(k[1]))
                    file.write("Type 5 code {}\n".format(k[1]))
                    break
                else:
                  #  print("ICMP Type 5 code ?")
                    file.write("Type 5 code ?\n")
        elif(type ==11):
            for k in icmp11:
                if(code==int(k[0])):
                 #   print("ICMP type 11 code {}".format(k[1]))
                    file.write("Type 11 code {}\n".format(k[1]))
                    break
            else:
                #print("ICMP Type 11 code ?")
                file.write("Type 11 code ?\n")
        elif(type ==12):
            for k in icmp12:
                if(code==int(k[0])):
                 #   print("ICMPT type 12 code {}".format(k[1]))
                    file.write("Type 12 code {}\n".format(k[1]))
                    break
            else:
                #print("ICMP Type 12 code ?")
                file.write("Type 12 code ?\n")
        else:
            for k in icmp_protokol:
                if(type==int(k[0])):
                 #   print("ICMP Type {} {}".format(k[0],k[1]))
                    file.write("Type {} {}\n".format(k[0],k[1]))
                    break
            else:
                #print("Type ?  ({})".format(type))
                file.write("Type ?  ({})\n".format(type))



        file.write("\n")
        #vypisPacketToHex(i[0], file)



#_______________________main______________________________
nazov = input("Add full file path :")

packetAnalyzator(nazov)






