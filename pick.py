#-*- coding:utf-8 -*-
import scapy.all as scapy
from scapy.layers import http
import sys
import os

def WriteFile(file, data):
    with open('./text/'+file,'ab') as f:
        f.write(data)

class Packet:
    def __init__(self,p):
        self.pkt=p

class Http(Packet):
    def parse(self):
        http_s=self.pkt.filter(lambda r:r.haslayer('HTTP'))
        for p in http_s:
            head=bytes('\n'+p.summary()+'\n',encoding='utf-8')
            WriteFile("http.bin",head)
            WriteFile("http.bin", bytes(p['TCP'].payload))

class Ftp(Packet):
    def parse(self):
        tcps=self.pkt.filter(lambda r:r.haslayer('TCP'))
        ftps=tcps.filter(lambda r:r['TCP'].sport==21 or r['TCP'].dport==21)
        for p in ftps:
            head=bytes('\n'+p.summary()+'\n',encoding='utf-8')
            WriteFile("ftp.bin",head)
            WriteFile("ftp.bin", bytes(p['TCP'].payload))

class Icmp(Packet):
    def parse(self):
        icmps=self.pkt.filter(lambda r:r.haslayer('ICMP'))
        for p in icmps:
            head=bytes('\n'+p.summary()+'\n',encoding='utf-8')
            WriteFile("ICMP.bin",head)
            WriteFile("ICMP.bin", bytes(p['ICMP']))

class Arp(Packet):
    def parse(self):
        arps=self.pkt.filter(lambda r:r.haslayer('ARP'))
        for p in arps:
            if p['ARP'].op==1:
                op=" Request"
            else:
                op=" Reply"
        hwsrc="srcMAC : "+str(p['ARP'].hwsrc)
        psrc="srcIP : "+str(p['ARP'].psrc)
        hwdst="dstMAC : "+str(p['ARP'].hwdst)
        pdst="dstIP : "+str(p['ARP'].pdst)
        data='\n'+op+'\n'+hwsrc+'\n'+psrc+'\n'+hwdst+'\n'+pdst+'\n'
        WriteFile("arp.bin",bytes(data,encoding='utf-8'))

#udp
#udps=packets.filter(lambda r:r.haslayer('UDP'))
#for p in udps:
#    head=bytes('\n'+p.summary()+'\n',encoding='ascii')
#    WriteFile("udp.bin",head)
#    WriteFile("udp.bin", bytes(p['UDP'].payload))

class Modbus(Packet):
    def parse(self):
        tcps=self.pkt.filter(lambda r:r.haslayer('TCP'))
        modbus=tcps.filter(lambda r:r.haslayer('Raw') and (r['TCP'].sport==502 or r['TCP'].dport==502))
        for m in modbus:
            load=m.load
            fc=load[7]
            head='\n'+m.summary()+'\n'
            if fc==3:
                if m['TCP'].sport==502:
                    op="fc:03 Read Holding Registers\n"
                    Type="response\n"
                    bytecount="byte count : "+str(load[8])+'\n'
                    reg='register values :\n'
                    text=''
                    i=0
                    while i<len(load)-9:
                        reg+="%02x"%load[9+i]+"%02x"%load[9+i+1]+'\n'
                        text=text+chr(load[9+i])+chr(load[9+i+1])
                        i=i+2
                    data=head+op+Type+bytecount+reg+text+'\n'
                    #pdb.set_trace()
                    WriteFile("modbus_03.bin",bytes(data,encoding='utf-8'))
            elif fc==16:
                if m['TCP'].dport==502:
                    op="fc:16 Write Holding Registers\n"
                    refnum="reference num : "+str(int("%02x"%load[8]+"%02x"%load[9],16))+'\n'
                    wordcount="word count : "+str(int("%02x"%load[10]+"%02x"%load[11],16))+'\n'
                    bytecount="byte count : "+str(load[12])+'\n'
                    reg='register values :\n'
                    text=''
                    for i in range(load[12]):
                        reg+="%02x"%load[13+i]+' '
                        text+=chr(load[13+i])
                    data=head+op+refnum+wordcount+bytecount+reg+'\n'+text+'\n'
                    WriteFile("modbus_16.bin",bytes(data,encoding='utf-8'))
            elif fc==1:
                if m['TCP'].sport==502:
                    op="fc:01 Read Coils\n"
                    Type="response\n"
                    bytecount="byte count : "+str(load[8])+'\n'
                    coil='coil status bit :\n'
                    text=''
                    for i in range(load[8]):
                        bits=[]
                        s=''
                        tmp=load[9+i]
                        for j in range(8):
                            bits.append(tmp&1)
                            tmp=tmp>>1
                        for k in bits:
                            s+=str(k)
                        coil=coil+s+' '
                        text+=chr(int(s,2))
                    data=head+op+Type+bytecount+coil+'\n'+text+'\n'
                    WriteFile("modbus_01.bin",bytes(data,encoding='utf-8'))
            elif fc==15:
                if m['TCP'].dport==502:
                    op='fc:15 Write Multiple Coils\n'
                    refnum="reference num : "+str(int("%02x"%load[8]+"%02x"%load[9],16))+'\n'
                    bitcount="bit count : "+str(int("%02x"%load[10]+"%02x"%load[11],16))+'\n'
                    bytecount="byte count : "+str(load[12])+'\n'
                    Data='data : \n'
                    text=''
                    for i in range(load[12]):
                        bits=[]
                        s=''
                        tmp=load[13+i]
                        for j in range(8):
                            bits.append(tmp&1)
                            tmp=tmp>>1
                        for k in bits:
                            s+=str(k)
                        n=int(s,2)
                        Data=Data+"%02x"%n+' '
                        text+=chr(n)
                    data=head+op+refnum+bitcount+bytecount+Data+'\n'+text+'\n'
                    WriteFile("modbus_15.bin",bytes(data,encoding='utf-8'))

class S7comm(Packet):
    def parse(self):
        tcps=self.pkt.filter(lambda r:r.haslayer('TCP'))
        s7comm=tcps.filter(lambda r:r.haslayer('Raw') and (r['TCP'].sport==102 or r['TCP'].dport==102))
        for s7 in s7comm:
            load=s7.load
            if load[7]==50:
                head='\n'+s7.summary()+'\n'
                datalength=int("%02x"%load[15]+"%02x"%load[16],16)-4
                length='data length : '+str(datalength)+'\n'
                Data='data : \n'
                text=''
                if s7['TCP'].sport==102 and load[19]==4:
                    op='fc:04 Read Var\n'
                    for i in range(datalength):
                        Data+="%02x"%load[25+i]
                        text+=chr(int("%02x"%load[25+i],16))
                    data=head+op+length+Data+'\n'+text+'\n'
                    WriteFile("s7comm_readVar.bin",bytes(data,encoding='utf-8'))
                elif s7['TCP'].dport==102 and load[17]==5:
                    op='fc:05 Write Var\n'
                    for i in range(datalength):
                        Data+="%02x"%load[35+i]
                        text+=chr(int("%02x"%load[35+i],16))
                    data=head+op+length+Data+'\n'+text+'\n'
                    WriteFile("s7comm_writeVar.bin",bytes(data,encoding='utf-8'))

def parse_factory(dir,protocol):
    try:
        p=scapy.rdpcap(dir)
    except Exception as e:
        print('\n找不到该数据包...\n\n')
        sys.exit(0)
    try:    
        os.mkdir('./text')
    except Exception as e:
        pass
    protocol=protocol.lower()
    if protocol=='http':
        x=Http(p)
        x.parse()
    elif protocol=='ftp':
        x=Ftp(p)
        x.parse()
    elif protocol=='icmp':
        x=Icmp(p)
        x.parse()
    elif protocol=='arp':
        x=Arp(p)
        x.parse()
    elif protocol=='modbus':
        x=Modbus(p)
        x.parse()
    elif protocol=='s7comm':
        x=S7comm(p)
        x.parse()
    else:
        print('\n不支持 '+protocol+' ...\n\n')
        sys.exit(0)

print('\n'+'-'*100)
print('\n')
print('支持协议： http  ftp  icmp  arp  modbus  s7comm')
print('-'*50)
dir=input('数据包路径 ：')
protocol=input('\n解析协议 ：')
parse_factory(dir,protocol)

print('结果输出在text文件夹...\n\ndone!\n')


