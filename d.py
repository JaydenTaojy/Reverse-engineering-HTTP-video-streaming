import dpkt
import math
import struct
import socket
import re

f = open('youtube_lap.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
yname,yip_list=[],[]
for time, buff in pcap:
   try:
     eth=dpkt.ethernet.Ethernet(buff)
   except:
     continue
   if eth.type != 2048:
        continue
   try:
        ip = eth.data
   except:
        continue
   try:
        udp = ip.data
   except:
        continue
   try:
        dns = dpkt.dns.DNS(udp.data)
   except:
        continue

   if dns.qr != dpkt.dns.DNS_R:
     continue
   if dns.opcode != dpkt.dns.DNS_QUERY:
     continue
   if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
     continue
   if len(dns.an) < 1:
     continue
   
   for answer in dns.an:
      #print(type(answer.name))
      if (re.search('youtube', answer.name) or re.search('googlevideo', answer.name)):
      #or answer.name.find('google')
         #print(answer.name)
         #print("match google succeed")
         try:
           #print(socket.inet_ntoa(answer.ip))
           #print("match google succeed")
           yip_list.append(socket.inet_ntoa(answer.ip))
           yname.append(answer.name)
           #print(type(socket.inet_ntoa(answer.ip)))
         except:
           continue
print('print the domain name and ip belongs to youtube:')
print(yname)
print(yip_list)

f= open('dailymotion_lap.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

dname,dip_list=[],[]
for time, buff in pcap:
   try:
     eth=dpkt.ethernet.Ethernet(buff)
   except:
     continue
   if eth.type != 2048:
        continue
   try:
        ip = eth.data
   except:
        continue
   try:
        udp = ip.data
   except:
        continue
   try:
        dns = dpkt.dns.DNS(udp.data)
   except:
        continue

   if dns.qr != dpkt.dns.DNS_R:
     continue
   if dns.opcode != dpkt.dns.DNS_QUERY:
     continue
   if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
     continue
   if len(dns.an) < 1:
     continue
   
   for answer in dns.an:
      if (re.search('dailymotion', answer.name) or re.search('dmwww', answer.name) or re.search('dmcdn', answer.name)):
          
          #print(answer.name)
          #print("match dailymotion succeed")
          try:
        #print(socket.inet_ntoa(answer.ip))
        #print("match google succeed")
            dip_list.append(socket.inet_ntoa(answer.ip))
            dname.append(answer.name)
        #print(type(socket.inet_ntoa(answer.ip)))
          except:
            continue
print('print the domain name and ip belongs to dailymotion:')
print(dname)
print(dip_list)

f = open('vimeo_lap.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

vname,vip_list=[],[]
for time, buff in pcap:
   try:
     eth=dpkt.ethernet.Ethernet(buff)
   except:
     continue
   if eth.type != 2048:
        continue
   try:
        ip = eth.data
   except:
        continue
   try:
        udp = ip.data
   except:
        continue
   try:
        dns = dpkt.dns.DNS(udp.data)
   except:
        continue

   if dns.qr != dpkt.dns.DNS_R:
     continue
   if dns.opcode != dpkt.dns.DNS_QUERY:
     continue
   if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
     continue
   if len(dns.an) < 1:
     continue
   
   for answer in dns.an:
      if (re.search('vimeo', answer.name)):
        #print(answer.name)
        #print("match vimeo succeed")
        try:
      #print(socket.inet_ntoa(answer.ip))
      #print("match google succeed")
          vip_list.append(socket.inet_ntoa(answer.ip))
          vname.append(answer.name)
      #print(type(socket.inet_ntoa(answer.ip)))
        except:
          continue
print('print the domain name and ip belongs to vimeo:')
print(vname)
print(vip_list)
