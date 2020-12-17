import dpkt
import socket
import re

f = open('youtube_lap.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
name_list=[]
ip_list=[]
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
         try:
           #print(socket.inet_ntoa(answer.ip))
           #print("match google succeed")
           ip_list.append(socket.inet_ntoa(answer.ip))
           name_list.append(answer.name)
           #print(type(socket.inet_ntoa(answer.ip)))
         except:
           continue
in_num=[0]*len(ip_list)
in_data=[0]*len(ip_list)
out_num=[0]*len(ip_list)
out_data=[0]*len(ip_list)

f = open('youtube_lap.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
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

     for i in range(len(ip_list)):
       if(socket.inet_ntoa(ip.src)==ip_list[i]):
          try:
           tcp = ip.data
          except:
            continue
          in_num[i]+=1
          in_data[i]+=ip.len
       elif(socket.inet_ntoa(ip.dst)==ip_list[i]):
         try:
           tcp = ip.data
         except:
           continue
         out_num[i]+=1
         out_data[i]+=ip.len
         
print(name_list)
print(ip_list)
print('packet number from service to clent:')
print(in_num)
print('data size from service to clent:')
print(in_data)
print('packet number from client to service:')
print(out_num)
print('data size from client to service:')
print(out_data)
