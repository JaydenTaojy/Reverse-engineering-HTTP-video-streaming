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
    #if ip.p != 17:
    #    continue
    #filter on UDP assigned ports for DNS
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
      if (re.search('youtube', answer.name) or re.search('googlevideo', answer.name)):
         #print(answer.name)
         #print("match google succeed")
         try:
           #print(socket.inet_ntoa(answer.ip))
           #print("match google succeed")
           ip_list.append(socket.inet_ntoa(answer.ip))
           name_list.append(answer.name)
           #print(type(socket.inet_ntoa(answer.ip)))
         except:
           continue

seg_number=[]
seg_datasize=[]
for i in range(len(ip_list)):
  request,seg=False,False
  seg_num,seg_size=0,0
  seg_data=[]
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
     if(socket.inet_ntoa(ip.src)==ip_list[i]):
          #print(ip_list[i])
          try:
            tcp = ip.data
          except:
            continue
          #if(seg==True):
           #seg_num+=1
          seg_size+=len(eth.data)
          #seg_size+=len(tcp.data)
             
     elif(socket.inet_ntoa(ip.dst)==ip_list[i]):
         #print(ip_list[i])
         try:
            tcp = ip.data
         except:
            continue
         #print(len(tcp.data))
         if(request==False and len(tcp.data)>0):
              #print(len(tcp.data))
              #seg=False
              request=True
              seg_data.append(seg_size)
              seg_size=0
           #the last request upstream has sent
         elif(request==True and len(tcp.data)==0):
              request=False
              seg_num+=1
              #seg=True
  seg_number.append(seg_num)
  seg_datasize.append(seg_data)
  
for i in range(len(seg_number)):
    for j in seg_datasize[i]:
       if j<500:
         seg_number[i]-=1
         seg_datasize[i].remove(j)
         
print('domain name:')
print(name_list)
print('ip list:')
print(ip_list)
print('segment number counter for each ip:')
print(seg_number)
print('2 dimension segment datasize list for each ip:')
print(seg_datasize)

