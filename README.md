# siplog
Log reader for tcpdump -A stdout of SIP messages

Usage: siplog.exe logfile.log anotherlogfile.log ...

edit the findmessages method to match the string for begining of SIP message.
it determines the end of the message when it matches the begining of the next message.
The array for each message:

the line number of the fie for first line of the SIP message [0], 
date[1] 
time[2]
src IP[3]
dst IP[4]
first line of SIP msg[5] 
Call-ID[6]
To:[7]  
From:[8]
the line number of the fie for last line of the SIP message [9]
color of the message when dispalyed in the diagram [10]
if the message has SDP [11]
filename [12]
the ip address offered/answered in SDP  [13]
the port offered/answered in SDP [14]
the first codec offered/answered in SDP [15]
useragent or server[16]
