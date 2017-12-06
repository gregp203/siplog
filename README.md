# siplog
Log reader for "tcpdump -i any -nn -A -tttt port 5060" stdout type of SIP message logs.

Usage: siplog.exe logfile.log anotherlogfile.log ...

Features
* Reads logs and finds all the SIP messages 
* Does not retain the log file in memory to keep memory utilization low 
* Can open multiple large log files at a time
* Finds all the call leg and notify call flows
* List all the calls in order in a filterable list
* Toggle the list to show notifys
* Select multiple call legs
* Diagram the call flows of the selected call legs
* Disply the full SIP message read from the log file by selecting the message fro mthe call flow diagram
* Search SIP messages by regular expresion
* include ports in the source and destination addresses

edit the findmessages function to match the string for begining of SIP message.
it determines the end of the message when it matches the begining of the next message.
The array for each message:

the line number of the fie for first line of the SIP message [0]
date[1] 
time[2]
src IP[3]
dst IP[4]
request or response[5] 
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
