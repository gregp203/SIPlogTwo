# SIPlogTwo
Log reader for "tcpdump -i any -nn -A -tttt port 5060" stdout type of SIP message logs.

Requires .NET Framework 4.5

Usage: SIPlogTwo.exe logfile.log anotherlogfile.log ...

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

The reges strings in the class and "if" sequences in the "ReadData" method could be changed to match the format of the log file you are working with.
