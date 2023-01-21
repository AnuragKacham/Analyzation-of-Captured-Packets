# README

This assignment is aimed to compute a program that reads a series of network packets provided by the user and produces a summary of those packets along with their header. The program can extract the different headers of the following type of packets namely,  UDP, TCP, ICMP and, ARP and these captured packets in the binary file and are further displayed.

1. Initially we understand the file type from the command line and return the file or filename given by the user in the input

2. After decoding the Ethernet Header from the network packet as provided by the user, we convert Single Byte Integer value to 2-character Hexadecimal so as to extract the headers and information. Then a function is written to decode the IP header from network packet by taking an input from byte array which contains the IP frame.

3. After decoding the ether header, depending upon the offset, the type of protocol will be determined and based on that, the header data for that particular protocol can be decoded using bitwise operators.

The code ensures that the file is of correct type and also outputs all the details at all the respective offsets.
