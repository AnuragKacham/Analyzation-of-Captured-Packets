/**
 * @author Anurag Kacham
 *
 * pktanalyzer.java
 **/

 import java.util.Scanner;
 import java.nio.file.Files;
 import java.nio.file.Paths;
 import java.io.IOException;

public class pktanalyzer {
    public static void main(String[] args) throws IOException {
        String path = parse(args);
        byte[] filebytes =  Files.readAllBytes(Paths.get(path));
        int len = filebytes.length;
        System.out.println("----- Ether Header -----");
        System.out.println("Packet size = " + len + " bytes");
        byte[] ipdata = new byte[len - 14];
        byte[] etherdata = new byte[14];
        System.arraycopy(filebytes, 0, etherdata, 0, 14);
        etherheaderdata(etherdata);
        System.arraycopy(filebytes, 14, ipdata, 0, n - 14);
        ipheaderdata(ipdata);
    }

    static String parse(String[] args) {
        String filepath = "";
        if(args.length == 1) filepath = args[0];
        else if(args.length == 0){
        	  System.out.println("Path : ");
            Scanner scan = new Scanner(System.in);
            filepath = scan.nextLine();
            scan.close();
        }
        else{
            System.out.println("Wrong format");
            System.exit(1);
        }
        return filepath;
    }

     public static void etherheaderdata(byte[] dataether) {
         System.out.print("Destination = ");
         for (int i = 0; i < 6; i++) {
             String str = String.format("%02X", dataether[i]).toLowerCase();
             if (i == 5) {
            	 System.out.print(str + ",");
             } else {
            	 System.out.print(str + ":");
             }
         }
         System.out.print("\nSource = ");
         for (int i = 6; i < 12; i++) {
             String str = String.format("%02X", dataether[i]).toLowerCase();
             if (i == 11) {
            	 System.out.print(str + ";");
             } else {
            	 System.out.print(str + ":");
             }
         }
         System.out.print("\nEthertype = ");
         for (int i = 12; i < 14; i++) {
        	 String str = String.format("%02X", dataether[i]);
        	 if(i == 13) {
                 System.out.print(str + " (IP)"\n);
             }
             else {
                 System.out.print(str);
             }
         }
         System.out.println();
     }

     public static void ipheaderdata(byte[] dataip){
         byte[] header = new byte[argument2.length];
         int[] ipdata = new int[dataip.length];
         for(int i=0; i<dataip.length; i++) {
             ipdata[i] = dataip[i]&0xff;
         }
         System.out.println("-------- IP Header --------");
         System.out.println("Version = " + (ipdata[0]>>4));
         System.out.println("Header Length = " + (((ipdata[0]&(1<<4)-1)*32)/8) + " bytes");
         System.out.println("Types of Service = 0x" + (String.format("%02X", ipdata[1])));
         System.out.println("    xxx. .... = 0 (precedence)");
         (ipdata[1]>>4&(1<<1)-1) != 0 ? System.out.println("    ...1 .... = Low Delay") : System.out.println("    ...0 .... = Normal Delay");
         (ipdata[1]>>3&(1<<1)-1) != 0 ? System.out.println("    .... 1... = High Throughput") : System.out.println("    .... 0... = Normal Throughput");
         (ipdata[1]>>2&(1<<1)-1) != 0 ? System.out.println("    .... .1.. = High Reliability") : System.out.println("    .... .0.. = Normal Reliability");
         System.out.println("Total length = " + (ipdata[2]<<8|ipdata[3]) + " bytes");
         System.out.println("Identification = " + (ipdata[4]<<8|ipdata[5]));
         System.out.println("Flags = 0x" + (String.format("%02X", ipdata[6]>>5)));
         (ipdata[6]>>6&(1<<1)-1) != 0 ? System.out.println("    .1.. .... = do not fragment") : System.out.println("    .0.. .... = do fragment");
         (ipdata[6]>>5&(1<<1)-1) != 0 ? System.out.println("    ..1. .... = more fragments") : System.out.println("    ..0. .... = last fragment");
         System.out.println("Fragment offset = " + (((ipdata[6]&31)<<8)|ipdata[7]) + " bytes");
         System.out.println("Time to live = " + ipdata[8] + " seconds/hops");
         if(bytedata[9] == 1) System.out.println("Protocol = " + ipdata[9] + " (ICMP)");
         else if (bytedata[9] == 6) System.out.println("Protocol = " + ipdata[9] + " (TCP)");
         else if (bytedata[9] == 17) System.out.println("Protocol = " + ipdata[9] + " (UDP)");
         else System.out.println("Protocol = " + ipdata[9] + " (ARP)");
         System.out.println("Header checksum = 0x" + (String.format("%02X", (ipdata[10]<<8)| ipdata[11])).toLowerCase());
         System.out.println("Source IP address = " + ipdata[12] + "." + ipdata[13] + "." + ipdata[14] + "." +
                 ipdata[15]);
         System.out.println("Destination IP address = " + ipdata[16] + "." + ipdata[17] + "." + ipdata[18] + "."
                 + ipdata[19]);
         if ((ipdata[0]&(1<<4)-1) > 5){
             int size = ((ipdata[0]&(1<<4)-1)*32)/8;
             System.arraycopy(dataip, 20 + size - 20, header, 0, dataip.length - size);
             System.out.println("Options = " + (size - 20) + " bytes");
         } else {
             System.arraycopy(dataip, 20, header, 0, dataip.length - 20);
             System.out.println("No options");
         }
         if (dataip[9] == 1){
        	 icmpheaderdata(header);
         }
         else if (dataip[9] == 6){
             tcpheaderdata(header);
         }
         else if (dataip[9] == 17){
             udpheaderdata(header);
         }
         else{
             arpheaderdata(dataip);
         }
    }

    public static void udpheaderdata(byte[] dataudp){
        int k = 0;
        int[] header = new int[dataudp.length];
        int headerlength = header.length;
        for(int i=0; i<dataudp.length; i++) {
            header[i] = dataudp[i]&0xff;
        }
        System.out.println("-------- UDP Header --------");
        System.out.println("Source port = " + ((header[0]<<8)|header[1]));
        System.out.println("Destination port = " + ((header[2]<<8)|header[3]));
        System.out.println("Length = " + (header[5]|(header[4]<<8)));
        System.out.println("Checksum = 0x" + (String.format("%02X", (header[6]<<8)|header[7])).toLowerCase());
        byte[] databytes = new byte[headerlength - 8];
        int datalength = databytes.length;
        System.arraycopy(dataudp, 8, databytes, 0, datalength);
        System.out.println("Data = (first 64 bytes)\n ");
        for (int i = 8; i<headerlength; i++) {
        	if(k % 8 == 0) {
            System.out.print("\n");
        	}
        	else {
        		k++;
            System.out.print(String.format("%02X", (header[i])).toLowerCase() + " ");
        	}
        }
        System.out.println("\n");
    }

    public static void tcpheaderdata(byte[] datatcp){
        int k = 0;
        byte[] header = new byte[datatcp.length];
        long[] databybits = new long[datatcp.length];
        for(int i=0; i<datatcp.length; i++) {
            databybits[i] = datatcp[i]&0xff;
        }
        System.out.println("----- TCP Header -----");
        System.out.println("Source port = " + ((databybits[0]<<8)|databybits[1]));
        System.out.println("Destination port = " + ((databybits[2]<<8)|databybits[3]));
        System.out.println("Sequence Number = " + ((databybits[4]<<24)|(databybits[5]<<16)|(databybits[6]<<8)|databybits[7]));
        System.out.println("Acknowledgement Number = " + (((databybits[8]<<24)| (databybits[9]<<16)|(databybits[10]<<8)|
                databybits[11])));
        System.out.println("Data Offset = " + (databybits[12]>>4&(1<<4)-1) + " 32 bytes");
        System.out.println("Flags = 0x" + (String.format("%02X", ((databybits[13]&((1<<6)-1))))));
        (databybits[13]>>5&(1<<1)-1) == 0 ? System.out.println("    ..0. .... = No Urgent Pointer") : System.out.println("    ..1. .... = Urgent Pointer");
        (databybits[13]>>4&(1<<1)-1) == 0 ? System.out.println("    ...0 .... = No Acknowledgement") : System.out.println("    ...1 .... = Acknowledgement");
        (databybits[13]>>3&(1<<1)-1) == 0 ? System.out.println("    .... 0... = No Push Request") : System.out.println("    .... 1... = Push Request");
        (databybits[13]>>2&(1<<1)-1) == 0 ? System.out.println("    .... .0.. = No Reset") : System.out.println("    .... .1.. = Reset");
        (databybits[13]>>1&(1<<1)-1) == 0 ? System.out.println("    .... ..0. = No Syn") : System.out.println("    .... ..1. = Syn");
        (databybits[13]&(1<<1)-1) == 0 ? System.out.println("    .... ...0 = No Fin") : System.out.println("    .... ...1 = Fin");
        System.out.println("Window = " + ((databybits[14]<<8)|databybits[15]));
        System.out.println("TCP Checksum = 0x" + (String.format("%02X", (databybits[16]<<8)|
                (databybits[17]))).toLowerCase());
        System.out.println("Urgent Pointer = " + ((databybits[18]<<8)|databybits[19]));
        if (databybits[12]>>4 >5) {
            int len = (int) ((databybits[12]>>4)*32)/8;
            System.arraycopy(datatcp, len - 20, header, 0, databybits.length - len);
            System.out.println("TCP Header has Options of length " + (len - 20) + " bytes");
        } else {
            System.arraycopy(datatcp, 20, header, 0, databybits.length - 20);
            System.out.println("TCP Header has No options");
        }
        System.out.println("TCP Payload/Data:\n ");
        System.out.println("Hexadecimal Values = ");
        for (int i = 0; i<databybits.length; i++) {
            k++;
            System.out.print(String.format("%02X", (header[i])) + " ");
            if (k % 8 == 0) System.out.print("\n");
        }
        System.out.println("\n");
    }

    public static void icmpheaderdata(byte[] dataicmp){
        long[] header = new long[dataicmp.length];
        for(int i=0; i<dataicmp.length; i++) {
            header[i] = dataicmp[i]& 0xff;
        }
        System.out.println("-------- ICMP Header --------");
        System.out.println("Message Type = " + (header[0]));
        System.out.println("Code = " + (header[1]));
        System.out.println("ICMP Checksum = 0x" + (String.format("%02x", (header[2]<<8)|(header[3]))));
    }

    public static void arpheaderdata(byte[] dataarp){
        long[] header = new long[dataarp.length];
        for(int i=0; i<dataarp.length; i++) {
            header[i] = dataarp[i]& 0xff;
        }
        System.out.println("-------- ARP Header --------");
        System.out.println("From Opcode");
        if (((header[6]<<8)|header[7]) == 1) {
            System.out.println("ARP Request");
        }
        else{
            System.out.println("ARP Response");
        }
        System.out.println("Hardware Type = " + ((header[0]<<8)|header[1]));
        System.out.print("Protocol Type = 0x" + (String.format("%02x", (header[2]<<8)|header[3])));
        if (((header[2]<<8)|header[3]) == 2048){
            System.out.println(" (IPv4)");
        }
        System.out.println("Hardware Address Length = " + (header[4]));
        System.out.println("Protocol Address Length = " + (header[5]));
        System.out.print("Operation Request Code = " + ((header[6]<<8)|header[7]));
        if (((header[6]<<8)|header[7]) == 1) {
            System.out.println(" (ARP Request)");
        }
        else{
            System.out.println(" (ARP Response)");
        }
        System.out.print("Source Hardware Address = ");
        for (int i = 8; i < 14; i++) {
            String s = String.format("%02X", header[i]);
            if (i != 13) {
              System.out.print(s + ":");
            } else {
              System.out.println(s);
            }
        }
        System.out.print("Source Protocol Address = ");
        String startaddr = "";
        for (int i = 14; i < 18; ++i)
        {
            long t = 0xFF & header[i];
            startaddr += "." + t;
        }
        startaddr = startaddr.substring(1);
        System.out.println(startaddr);
        System.out.print("Target Hardware Address = ");
        for (int i = 18; i <= 23; i++) {
            String st = String.format("%02X", header[i]);
            if (i != 23) {
              System.out.print(st + ":");
            } else {
              System.out.println(st);
            }
        }
        System.out.print("Target Protocol Address = ");
        StringBuilder destaddr = new StringBuilder();
        for (int i = 24; i < 28; ++i)
        {
            long t = 0xFF & header[i];
            destaddr.append(".").append(t);
        }
        destaddr = new StringBuilder(destaddr.substring(1));
        System.out.println(destaddr);
    }
}
