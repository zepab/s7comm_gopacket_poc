# s7comm_gopacket_poc

This is a proof of concept for decoding the Siemens S7 protocol using go langage and gopacket library.

The goal of this tool is to perform a post processing of a network capture (wireshark pcap file)
and extract informations about memory write and memory read instructions.

provided .pcap files to test comes from https://github.com/automayt/ICS-pcap/tree/master/S7

Those network captures contains exchanges done between Siemens PLC using S7comm protocol.
This protocol is not officially documented but they are plenty resources on the web to understand it.
Also latest version of wireshark directly include a S7comm dissector  

This tool consist of one go file 
gopacket library has been used to ease reading of wireshark capture and packet extraction.
Even if I did use gopacket, I have not developped a custom layer but with the present code
this is easy to turn it into a custom layer if needed.

As this is the first time I use go, there might some improvement to perform.

Please check comments in the code and note the following restrictions:

  - tcp and TPKT packet reassembly are not considered
  - we don't expect malicious packet and thus we trust the S7comm protocol about item count versus data length available
  - all write and read request return sucessfull answer (todo handle failed request)

A list of remaining work would be: 

- make automatic correlation of request and answers. 
 (this can be easly achieved using the combination of ip address and port number and the RequestID).

- display information in a more user firendly way using enum to translate raw value into human readable text.

- add more information about packet analyzed (pcap entry number, timestamp).

- use something different than the tcp flow in order to have also the src and dest ip address information instead of only the src and dest port number.


## Getting Started

### Installing

of course you need to have go compiler installed on your host, cf https://golang.org/doc/install
once installed you need to download the gopacket library from github :
go get github.com/google/gopacket


### Running the tool

just ask go to compile and run the main.go file using following args:
 go run main.go -r s7comm_varservice_libnodavedemo_bench.pcap | tee result.log

sample content for Write instructions:
4272->102|requestID=2|WRITE REQ[1]|VarType:18|Var Length:10|SyntaxId:16|TransportSize:2|length:4|dbnumber:0x0|dbarea:0x83|dbaddress:0x000000|value(4):77100002
102->4272|requestID=2|WRITE ANS[1]|result(0xff)

sample content for Read instructions for more than one item in a single request:
4272->102|requestID=2005|READ REQ[1]|VarType:18|Var Length:10|SyntaxId:16|TransportSize:2|length:6|dbnumber:0x0|dbarea:0x81|dbaddress:0x000000
4272->102|requestID=2005|READ REQ[2]|VarType:18|Var Length:10|SyntaxId:16|TransportSize:2|length:6|dbnumber:0x0|dbarea:0x83|dbaddress:0x000000
4272->102|requestID=2005|READ REQ[3]|VarType:18|Var Length:10|SyntaxId:16|TransportSize:2|length:6|dbnumber:0x0|dbarea:0x83|dbaddress:0x000030
4272->102|requestID=2005|READ REQ[4]|VarType:18|Var Length:10|SyntaxId:16|TransportSize:2|length:54|dbnumber:0x0|dbarea:0x83|dbaddress:0x000020
4272->102|requestID=2005|READ REQ[5]|VarType:18|Var Length:10|SyntaxId:16|TransportSize:2|length:4|dbnumber:0x0|dbarea:0x83|dbaddress:0x000020
102->4272|requestID=2005|READ ANS[1]|result(0xff)|value(6):000000000000
102->4272|requestID=2005|READ ANS[2]|result(0xff)|value(6):0a1000020000
102->4272|requestID=2005|READ ANS[3]|result(0xff)|value(6):010500000006
102->4272|requestID=2005|READ ANS[4]|result(0xff)|value(54):0000010500000006400ccccd000000000000000000000000000000000000000000000000000000000000000000000000000000000000
102->4272|requestID=2005|READ ANS[5]|result(0xff)|value(4):00000105

### architecture

#### main 
The main function is in charge of opening the pcap file, reading it, and filtering it to keep only tcp packet sent or received on port 102
(This port is configurable, see startup option -p ).
For each pcap entry filtered the follwing function is called :

#### func decodeS7packet( packet gopacket.Packet) 

  This function keep only tcp packet of interest for us, that is non empty tcp packet with sucessfull decoding of TPKT and COTP header
  containing a Data (DT) TPDU.
  Then for each packet selected, the S7 pdu is extracted and depending of the type (request or answer) and the function code concerned
  (Memory Write, Memory read) the corresponding method are called to provide full decoding of the content :

#### func traceS7MemoryWriteRequest( flow gopacket.Flow,requestId int, itemCount uint8, data []byte, itemOffset uint16, dataOffset uint16 ) 
   Extract as much as possible information of the S7 PDU about memory area and address being writted and print it on screen 

#### func traceS7MemoryReadRequest( flow gopacket.Flow,requestId int, itemCount uint8, data []byte, itemOffset uint16, dataOffset uint16 ) 
   Extract as much as possible information of the S7 PDU about memory area and address being read and print it on screen 

#### func traceS7MemoryWriteResponse( flow gopacket.Flow,requestId int, itemCount uint8, data []byte, itemOffset uint16, dataOffset uint16 ) 
   Extract and display the result code of the write operation. 0xFF means sucess 

#### func traceS7MemoryReadResponse( flow gopacket.Flow,requestId int, itemCount uint8, data []byte, itemOffset uint16, dataOffset uint16 ) 
   Extract and display the result code of the read operation. 0xFF means sucess and Display the value read



