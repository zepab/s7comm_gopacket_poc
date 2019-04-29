# s7comm_gopacket_poc
Just a proof of concept for decoding the Siemens S7 protocol using go langage and gopacket library.

The aims of this tool is to perform a post processing of network capture (wireshark pcap file).
The network capture contains exchanges done between Siemens PLC using S7comm protocol.
This protocol is not officially documented but they are plenty resources on the web to understand it.
Also latest version of wireshark directly include a S7comm dissector  

This tool consist of one go file 
gopacket library has been used to ease reading of wireshark capture and packet extraction
Even if I did use gopacket, I have not developped a custom layer but with the present code
this is easy to turn it into a custom layer if needed.

As this is the first time I use go, there might some improvement to perform.

This code was done like an academic study, in order to extract information about 
memory access done on PLC using the S7comm protocol
Please check comments in the code and note that there are the following restrictions:

  - tcp and TPKT packet reassembly are not considered
  - we don't expect malicious packet and thus we trust the S7comm protocol about item count versus data length available
  - all write and read request return sucessfull answer (todo handle failed request)

A list of remaining work would be: 

- make automatic correlation of request and answers 
 (this can be easly achieved using the combination of src and dest ip address and port plus the RequestID)

- display information in a more user firendly way using enum to translate raw value into human readable text

