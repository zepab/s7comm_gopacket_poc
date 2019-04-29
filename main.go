// hypothesis: 
//   - tcp and TPKT packet reassembly are not considered
//   - we don't expect malicious packet and thus we trust the S7comm protocol about item count versus data length available
//   - all write and read request return sucessfull answer (todo handle failed request)


package main

import (
	"flag"
	"fmt"
	//"io"
	"log"
	"os"
	//"strings"
	"time"
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

var fname = flag.String("r", "", "Filename to read from")
var fport = flag.String("p", "102", "TCP port handling S7comm traffic")

var tcpLayer layers.TCP

var lastTS time.Time
var lastSend time.Time

var start time.Time
var bytesSent int

func traceS7MemoryWriteRequest( flow gopacket.Flow,requestId int, itemCount uint8, data []byte, itemOffset uint16, dataOffset uint16 ) {
	//fmt.Println(flow," -> requestID=", requestId, ": Handling a Request to Write a Variable", "itemOffset=", itemOffset, "dataOffset=", dataOffset)
    // for each item get the information using below header
	for i := uint8(1); i <= itemCount; i++ {
		//Figure 3 S7 0x32 PDU: Read/Write Request - Parameter Item
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//+---------------+---------------+---------------+----------------+
		//| Var Type      | Var Length    | Syntax Id     | Transport Size |
		//+---------------+---------------+---------------+----------------+
		//|	            Length            |            DB Number           |
		//+---------------+---------------+---------------+----------------+
		//|      Area     |                    Address                     |
		//+---------------+---------------+---------------+----------------+
		varType := uint8(data[itemOffset])
		varLength := uint8(data[itemOffset+1])
		varSyntaxId := uint8(data[itemOffset+2])
		transportSize := uint8(data[itemOffset+3])
		length := uint16(binary.BigEndian.Uint16(data[itemOffset+4:itemOffset+6]))
		dbnumber := uint16(binary.BigEndian.Uint16(data[itemOffset+6:itemOffset+8]))
		dbarea := uint8(data[itemOffset+8])
		dbaddress := uint32(binary.BigEndian.Uint32(data[itemOffset+8:itemOffset+12]) & 0x0FFF)
		//point to the nextItem 
		itemOffset = itemOffset + 12
		// try to read the data value associated to this item using following header
		// note that data values are located after all item data, thus we make use of dataOffset to directly point to them
		// Figure 4 S7 0x32 PDU: Header of Data Item
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//+---------------+---------------+---------------------------------+
		//| Return Code   | Transport Size| Data Length (per transport size)|
		//+---------------+---------------+---------------------------------+
		//dataTransportSize := uint8(data[dataOffset+1])
		dataLength := uint16(binary.BigEndian.Uint16(data[dataOffset+2:dataOffset+4]))
		// compute the number of byte to read for the data we make here a big assertion:
		// we consider that the dataLength is a multiple of transportSize and that dataLength is also a multiple of a byte (8 bits)
		nbBytes :=dataLength / uint16(8)
		// read the value into a byte array
		value := make([]byte, nbBytes, nbBytes)
		copy(value,data[dataOffset+4:dataOffset+4+nbBytes])
		//point to the nextItem 
		dataOffset=dataOffset+4+nbBytes
		fmt.Printf("%v|requestID=%v|WRITE REQ[%d]|VarType:%v|Var Length:%v|SyntaxId:%v|TransportSize:%v|length:%v", flow,requestId,i,varType,varLength,varSyntaxId,transportSize,length )
		fmt.Printf("|dbnumber:%#x|dbarea:%#x|dbaddress:%#06x|value(%v):%x\n", dbnumber,dbarea,dbaddress,nbBytes,value )
	}
}
                                                  
func traceS7MemoryReadRequest( flow gopacket.Flow,requestId int, itemCount uint8, data []byte, itemOffset uint16, dataOffset uint16 ) {
	//fmt.Println(flow," -> requestID=", requestId, ": Handling a Request to Read a Variable")
    // for each item get the information using below header
	for i := uint8(1); i <= itemCount; i++ {
		//Figure 3 S7 0x32 PDU: Read/Write Request - Parameter Item
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//+---------------+---------------+---------------+----------------+
		//| Var Type      | Var Length    | Syntax Id     | Transport Size |
		//+---------------+---------------+---------------+----------------+
		//|	            Length            |            DB Number           |
		//+---------------+---------------+---------------+----------------+
		//|      Area     |                    Address                     |
		//+---------------+---------------+---------------+----------------+
		varType := uint8(data[itemOffset])
		varLength := uint8(data[itemOffset+1])
		varSyntaxId := uint8(data[itemOffset+2])
		transportSize := uint8(data[itemOffset+3])
		length := uint16(binary.BigEndian.Uint16(data[itemOffset+4:itemOffset+6]))
		dbnumber := uint16(binary.BigEndian.Uint16(data[itemOffset+6:itemOffset+8]))
		dbarea := uint8(data[itemOffset+8])
		dbaddress := uint32(binary.BigEndian.Uint32(data[itemOffset+8:itemOffset+12]) & 0x0FFF)
		//point to the nextItem 
		itemOffset = itemOffset + 12
		fmt.Printf("%v|requestID=%v|READ REQ[%d]|VarType:%v|Var Length:%v|SyntaxId:%v|TransportSize:%v|length:%v", flow,requestId,i,varType,varLength,varSyntaxId,transportSize,length )
		fmt.Printf("|dbnumber:%#x|dbarea:%#x|dbaddress:%#06x\n", dbnumber,dbarea,dbaddress)
	}	
}

func traceS7MemoryWriteResponse( flow gopacket.Flow,requestId int, itemCount uint8, data []byte, itemOffset uint16, dataOffset uint16 ) {
	//fmt.Println(flow," -> requestID=", requestId, ": Handling a Response to Write a Variable")
	for i := uint8(1); i <= itemCount; i++ {
		// try to read the data value associated to this item using following header
		// note that data values are located after all item data, thus we make use of dataOffset to directly point to them
		// Figure 4 S7 0x32 PDU: Header of Data Item
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//+---------------+---------------+---------------------------------+
		//| Return Code   | Transport Size| Data Length (per transport size)|
		//+---------------+---------------+---------------------------------+
		returnCode := uint8(data[dataOffset])
		//TODO try to find write ack answer with more than one item as it seems that only the Return Code is present in the frame
		dataOffset=dataOffset+1
		fmt.Printf("%v|requestID=%v|WRTIE ANS[%d]|result(%#x)\n",flow,requestId,i,returnCode )
	}	
}

func traceS7MemoryReadResponse( flow gopacket.Flow,requestId int, itemCount uint8, data []byte, itemOffset uint16, dataOffset uint16 ) {
	//fmt.Println(flow," -> requestID=", requestId, ": Handling a Response to Read a Variable")
    // for each item get the information using below header
	for i := uint8(1); i <= itemCount; i++ {
		// try to read the data value associated to this item using following header
		// note that data values are located after all item data, thus we make use of dataOffset to directly point to them
		// Figure 4 S7 0x32 PDU: Header of Data Item
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//+---------------+---------------+---------------------------------+
		//| Return Code   | Transport Size| Data Length (per transport size)|
		//+---------------+---------------+---------------------------------+
		returnCode := uint8(data[dataOffset])
		//dataTransportSize := uint8(data[dataOffset+1])
		dataLength := uint16(binary.BigEndian.Uint16(data[dataOffset+2:dataOffset+4]))
		// compute the number of byte to read for the data we make here a big assertion:
		// we consider that the dataLength is a multiple of transportSize and that dataLength is also a multiple of a byte (8 bits)
		nbBytes :=dataLength / uint16(8)
		// read the value into a byte array
		value := make([]byte, nbBytes, nbBytes)
		copy(value,data[dataOffset+4:dataOffset+4+nbBytes])
		//point to the nextItem 
		dataOffset=dataOffset+4+nbBytes		
		fmt.Printf("%v|requestID=%v|READ ANS[%d]|result(%#x)|value(%v):%x\n",flow,requestId,i,returnCode,nbBytes,value )
	}
}

func decodeS7packet( packet gopacket.Packet) {
	//fmt.Println(packet)
	//for sure because of the filter set we have receive a tcp packet.
	//still ask to gopacket to decode it to avoid malformed tcp packet 
	if (packet.Layer(layers.LayerTypeTCP) == nil) {
		fmt.Fprintf(os.Stderr,"skip non tcp or malformed tcp packet\n")
		return
	}
    tcpLayer,_ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
    payload := tcpLayer.Payload
	tcpLen := len(payload)
	// note that we are only interested in packet with upper application payload, 
	// we don't care about standard tcp syn, syn ack, rst etc ...
    // basically expect a payload size greater than 0 
    if ( tcpLen == 0 ) {
		//fmt.Fprintf(os.Stderr,"skip tcp packet with payload size == 0\n")
		return		
    }	

	// the S7comm packet are encapsulated into TPKT and then into ISO-COTP 
	// look for the following in google: Accurate Modeling of the Siemens S7 SCADA  JDFSL V9N2
	// this is written by Amit Kleinmann and Avishai Wool from Tel-Aviv University.
	// remove first TPKT base the analysis on https://tools.ietf.org/html/rfc1006:
    //  A TPKT consists of two parts:  a packet-header and a TPDU.  The
    //  format of the header is constant regardless of the type of packet.
    //  The format of the packet-header is as follows:
	//
    //    0                   1                   2                   3
    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |      vrsn     |    reserved   |          packet length        |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+	
	tpktLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if  payload[0] != 3 && payload[1] != 0 && tpktLen != tcpLen {
		fmt.Fprintf(os.Stderr,"skip packet which does contain expected TPKT data\n")
		return			
	}
	offset := uint16(4)
	//check now about the COTP packet received, header is defined in ISO8073
	// and implementation is described in https://tools.ietf.org/html/rfc905
	// we only want TPDU holding Data that is DT TPDU (Data TPDU)
	//	each TPDU structure is the following
    //      octet    1   2 3 4 ... n   n+1  ...    p  p+1 ...end
    //             +---+-------------+--------------+-----------+
    //             | LI| fixed part  | variable part| data field|
    //             +---+-------------+--------------+-----------+
    //             <---------------   header ------>
    tpduHeaderLen := uint8(payload[offset])
	
	// we only wants DT type pdu, see chapter13.7  Data (DT) TPDU, expect 11110000=>0xF0
	tpduType := payload[offset+1]
	if tpduType != 0xf0 {
		fmt.Fprintf(os.Stderr,"skip non DT TPDU data of type:%v\n", tpduType)
		return				
	}

	// there are different format depending on the class selected during connection establishment
	// but we don't mind since the LI (Lenght Indicator) allow us to skip the whole header and extract the S7 pdu
	offset = offset + uint16(1) + uint16(tpduHeaderLen)
	// remaining bytes are the UserData containing S7 pdu it self
	// just check UserData is no empty before going on and that it begin with the special value 0x32
	if offset >= uint16(tpktLen) || payload[offset] != 0x32 {
		fmt.Fprintf(os.Stderr,"skip DT TPDU data empty or not containing S7Comm protocol pdu\n")
		return				
	}
	//fmt.Println("Packet Flow: ",tcpLayer.TransportFlow(), "payload size: ",len(payload), "TPDU Header size: ", tpduHeaderLen, "TPDU type: ", tpduType)
	// S7 pdu header extracted from "Accurate Modeling of the Siemens S7 SCADA  JDFSL V9N2"
	//S7 0x32 PDU: Header for ROSCTR 1 or 3, Function Code 4 or 5 (Read/Write)
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//+---------------+---------------+--------------------------------+
	//| Protocol Id   |     ROSCTR    |  Reserved                      |
	//+---------------+---------------+--------------------------------+
	//|           Request ID          |    ParameterLength             |
	//+---------------+---------------+--------------------------------+
	//|          Data Length          |  Error Code only for ROSCTR 3  |
	//+---------------+---------------+--------------------------------+
	//| Function Code | Item Count    |
	//+---------------+---------------+
	//Now handle S7 pdu depending on the ROSCTR value (Remote Operating Service Control)
	if payload[offset+1] == 0x01 {
		// extract the request ID in order to match request and response
		requestId := int(binary.BigEndian.Uint16(payload[offset+4:offset+6]))
		// also get the parameterLength for the trace function
		parameterLength := uint16(binary.BigEndian.Uint16(payload[offset+6:offset+8]))
		if payload[offset+10] == 0x04 { 
			// get number of item present in this pdu 
			itemCount := uint8(payload[offset+11])
			traceS7MemoryReadRequest(tcpLayer.TransportFlow(),requestId,itemCount,payload,offset+12, offset + 10 + parameterLength)
		} else if payload[offset+10] == 0x05 { 
			itemCount := uint8(payload[offset+11])		
			traceS7MemoryWriteRequest(tcpLayer.TransportFlow(),requestId,itemCount,payload,offset+12, offset + 10 + parameterLength)
		} else {
		    fmt.Fprintf(os.Stderr,"skip a S7 pdu request not concerning Read/Write function: %v\n",payload[offset+10])
			return
		}
	} else if payload[offset+1] == 0x03 {
		// extract the request ID in order to match request and response
		requestId := int(binary.BigEndian.Uint16(payload[offset+4:offset+6]))
		// get the error code:
		//errorCode := int(binary.BigEndian.Uint16(payload[offset+10:offset+12]))
		// TODO need to trace if global errorcode is not sucess consider it for now as always sucessfull
		// also get the parameterLength for the trace function
		parameterLength := uint16(binary.BigEndian.Uint16(payload[offset+6:offset+8]))
		if payload[offset+12] == 0x04 { 
			itemCount := uint8(payload[offset+13])	
            // to compute start of the 			
			traceS7MemoryReadResponse(tcpLayer.TransportFlow(),requestId,itemCount,payload,offset+14, offset + 12 + parameterLength)
		} else if payload[offset+12] == 0x05 { 
			itemCount := uint8(payload[offset+13])
			traceS7MemoryWriteResponse(tcpLayer.TransportFlow(),requestId,itemCount,payload,offset+14, offset + 12 + parameterLength)
		} else {
		    fmt.Fprintf(os.Stderr,"skip a S7 pdu response not concerning Read/Write function: %v\n",payload[offset+12])
			return
		}
	} else {
	    fmt.Fprintf(os.Stderr,"skip a S7 pdu with ROSCTR neither request nor response: %v\n",payload[offset+1])
		return
	}
}
func main() {
	defer util.Run()()

	// Sanity checks
	if *fname == "" {
		log.Fatal("Need a input file")
	}

	// Open PCAP file + handle potential BPF Filter
	handleRead, err := pcap.OpenOffline(*fname)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
	}
	defer handleRead.Close()
	if *fport != "" {
		bpffilter := "tcp and port "
		bpffilter += *fport
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handleRead.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}
	pkt := 0

	// Loop over packets and launch analysis when siemens S7comm packet is detected
    packetSource := gopacket.NewPacketSource(handleRead, handleRead.LinkType())
    for packet := range packetSource.Packets() {
		pkt++
		//fmt.Println(packet)
		decodeS7packet(packet)
    }
}
