// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package pdusessworker

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/omec-project/gnbsim/common"
	realuectx "github.com/omec-project/gnbsim/realue/context"
	"github.com/omec-project/gnbsim/util/test"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	ICMP_HEADER_LEN int = 8

	/*ipv4 package requires ipv4 header length in terms of number of bytes,
	  however it later converts it into number of 32 bit words
	*/
	IPV4_MIN_HEADER_LEN int = 20
)

var (
	clientPort layers.TCPPort = 0
	ethAddr    net.IP
	srcAddr    net.IP
	dstAddr    net.IP
	srcMac     net.HardwareAddr
	dstMac     net.HardwareAddr

	device       string = "eth0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	options      = gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
)

func sendPacket(handle *pcap.Handle, packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	appLayer := packet.ApplicationLayer()

	eth, _ := ethLayer.(*layers.Ethernet)
	ipp, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		eth,
		ipp,
		tcp,
		gopacket.Payload(appLayer.(gopacket.Payload)),
	)
	outgoingPacket := buffer.Bytes()

	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Errorf("Error Writing Packet")
	}

}

func handleFunc(w http.ResponseWriter, r *http.Request) {
	// stall until we can do all the packet things
	fmt.Printf("Received http request - sleeping 1 minute\n")
	time.Sleep(60 * time.Second)
}

/*
func setChecksum(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// Compute the IP checksum
		ip.Checksum = 0
		ip.Checksum = ip.ComputeChecksum()

		// Get the TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Compute the TCP checksum
			tcp.SetNetworkLayerForChecksum(ip)
			tcp.Checksum = tcp.ComputeChecksum()
		}
	}
}
*/

func getIPv4Addr() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(err)
		return
	}

	for _, i := range ifaces {
		if i.Name == "eth0" {
			addrs, err := i.Addrs()
			if err != nil {
				fmt.Print(err)
				return
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				// check if the address is IPv4
				if ip.To4() != nil {
					fmt.Println("Found IPv4 Address:", ip)
					ethAddr = ip
					return
				}
			}
		}
	}
}

func convertPacket(packet gopacket.Packet) (*ipv4.Header, error) {
	// Get the IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		var flag ipv4.HeaderFlags = ipv4.HeaderFlags(int(ip.Flags))

		// Create a new ipv4.Header
		header := &ipv4.Header{
			Version:  int(ip.Version),
			Len:      int(ip.IHL * 4),
			TOS:      int(ip.TOS),
			TotalLen: int(ip.Length),
			ID:       int(ip.Id),
			//Flags:    ipv4.Flags(ip.Flags),
			FragOff:  int(ip.FragOffset),
			TTL:      int(ip.TTL),
			Protocol: int(ip.Protocol),
			Flags:    flag,
			Checksum: int(ip.Checksum),
			Src:      net.IP(ip.SrcIP),
			Dst:      net.IP(ip.DstIP),
		}

		return header, nil
	}

	return nil, fmt.Errorf("No IPv4 layer found")
}

// So this server will run on :10001 as an http server that
// we will then have a client connect to as localhost:10001
// then we will rewrite the ip addresses
// recompute ip, tcp checksums
// rewrite http data field
func handlePacket(handle *pcap.Handle, packet gopacket.Packet, pduSess *realuectx.PduSession) {
	pduSess.Log.Infof("in handle packet\n")
	// the packet should be tcp

	/*
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		pduSess.Log.Errorf("no eth\n")
		return
	}
	*/
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		pduSess.Log.Errorf("no ip\n")
		return
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		pduSess.Log.Errorf("no tcp\n")
		return
	}

	pduSess.Log.Infof("have layers\n")

	//eth, _ := ethLayer.(*layers.Ethernet)
	ipp, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	pduSess.Log.Infof("have elements\n")
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		pduSess.Log.Errorf("Nil app layer\n")
		return
	}

	// Need to forward to sdcore
	if tcp.DstPort == 10001 {
		pduSess.Log.Infof("pkt going to 10001\n")
		// Need to track the incoming source port
		if clientPort == 0 {
			clientPort = tcp.SrcPort
			srcAddr = ipp.SrcIP
			dstAddr = ipp.DstIP
			//srcMac = eth.SrcMAC
			//dstMac = eth.DstMAC
		}
		tcp.SrcPort = 10002
		ipp.SrcIP = pduSess.PduAddress
		ipp.DstIP = net.ParseIP(pduSess.DefaultAs).To4()

		if appLayer != nil {
			pduSess.Log.Infof("Application layer/Payload found.\n")
			pduSess.Log.Infof("%s\n", appLayer.Payload())

			// Search for a string inside the payload
			if strings.Contains(string(appLayer.Payload()), "HTTP") {
				pduSess.Log.Infof("HTTP found!\n")
			}

			// now we need to overwrite the http payload
			//strings.Replace(string(appLayer.Payload()), ethAddr.To4().String(), pduSess.DefaultAs, -1)
			strings.Replace(string(appLayer.Payload()), "localhost", pduSess.DefaultAs, -1)
		}
	} else if tcp.DstPort == 10002 {
		pduSess.Log.Infof("pkt going to 10002\n")
		// Need to forward back to localhost
		tcp.DstPort = clientPort
		ipp.SrcIP = dstAddr
		ipp.DstIP = srcAddr
		//eth.SrcMAC = dstMac
		//eth.DstMAC = srcMac

		if appLayer != nil {
			pduSess.Log.Infof("Application layer/Payload found.\n")
			pduSess.Log.Infof("%s\n", appLayer.Payload())

			// Search for a string inside the payload
			if strings.Contains(string(appLayer.Payload()), "HTTP") {
				pduSess.Log.Infof("HTTP found!\n")
			}

			// now we need to overwrite the http payload
			//strings.Replace(string(appLayer.Payload()), pduSess.DefaultAs, ethAddr.To4().String(), -1)
			strings.Replace(string(appLayer.Payload()), "localhost", ethAddr.To4().String(), -1)
		}
		pduSess.Log.Infof("going to send packet\n")

		sendPacket(handle, packet)
		return
	} else {
		pduSess.Log.Errorf("not port found\n")
		return
	}


	pduSess.Log.Infof("checksuming\n")
	tcp.SetNetworkLayerForChecksum(ipp)

	ipv4hdr, err := convertPacket(packet)
	if err != nil {
		fmt.Errorf("Error converting packet: %v\n", err)
	}
	checksum := test.CalculateIpv4HeaderChecksum(ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	if err != nil {
		pduSess.Log.Errorln("ipv4hdr header marshal failed")
		return
	}

	pduSess.Log.Infof("serializing\n")

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		tcp,
		gopacket.Payload(appLayer.(gopacket.Payload)),
	)
	outgoingPacket := buffer.Bytes()

	payload := append(v4HdrBuf, outgoingPacket...)

	pduSess.Log.Infof("yolo\n")

	userDataMsg := &common.UserDataMessage{}
	userDataMsg.Event = common.UL_UE_DATA_TRANSFER_EVENT
	userDataMsg.Payload = payload
	pduSess.WriteGnbChan <- userDataMsg
	pduSess.TxDataPktCount++

	pduSess.Log.Traceln("Sent UL tcp message")

}

// main function to do our http proxy'ing
func Blah(pduSess *realuectx.PduSession) error {

	pduSess.Log.Infof("in blah\n")

	// get our eth0 address that we will need to get forwarded back to
	getIPv4Addr()

	pduSess.Log.Infof("got eth0 addr: %s\n", ethAddr.To4().String())

	http.HandleFunc("/", handleFunc)
	//go http.ListenAndServe(fmt.Sprintf("%s:10001", ethAddr.To4().String()), nil)
	go http.ListenAndServe(fmt.Sprintf("%s:10001", "localhost"), nil)

	pduSess.Log.Infof("began listening on 10001\n")

	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		pduSess.Log.Errorf("Failed to open listener: %v\n", err)
		return err
	}
	pduSess.Log.Infof("opened handle\n")
	err = handle.SetBPFFilter("tcp")
	if err != nil {
		pduSess.Log.Errorf("Something with tcp: %v\n", err)
		return err
	}
	pduSess.Log.Infof("handle tcp\n")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		pduSess.Log.Infof("calling handlePacket\n")
		handlePacket(handle, packet, pduSess) // Do something with a packet here.
	}

	pduSess.Log.Infof("End of function oh no.\n")

	return nil
}

func HandleInitEvent(pduSess *realuectx.PduSession,
	intfcMsg common.InterfaceMessage,
) (err error) {
	msg := intfcMsg.(*common.UeMessage)
	pduSess.WriteGnbChan = msg.CommChan
	pduSess.LastDataPktRecvd = false
	return nil
}

func SendIcmpEchoRequest(pduSess *realuectx.PduSession) (err error) {
	pduSess.Log.Traceln("Sending UL ICMP ping message")

	icmpPayload, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	if err != nil {
		pduSess.Log.Errorln("Failed to decode icmp hexString ")
		return err
	}
	icmpPayloadLen := len(icmpPayload)
	pduSess.Log.Traceln("ICMP payload size:", icmpPayloadLen)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      IPV4_MIN_HEADER_LEN,
		Protocol: 1,
		Flags:    0,
		TotalLen: IPV4_MIN_HEADER_LEN + ICMP_HEADER_LEN + icmpPayloadLen,
		TTL:      64,
		Src:      pduSess.PduAddress,                   // ue IP address
		Dst:      net.ParseIP(pduSess.DefaultAs).To4(), // upstream router interface connected to Gi
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	if err != nil {
		pduSess.Log.Errorln("ipv4hdr header marshal failed")
		return err
	}

	icmpMsg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: pduSess.GetNextSeqNum(),
			Data: icmpPayload,
		},
	}
	b, err := icmpMsg.Marshal(nil)
	if err != nil {
		pduSess.Log.Errorln("Failed to marshal icmp message")
		return err
	}

	payload := append(v4HdrBuf, b...)

	userDataMsg := &common.UserDataMessage{}
	userDataMsg.Event = common.UL_UE_DATA_TRANSFER_EVENT
	userDataMsg.Payload = payload
	pduSess.WriteGnbChan <- userDataMsg
	pduSess.TxDataPktCount++

	pduSess.Log.Traceln("Sent UL ICMP ping message")

	return nil
}

func HandleIcmpMessage(pduSess *realuectx.PduSession,
	icmpPkt []byte,
) (err error) {
	icmpMsg, err := icmp.ParseMessage(1, icmpPkt)
	if err != nil {
		return fmt.Errorf("failed to parse icmp message:%v", err)
	}

	switch icmpMsg.Type {
	case ipv4.ICMPTypeEchoReply:
		echpReply := icmpMsg.Body.(*icmp.Echo)
		if echpReply == nil {
			return fmt.Errorf("icmp echo reply is nil")
		}

		pduSess.Log.Infof("Received ICMP Echo Reply, ID:%v, Seq:%v",
			echpReply.ID, echpReply.Seq)

		pduSess.RxDataPktCount++
		if pduSess.ReqDataPktInt == 0 {
			if pduSess.TxDataPktCount < pduSess.ReqDataPktCount {
				err := SendIcmpEchoRequest(pduSess)
				if err != nil {
					return fmt.Errorf("failed to send icmp message:%v", err)
				}
			} else {
				msg := &common.UuMessage{}
				msg.Event = common.DATA_PKT_GEN_SUCCESS_EVENT
				pduSess.WriteUeChan <- msg
				pduSess.Log.Traceln("Sent Data Packet Generation Success Event")
			}
		}
	default:
		return fmt.Errorf("unsupported icmp message type:%v", icmpMsg.Type)
	}

	return nil
}

func HandleDlMessage(pduSess *realuectx.PduSession,
	msg common.InterfaceMessage,
) (err error) {
	pduSess.Log.Traceln("Handling DL user data packet from gNb")

	if msg.GetEventType() == common.LAST_DATA_PKT_EVENT {
		pduSess.Log.Debugln("Received last downlink data packet")
		pduSess.LastDataPktRecvd = true
		return nil
	}

	dataMsg := msg.(*common.UserDataMessage)

	if dataMsg.Qfi != nil {
		pduSess.Log.Infoln("Received QFI value in downlink user data packet:", *dataMsg.Qfi)
	}

	ipv4Hdr, err := ipv4.ParseHeader(dataMsg.Payload)
	if err != nil {
		return fmt.Errorf("failed to parse ipv4 header:%v", err)
	}

	switch ipv4Hdr.Protocol {
	/* Currently supporting ICMP protocol */
	case 1:
		err = HandleIcmpMessage(pduSess, dataMsg.Payload[ipv4Hdr.Len:])
		if err != nil {
			return fmt.Errorf("failed to handle icmp message:%v", err)
		}
	default:
		return fmt.Errorf("unsupported ipv4 protocol:%v", ipv4Hdr.Protocol)
	}

	return nil
}

func HandleDataPktGenRequestEvent(pduSess *realuectx.PduSession,
	intfcMsg common.InterfaceMessage,
) (err error) {
	cmd := intfcMsg.(*common.UeMessage)
	pduSess.ReqDataPktCount = cmd.UserDataPktCount
	pduSess.ReqDataPktInt = cmd.UserDataPktInterval
	pduSess.DefaultAs = cmd.DefaultAs
	if pduSess.ReqDataPktInt == 0 {
		err = SendIcmpEchoRequest(pduSess)
		if err != nil {
			return fmt.Errorf("failed to send icmp echo req:%v", err)
		}
	} else {
		go func(pduSess *realuectx.PduSession) {
			for pduSess.TxDataPktCount < pduSess.ReqDataPktCount {
				err := SendIcmpEchoRequest(pduSess)
				if err != nil {
					pduSess.Log.Errorf("failed to send icmp echo req: %v", err)
					return // Exit the goroutine on error
				}
				time.Sleep(time.Duration(pduSess.ReqDataPktInt) * time.Second)
			}
			msg := &common.UuMessage{}
			msg.Event = common.DATA_PKT_GEN_SUCCESS_EVENT
			pduSess.WriteUeChan <- msg
			pduSess.Log.Traceln("Sent Data Packet Generation Success Event")
		}(pduSess)
	}
	return nil
}

func HandleConnectionReleaseRequestEvent(pduSess *realuectx.PduSession,
	intfcMsg common.InterfaceMessage,
) (err error) {
	userDataMsg := &common.UserDataMessage{}
	userDataMsg.Event = common.LAST_DATA_PKT_EVENT
	pduSess.WriteGnbChan <- userDataMsg
	// Releasing the reference so as to be freed by Garbage Collector
	pduSess.WriteGnbChan = nil
	return nil
}

func HandleQuitEvent(pduSess *realuectx.PduSession,
	intfcMsg common.InterfaceMessage,
) (err error) {
	if pduSess.WriteGnbChan != nil {
		userDataMsg := &common.UserDataMessage{}
		userDataMsg.Event = common.LAST_DATA_PKT_EVENT
		pduSess.WriteGnbChan <- userDataMsg
		pduSess.WriteGnbChan = nil
	}

	// Drain all the messages until END MARKER is received.
	// This ensures that the transmitting go routine is not blocked while
	// sending data on this channel
	if !pduSess.LastDataPktRecvd {
		for pkt := range pduSess.ReadDlChan {
			if pkt.GetEventType() == common.LAST_DATA_PKT_EVENT {
				pduSess.Log.Debugln("Received last downlink data packet")
				break
			}
		}
	}

	pduSess.WriteUeChan = nil
	pduSess.Log.Infoln("Pdu Session terminated")

	return nil
}
