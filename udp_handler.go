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
	//clientPort layers.TCPPort = 0
	clientSrcPort layers.UDPPort = 0
	clientDstPort layers.UDPPort = 0
	ethAddr       net.IP
	srcAddr       net.IP
	dstAddr       net.IP
	srcMac        net.HardwareAddr
	dstMac        net.HardwareAddr

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

func sendPacket(pduSess *realuectx.PduSession, handle *pcap.Handle, packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	//tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcpLayer := packet.Layer(layers.LayerTypeUDP)
	appLayer := packet.ApplicationLayer()

	ipp, _ := ipLayer.(*layers.IPv4)
	//tcp, _ := tcpLayer.(*layers.TCP)
	tcp, _ := tcpLayer.(*layers.UDP)

	buffer := gopacket.NewSerializeBuffer()
	if appLayer != nil {
		pduSess.Log.Infof("app data to write to wire\n")
		gopacket.SerializeLayers(buffer, options,
			ipp,
			tcp,
			gopacket.Payload(appLayer.Payload()),
		)
	} else {
		pduSess.Log.Infof("no app data on wire\n")
		gopacket.SerializeLayers(buffer, options,
			ipp,
			tcp,
		)
	}

	outgoingPacket := buffer.Bytes()

	pduSess.Log.Infof("packet on the wire: %d\n", len(outgoingPacket))
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Errorf("Error Writing Packet")
	}

}

func handleUDP(port int) {
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Printf("Failed to listen %v\n", err)
		return
	}
	fmt.Printf("listening on port %d\n", port)
	for {
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("Error reading udp\n")
		}

		//fmt.Printf("udp read: %s\n", string(buf[:n]))
		fmt.Printf("udp read: %d bytes\n", n)
	}
}

func handleFunc(w http.ResponseWriter, r *http.Request) {
	// stall until we can do all the packet things
	fmt.Printf("Received http request - sleeping 1 minute\n")
	time.Sleep(60 * time.Second)
}

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
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		var flag ipv4.HeaderFlags = ipv4.HeaderFlags(int(ip.Flags))

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
			Src:      net.IP(ip.SrcIP).To4(),
			Dst:      net.IP(ip.DstIP).To4(),
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
func handlePacket(handle *pcap.Handle, packet gopacket.Packet, pduSess *realuectx.PduSession, port int, dst string) {
	pduSess.Log.Infof("in handle packet\n")

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv6Layer == nil {
			pduSess.Log.Errorf("no ip\n")
			return
		} else {
			pduSess.Log.Errorf("ipv6\n")
			return
		}
	}
	tcpLayer := packet.Layer(layers.LayerTypeUDP)
	if tcpLayer == nil {
		pduSess.Log.Errorf("no udp\n")
		return
	}

	pduSess.Log.Infof("have layers\n")

	ipp, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.UDP)

	pduSess.Log.Infof("From src ip %d to dst ip %d\n", ipp.SrcIP, ipp.DstIP)
	pduSess.Log.Infof("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)

	appLayer := packet.ApplicationLayer()

	// Need to forward to sdcore
	if int(tcp.DstPort) == port {
		pduSess.Log.Infof("outgoing %d\n", port)
		// Need to track the incoming source port
		if clientSrcPort == 0 {
			clientSrcPort = tcp.SrcPort
			clientDstPort = tcp.DstPort
			srcAddr = ipp.SrcIP
			dstAddr = ipp.DstIP
		}
		ipp.SrcIP = pduSess.PduAddress

		//ipp.DstIP = net.ParseIP(pduSess.DefaultAs).To4()
		ipp.DstIP = net.ParseIP(dst).To4()

		if appLayer != nil {
			pduSess.Log.Infof("Application layer/Payload found.\n")

			if strings.Contains(string(appLayer.Payload()), "HTTP") {
				pduSess.Log.Infof("HTTP found!\n")
			}

			payload := string(appLayer.Payload())

			payload = strings.ReplaceAll(payload, "localhost", dst)

			*packet.ApplicationLayer().(*gopacket.Payload) = []byte(payload)
		}

		pduSess.Log.Infof("send checksuming\n")
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

		buffer := gopacket.NewSerializeBuffer()
		if appLayer != nil {
			gopacket.SerializeLayers(buffer, options,
				tcp,
				gopacket.Payload(appLayer.Payload()),
			)
		} else {
			gopacket.SerializeLayers(buffer, options,
				tcp,
			)
		}
		outgoingPacket := buffer.Bytes()

		payload := append(v4HdrBuf, outgoingPacket...)

		pduSess.Log.Errorf("Custom packet out GnbChan")
		userDataMsg := &common.UserDataMessage{}
		userDataMsg.Event = common.UL_UE_DATA_TRANSFER_EVENT
		userDataMsg.Payload = payload
		pduSess.WriteGnbChan <- userDataMsg
		pduSess.TxDataPktCount++

	} else if tcp.DstPort == clientSrcPort {
		pduSess.Log.Infof("incoming packet %d\n", clientSrcPort)
		/*
				// Need to forward back to localhost
				tcp.DstPort = clientPort
				ipp.SrcIP = dstAddr
				ipp.DstIP = srcAddr
				//eth.SrcMAC = dstMac
				//eth.DstMAC = srcMac

				if appLayer != nil {
					pduSess.Log.Infof("Application layer/Payload found.\n")
					pduSess.Log.Infof("%s\n", appLayer.Payload())

					if strings.Contains(string(appLayer.Payload()), "HTTP") {
						pduSess.Log.Infof("HTTP found!\n")
					}

					payload := string(appLayer.Payload())

					payload = strings.ReplaceAll(payload, dst, "localhost")

					//pduSess.Log.Infof("modified payload: %s\n", payload)
					*packet.ApplicationLayer().(*gopacket.Payload) = []byte(payload)
				}

			        pduSess.Log.Infof("recv checksuming\n")
			        tcp.SetNetworkLayerForChecksum(ipp)

				sendPacket(pduSess, handle, packet)
				return
		*/
	} else {
		pduSess.Log.Warnf("unhandled packet going to %d\n", tcp.DstPort)
		return
	}

}

// main function to do our http proxy'ing
func Blah(pduSess *realuectx.PduSession) error {

	pduSess.Log.Infof("starting udp proxy\n")

	var dstIP = "10.10.5.2"

	//UDP
	var port = 11000
	//TCP
	//var port = 10001

	// get our eth0 address that we will need to get forwarded back to
	getIPv4Addr()

	//go http.ListenAndServe(fmt.Sprintf("%s:10001", ethAddr.To4().String()), nil)

	//TCP
	//http.HandleFunc("/", handleFunc)
	//go http.ListenAndServe(fmt.Sprintf("%s:%d", "localhost", port), nil)

	go handleUDP(port)

	pduSess.Log.Infof("proxy listening on %d\n", port)

	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		pduSess.Log.Errorf("Failed to open listener: %v\n", err)
		return err
	}

	// TCP
	/*
		err = handle.SetBPFFilter("tcp")
		if err != nil {
			pduSess.Log.Errorf("Something with tcp: %v\n", err)
			return err
		}
		pduSess.Log.Infof("handle tcp\n")
	*/

	// UDP
	err = handle.SetBPFFilter("udp")
	if err != nil {
		pduSess.Log.Errorf("Something with udp: %v\n", err)
		return err
	}
	pduSess.Log.Infof("handling udp\n")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		pduSess.Log.Infof("calling handlePacket\n")
		handlePacket(handle, packet, pduSess, port, dstIP)
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
		//return fmt.Errorf("unsupported icmp message type:%v", icmpMsg.Type)
		return nil
	}

	return nil
}

func HandleIpv4Message(pduSess *realuectx.PduSession, ipv4Hdr *ipv4.Header, ipv4Pkt []byte) (err error) {

	/*
		ip4 := layers.IPv4{
			SrcIP:    ipv4Hdr.Src,
			DstIP:    ipv4Hdr.Dst,
			Checksum: ipv4Hdr.Checksum,
			Flags:    int(ipv4Hdr.HeaderFlags),
			Protocol: ipv4Hdr.Protocol,
			TTL:      ipv4Hdr.TTL,
			FragOffset: ipv4Hdr.FragOff,
			Id:         ipv4Hdr.ID,
			TOS:        ipv4Hdr.TOS,
			Length:     ipv4Hdr.TotalLen,
			IHL:        ipv4Hdr.Len/4,
			Version:    ipv4Hdr.Version,
		}
	*/

	// UDP
	if ipv4Hdr.Protocol == 17 {

		packet := gopacket.NewPacket(ipv4Pkt, layers.LayerTypeIPv4, gopacket.Default)

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			pduSess.Log.Println("This is a UDP packet!")

			udp, _ := udpLayer.(*layers.UDP)

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				pduSess.Log.Errorf("bad decode ip packet\n")
				return
			}

			ipp, _ := ipLayer.(*layers.IPv4)

			appLayer := packet.ApplicationLayer()

			pduSess.Log.Infof("From src ip %d to dst ip %d\n", ipp.SrcIP, ipp.DstIP)
			pduSess.Log.Infof("From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)

			// Need to forward back to localhost
			udp.SrcPort = clientDstPort
			udp.DstPort = clientSrcPort
			ipp.SrcIP = dstAddr
			ipp.DstIP = srcAddr

			pduSess.Log.Infof("Updated src ip %d to dst ip %d\n", ipp.SrcIP, ipp.DstIP)
			pduSess.Log.Infof("Updated src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)

			pduSess.Log.Infof("recv checksuming\n")
			udp.SetNetworkLayerForChecksum(ipp)

			buffer := gopacket.NewSerializeBuffer()

			if appLayer == nil {
				pduSess.Log.Infof("no app data on wire\n")
				gopacket.SerializeLayers(buffer, options,
					ipp,
					udp,
				)
			} else {
				pduSess.Log.Infof("app data on wire: %s\n", appLayer.Payload())
				gopacket.SerializeLayers(buffer, options,
					ipp,
					udp,
					gopacket.Payload(appLayer.Payload()),
				)
			}

			outgoingPacket := buffer.Bytes()

			handle2, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
			if err != nil {
				fmt.Errorf("Error Opening handle")
				return err
			}
			pduSess.Log.Infof("reconstructed pkt on the wire: %d\n", len(outgoingPacket))
			err = handle2.WritePacketData(outgoingPacket)
			if err != nil {
				fmt.Errorf("Error Writing Packet")
			}

		} else {
			fmt.Println("Not a UDP packet!")
			return
		}

		/*
			ip4num2 = &layers.IPv4{}
			udp = &layers.UDP{}
			payload = &gopacket.Payload{}

			nf := gopacket.NilDecodeFeedback
			data := ipv4Pkt[:]

			err = ip4num2.DecodeFromBytes(data, nf)
			if err != nil {
				pduSess.Log.Errorf("packet doesnt look right\n")
				return err
			}

			data = ipv4num.LayerPayload()

			err = udp.DecodeFromBytes(data, nf)
			if err != nil {
				pduSess.Log.Errorf("packet doesnt look right\n")
				return err
			}

			data = d.LayerPayload()

			err = payload.DecodeFromBytes(data, nf)
			if err != nil {
				pduSess.Log.Errorf("packet doesnt look right\n")
				return err
			}

			data = d.LayerPayload()
		*/
	} else if ipv4Hdr.Protocol == 6 {
		// TCP TODO
		pduSess.Log.Errorf("TCP not implement on recv: %d\n", ipv4Hdr.Protocol)
		/*
				type TCP struct {
					BaseLayer
					SrcPort, DstPort                           TCPPort
					Seq                                        uint32
					Ack                                        uint32
					DataOffset                                 uint8
					FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
					Window                                     uint16
					Checksum                                   uint16
					Urgent                                     uint16
					sPort, dPort                               []byte
					Options                                    []TCPOption
					Padding                                    []byte
					opts                                       [4]TCPOption
					tcpipchecksum
				}

			tcp, _ := tcpLayer.(*layers.UDP)

			if appLayer != nil {
				pduSess.Log.Infof("app data to write to wire\n")
				gopacket.SerializeLayers(buffer, options,
					ipp,
					tcp,
					gopacket.Payload(appLayer.Payload()),
				)


		*/
	} else {
		pduSess.Log.Errorf("Unimplemented ipv4 protocol: %d\n", ipv4Hdr.Protocol)
		return nil
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
		pduSess.Log.Infof("Protocol: %d\n", ipv4Hdr.Protocol)
		err = HandleIpv4Message(pduSess, ipv4Hdr, dataMsg.Payload)
		if err != nil {
			return fmt.Errorf("failed to handle our ipv4 message:%v", err)
		}
		// This is our message!
		//return fmt.Errorf("unsupported ipv4 protocol:%v", ipv4Hdr.Protocol)
	}

	return nil
}

func HandleDataPktGenRequestEvent(pduSess *realuectx.PduSession,
	intfcMsg common.InterfaceMessage,
) (err error) {
	cmd := intfcMsg.(*common.UeMessage)
	//pduSess.ReqDataPktCount = cmd.UserDataPktCount
	pduSess.ReqDataPktCount = 240
	pduSess.ReqDataPktInt = cmd.UserDataPktInterval
	pduSess.DefaultAs = cmd.DefaultAs
	if pduSess.ReqDataPktInt == 0 {
		err = SendIcmpEchoRequest(pduSess)
		if err != nil {
			return fmt.Errorf("failed to send icmp echo req:%v", err)
		}
		time.Sleep(1 * time.Second)
	} else {
		go func(pduSess *realuectx.PduSession) {
			for pduSess.TxDataPktCount < pduSess.ReqDataPktCount {
				pduSess.Log.Infof("sending icmp counts :%d <? %d\n", pduSess.TxDataPktCount, pduSess.ReqDataPktCount)

				time.Sleep(1 * time.Second)
				err := SendIcmpEchoRequest(pduSess)
				if err != nil {
					pduSess.Log.Errorf("failed to send icmp echo req: %v", err)
					return // Exit the goroutine on error
				}
				time.Sleep(time.Duration(pduSess.ReqDataPktInt) * time.Second)
			}

			// TODO: Here
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
			pduSess.Log.Infof("Received pkt from DL data packet: %s\n", pkt.GetEventType())
			// TODO: Here
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
