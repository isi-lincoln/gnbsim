// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package pdusessworker

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
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
	ICMP_HEADER_LEN     int = 8
	IPV4_MIN_HEADER_LEN int = 20
)

var (
	LocalPort     layers.TCPPort = 0
	clientSrcPort layers.TCPPort = 0
	clientDstPort layers.TCPPort = 0
	ipSrcAddr     net.IP
	ipDstAddr     net.IP
	srcMac        net.HardwareAddr
	dstMac        net.HardwareAddr
	gInConn       *net.Conn
	gOutConn      *net.Conn

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
	mu      sync.Mutex
	lastPdu *realuectx.PduSession

	ackMap map[uint32][]byte
)

func sendPacket(pduSess *realuectx.PduSession, packet gopacket.Packet) {

	eth := &layers.Ethernet{
		//DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		SrcMAC: net.HardwareAddr{0x02, 0x42, 0xac, 0x1a, 0x0, 0x2},
		DstMAC: net.HardwareAddr{0x02, 0x42, 0xac, 0x1a, 0x0, 0x2},
		//SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipp, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)

	appLayer := packet.ApplicationLayer()

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	/*
		//err := gopacket.SerializeLayers(buffer, options, eth, ipLayer)
		err := gopacket.SerializeLayers(buffer, options, eth, ipp, tcp)
		if err != nil {
			panic(err)
		}
	*/

	if appLayer != nil {
		gopacket.SerializeLayers(buffer, options,
			eth,
			ipp,
			tcp,
			gopacket.Payload(appLayer.Payload()),
		)
	} else {
		gopacket.SerializeLayers(buffer, options,
			eth,
			ipp,
			tcp,
		)
	}

	packetData := buffer.Bytes()

	handle2, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle2.Close()

	err = handle2.WritePacketData(packetData)
	if err != nil {
		panic(err)
	}

}

func getIPv4Addr() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(err)
		return
	}

	for _, i := range ifaces {
		if i.Name == device {
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

				if ip.To4() != nil {
					fmt.Println("Found IPv4 Address:", ip)
					ipSrcAddr = ip
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

func listenInTCP(pduSess *realuectx.PduSession, inPort int) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", inPort))
	if err != nil {
		pduSess.Log.Infof("Failed to listen %v\n", err)
		return
	}

	conn, err := ln.Accept()
	if err != nil {
		pduSess.Log.Infof("Failed to accept %v\n", err)
		return
	}

	gInConn = &conn

	pduSess.Log.Infof("creating inbound port on %d\n", inPort)

	for {
		buf := make([]byte, 2000)
		n, err := conn.Read(buf)
		if err != nil {
			pduSess.Log.Infof("Error reading tcp: %v\n", err)
			conn.Close()

			conn, err = ln.Accept()
			if err != nil {
				pduSess.Log.Infof("Failed to accept %v\n", err)
				return
			}
			gInConn = &conn
			continue
		}

		if gOutConn == nil {
			initializeOutTCP(pduSess, ipDstAddr.String(), int(clientSrcPort), int(clientDstPort))
		}

		if n > 0 {
			data := buf[:n]
			pduSess.Log.Infof("tcp local read: %s\n %d bytes\n", data, n)
			handleOutTCP(data)
		} else {
			conn.Close()
			(*gOutConn).Close()
		}
	}
}

func initializeOutTCP(pduSess *realuectx.PduSession, outHost string, outSrcPort, outDstPort int) {
	localAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", ipSrcAddr, outSrcPort))
	if err != nil {
		pduSess.Log.Errorf("faled to listen on our GTP local %v", err)
		return
	}

	dialer := net.Dialer{
		LocalAddr: localAddr,
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", outHost, outDstPort))
	if err != nil {
		pduSess.Log.Errorf("Failed to listen %v\n", err)
		return
	}

	pduSess.Log.Infof("creating outbound tcp on %d\n", outDstPort)

	gOutConn = &conn
}

func handleOutTCP(data []byte) {
	mu.Lock()
	defer mu.Unlock()

	if (*gOutConn) != nil {
		_, err := (*gOutConn).Write(data)
		if err != nil {
			fmt.Errorf("Error writing 'Out' tcp\n")
		}

		//fmt.Printf("tcp copying out to remote: %s\n %d bytes\n", data[:n], n)
	} else {
		fmt.Errorf("gconn 'Out' connection is nil!\n")
	}
}

func handleInTCP(data []byte) {
	mu.Lock()
	defer mu.Unlock()
	if (*gInConn) != nil {
		if data == nil {
			(*gInConn).Close()
		} else {
			_, err := (*gInConn).Write(data)
			if err != nil {
				fmt.Errorf("Error writing 'In' tcp\n")
			}
		}

		//fmt.Printf("tcp response to local: %s\n", data[:n])
	} else {
		fmt.Errorf("gconn 'In' connection is nil!\n")
	}
}

// So this server will run on :10001 as an http server that
// we will then have a client connect to as localhost:10001
// then we will rewrite the ip addresses
// recompute ip, tcp checksums
// rewrite http data field
func handlePacket(packet gopacket.Packet, pduSess *realuectx.PduSession, dstPort int, dstIP string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv6Layer == nil {
			return
		} else {
			return
		}
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	ipp, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	appLayer := packet.ApplicationLayer()

	// Need to forward to sdcore
	if int(tcp.DstPort) == dstPort {
		pduSess.Log.Errorf("handlePacket: %d\n", dstPort)

		pduSess.Log.Infof("RAW: src ip %s:%d to dst ip %s:%d\n", ipp.SrcIP, tcp.SrcPort, ipp.DstIP, tcp.DstPort)
		ipp.SrcIP = pduSess.PduAddress
		ipp.DstIP = net.ParseIP(dstIP).To4()
		pduSess.Log.Infof("TO GTP: src ip %s:%d to dst ip %s:%d\n", ipp.SrcIP, tcp.SrcPort, ipp.DstIP, tcp.DstPort)

		pduSess.Log.Infof("Send Sequence number: %v\n", tcp.Seq)
		pduSess.Log.Infof("Send Acknoweldge number: %v\n", tcp.Ack)
		pduSess.Log.Infof("Send SYN: %t, ACK: %t, FIN: %t, RST: %t\n", tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST)

		//ipp.Flags = layers.IPv4MoreFragments

		//reset mss
		for i := range tcp.Options {
			if tcp.Options[i].OptionType == layers.TCPOptionKindMSS {
				mss := (uint16(tcp.Options[i].OptionData[0]) << 8) | uint16(tcp.Options[i].OptionData[1])
				if mss > 1000 {
					tcp.Options[i].OptionData = []byte{0x03, 0xe8} // 0x03e8 is 1000 in hexadecimal
				}
			}
		}

		// because data loss / retransmits we need to track state
		for seq, data := range ackMap {
			pduSess.Log.Errorf("Ack %d: Map: %d\n", tcp.Ack, seq)
			if tcp.Ack == seq {
				pduSess.Log.Errorf("Data acknowledged %d: %s\n", seq, string(data))
				handleInTCP(data)
				delete(ackMap, seq)
			}
		}

		/*
			if !found {
				tcp.Options = append(tcp.Options, layers.TCPOption{
					OptionType:   layers.TCPOptionKindMSS,
					OptionLength: 4,
					OptionData:   []byte{byte(1000 >> 8), byte(1000 & 0xff)},
				})
			}
		*/

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

			payload := string(appLayer.Payload())
			payload = strings.ReplaceAll(payload, "localhost", ipDstAddr.String())
			payload = strings.ReplaceAll(payload, string(LocalPort), string(clientDstPort))
			*packet.ApplicationLayer().(*gopacket.Payload) = []byte(payload)

			//pduSess.Log.Warnf("App payload: %s\n", payload)

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

		userDataMsg := &common.UserDataMessage{}
		userDataMsg.Event = common.UL_UE_DATA_TRANSFER_EVENT
		userDataMsg.Payload = payload
		pduSess.WriteGnbChan <- userDataMsg
		pduSess.TxDataPktCount++

	} else {
		pduSess.Log.Warnf("unhandled packet going to %d\n", tcp.DstPort)
		return
	}
}

// main function to do our http proxy'ing
func Blah(pduSess *realuectx.PduSession) error {
	if lastPdu == nil {
		lastPdu = pduSess
	}
	pduSess.Log.Infof("starting tcp proxy\n")

	ackMap = make(map[uint32][]byte, 0)

	var dstIP = "10.10.5.2"
	ipDstAddr = net.ParseIP(dstIP)

	//TCP
	var inPort = 10000
	var outDstPort = 10001
	var outSrcPort = 10002

	clientSrcPort = layers.TCPPort(outSrcPort)
	clientDstPort = layers.TCPPort(outDstPort)
	LocalPort = layers.TCPPort(inPort)

	getIPv4Addr()

	//TCP
	go func() {
		// Need to sleep here to make sure we can intercept these packets for the
		// 3 way handshake
		time.Sleep(5 * time.Second)
		pduSess.Log.Warnf("begin listening on %d\n", outSrcPort)
		initializeOutTCP(pduSess, dstIP, outSrcPort, outDstPort)
	}()

	pduSess.Log.Infof("proxy listening on %d\n", inPort)
	go listenInTCP(pduSess, inPort)

	handleLocal, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		pduSess.Log.Errorf("Failed to open listener: %v\n", err)
		return err
	}
	defer handleLocal.Close()
	handle = handleLocal

	packetSource := gopacket.NewPacketSource(handleLocal, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet, pduSess, outDstPort, dstIP)
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

	time.Sleep(1 * time.Second)

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

	if ipv4Hdr.Protocol == 1 {
		pduSess.Log.Println("This is an icmp packet!")
		return nil
	}
	// TCP
	if ipv4Hdr.Protocol == 6 {
		packet := gopacket.NewPacket(ipv4Pkt, layers.LayerTypeIPv4, gopacket.Default)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			//pduSess.Log.Println("This is a TCP packet!")

			tcp, _ := tcpLayer.(*layers.TCP)

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				pduSess.Log.Errorf("bad decode ip packet\n")
				return
			}

			ipp, _ := ipLayer.(*layers.IPv4)

			pduSess.Log.Errorf("HandleIPv4: %d\n", tcp.DstPort)
			pduSess.Log.Infof("From src ip %s:%d to dst ip %s:%d\n", ipp.SrcIP, tcp.SrcPort, ipp.DstIP, tcp.DstPort)

			// Need to forward back to localhost
			tcp.SrcPort = clientDstPort
			tcp.DstPort = clientSrcPort
			ipp.SrcIP = ipDstAddr
			ipp.DstIP = ipSrcAddr

			tcp.SetNetworkLayerForChecksum(ipp)

			pduSess.Log.Infof("Recv Updated src ip %s:%d to dst ip %s:%d\n", ipp.SrcIP, tcp.SrcPort, ipp.DstIP, tcp.DstPort)
			pduSess.Log.Infof("Recv Seq: %v || Ack: %v\n", tcp.Seq, tcp.Ack)
			pduSess.Log.Infof("Recv SYN: %t, ACK: %t, FIN: %t, RST: %t\n", tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST)

			appLayer := packet.ApplicationLayer()
			if appLayer != nil {
				payload := string(appLayer.Payload())
				payload = strings.ReplaceAll(payload, ipDstAddr.String(), "localhost")
				payload = strings.ReplaceAll(payload, string(clientDstPort), string(LocalPort))
				*packet.ApplicationLayer().(*gopacket.Payload) = []byte(payload)

				pduSess.Log.Warnf("App payload:\n%s\n", payload)
				pduSess.Log.Errorf("Saved to: %d\n", tcp.Seq)
				ackMap[tcp.Seq] = appLayer.Payload()
				pduSess.Log.Errorf("Saved to: %d\n", int(tcp.Seq)+len(appLayer.Payload()))
				ackMap[tcp.Seq+uint32(len(appLayer.Payload()))] = appLayer.Payload()

			} else {
			}

			sendPacket(pduSess, packet)

			if tcp.FIN {
				handleInTCP(nil)
			}

		} else {
			pduSess.Log.Errorf("Not a TCP packet\n")
			return
		}

	} else if ipv4Hdr.Protocol == 17 {
		pduSess.Log.Errorf("UDP not implement on recv: %d\n", ipv4Hdr.Protocol)
		return nil
	} else {
		pduSess.Log.Errorf("Unimplemented ipv4 protocol: %d\n", ipv4Hdr.Protocol)
		return nil
	}

	return nil
}

func HandleDlMessage(pduSess *realuectx.PduSession,
	msg common.InterfaceMessage,
) (err error) {
	if pduSess == nil {
		pduSess = lastPdu
		if pduSess == nil {
			pduSess.Log.Errorf("pdu sess nil")
			return nil
		}
	}
	pduSess.Log.Traceln("Handling DL user data packet from gNb")

	if msg.GetEventType() == common.LAST_DATA_PKT_EVENT {
		pduSess.Log.Debugln("Received last downlink data packet")
		pduSess.LastDataPktRecvd = true
		return nil
	}

	dataMsg := msg.(*common.UserDataMessage)

	if dataMsg.Qfi != nil {
		pduSess.Log.Traceln("Received QFI value in downlink user data packet:", *dataMsg.Qfi)
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
		//pduSess.Log.Infof("Protocol: %d\n", ipv4Hdr.Protocol)
		err = HandleIpv4Message(pduSess, ipv4Hdr, dataMsg.Payload)
		if err != nil {
			return fmt.Errorf("failed to handle our ipv4 message:%v", err)
		}
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
		time.Sleep(1 * time.Second)
		err = SendIcmpEchoRequest(pduSess)
		if err != nil {
			return fmt.Errorf("failed to send icmp echo req:%v", err)
		}
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
