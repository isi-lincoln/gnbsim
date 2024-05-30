// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"fmt"
	"net"
	"strconv"

	"github.com/omec-project/gnbsim/common"
	gnbctx "github.com/omec-project/gnbsim/gnodeb/context"
	"github.com/omec-project/gnbsim/logger"
	pdu "github.com/omec-project/gnbsim/realue/worker/pdusessworker"
	"github.com/omec-project/gnbsim/transportcommon"
	"github.com/omec-project/gnbsim/util/test"
	"github.com/sirupsen/logrus"
)

// Need to check if NGAP may exceed this limit
var MAX_UDP_PKT_LEN int = 65507

// TODO: Should have a context variable which when cancelled will result in
// the termination of the ReceiveFromPeer handler

// GnbUpTransport represents the User Plane transport of the GNodeB
type GnbUpTransport struct {
	GnbInstance *gnbctx.GNodeB

	/* UDP Connection without any association with peers */
	Conn *net.UDPConn

	Log *logrus.Entry
}

func NewGnbUpTransport(gnb *gnbctx.GNodeB) *GnbUpTransport {
	transport := &GnbUpTransport{}
	transport.GnbInstance = gnb
	transport.Log = logger.GNodeBLog.WithFields(logrus.Fields{"subcategory": "UserPlaneTransport"})

	return transport
}

func (upTprt *GnbUpTransport) Init() error {
	gnb := upTprt.GnbInstance
	ipPort := net.JoinHostPort(gnb.GnbN3Ip, strconv.Itoa(gnb.GnbN3Port))
	addr, err := net.ResolveUDPAddr("udp", ipPort)
	if err != nil {
		upTprt.Log.Errorln("ResolveUDPAddr returned:", err)
		return fmt.Errorf("invalid ip or port: %v", ipPort)
	}

	upTprt.Conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		upTprt.Log.Errorln("ListenUDP returned:", err)
		return fmt.Errorf("failed to create udp socket: %v", ipPort)
	}

	go upTprt.ReceiveFromPeer(nil)

	upTprt.Log.Infoln("User Plane transport listening on:", ipPort)
	return nil
}

// SendToPeer sends a GTP-U encoded packet to the specified UPF over the socket
func (upTprt *GnbUpTransport) SendToPeer(peer transportcommon.TransportPeer,
	pkt []byte, id uint64,
) (err error) {
	err = upTprt.CheckTransportParam(peer, pkt)
	if err != nil {
		return err
	}

	upf := peer.(*gnbctx.GnbUpf)

	pktLen := len(pkt)
	n, err := upTprt.Conn.WriteTo(pkt, upf.UpfAddr)
	if err != nil {
		upTprt.Log.Errorln("WriteTo returned:", err)
		return fmt.Errorf("failed to write on socket")
	} else if n != pktLen {
		return fmt.Errorf("total bytes:%v, written bytes:%v", pktLen, n)
	} else {
		upTprt.Log.Infof("Sent UDP Packet, length: %v bytes\n", n)
	}

	return
}

// ReceiveFromPeer continuously waits for an incoming message from the UPF
// It then routes the message to the GnbUpfWorker
func (upTprt *GnbUpTransport) ReceiveFromPeer(peer transportcommon.TransportPeer) {
	for {
		recvMsg := make([]byte, MAX_UDP_PKT_LEN)
		// TODO Handle notification, info
		n, srcAddr, err := upTprt.Conn.ReadFromUDP(recvMsg)
		if err != nil {
			upTprt.Log.Errorln("ReadFromUDP returned:", err)
		}
		srcIp := srcAddr.IP.String()
		upTprt.Log.Infof("Read %v bytes from %v:%v\n", n, srcIp, srcAddr.Port)

		gnbupf := upTprt.GnbInstance.GnbPeers.GetGnbUpf(srcIp)
		if gnbupf == nil {
			upTprt.Log.Errorln("No UPF Context found corresponding to IP:", srcIp)
			continue
		}

		tMsg := &common.TransportMessage{}
		tMsg.RawPkt = recvMsg[:n]
		// TODO: Start here @Lincoln
		/*
			gnbupf.ReadChan <- tMsg
		*/

		tMsg := msg.(*common.TransportMessage)
		gtpPdu, err := test.DecodeGTPv1Header(tMsg.RawPkt)
		if err != nil {
			gnbUpf.Log.Errorln("DecodeGTPv1Header() returned:", err)
			return fmt.Errorf("failed to decode gtp-u header")
		}
		switch gtpPdu.Hdr.MsgType {
		case test.TYPE_GPDU:
			/* A G-PDU is T-PDU encapsulated with GTP-U header*/
			gnbUpf.Log.Traceln("Processing downlink G-PDU packet")
			gnbUpUe := gnbUpf.GnbUpUes.GetGnbUpUe(gtpPdu.Hdr.Teid, true)
			if gnbUpUe == nil {
				return nil
				/* TODO: Send ErrorIndication message to upf*/
			}
			msg := &common.N3Message{}
			msg.Event = common.DL_UE_DATA_TRANSPORT_EVENT
			msg.Pdu = gtpPdu
			gnbUpUe.ReadDlChan <- msg

			if err != nil {
				gnbUpf.Log.Errorln("HandleDlGpduMessage() returned:", err)
				return fmt.Errorf("failed to handle downling gpdu message")
			}

			// TODO: Where goes the data come out?

			ueDataMsg := &common.UserDataMessage{}
			ueDataMsg.Payload = msg.Pdu.Payload

			optHdr := msg.Pdu.OptHdr
			if optHdr != nil {
				if optHdr.NextHdrType == test.PDU_SESS_CONTAINER_EXT_HEADER_TYPE {
					// TODO: Write a generic function to process all the extension
					// headers and return a map(ext header type - ext headers)
					// and user data
					var extHdr *test.PduSessContainerExtHeader
					ueDataMsg.Payload, extHdr, err = test.DecodePduSessContainerExtHeader(msg.Pdu.Payload)
					if err != nil {
						return fmt.Errorf("failed to decode pdu session container extension header:%v", err)
					}
					ueDataMsg.Qfi = new(uint8)
					*ueDataMsg.Qfi = extHdr.Qfi
					gnbue.Log.Infoln("Received QFI value in downlink G-PDU:", extHdr.Qfi)
				}
			}

			ueDataMsg.Event = common.DL_UE_DATA_TRANSFER_EVENT

			gnbue.Log.Infoln("Lincoln: Sent DL user data packet to UE")
			pdu.HandleDlMessage(nil, ueDataMsg)

			/* TODO: Handle More GTP-PDU types eg. Error Indication */
		}

	}
}

func (upTprt *GnbUpTransport) CheckTransportParam(peer transportcommon.TransportPeer,
	pkt []byte,
) error {
	upf := peer.(*gnbctx.GnbUpf)

	if upf == nil {
		return fmt.Errorf("UPF is nil")
	}

	if len(pkt) == 0 {
		return fmt.Errorf("packet len is 0")
	}

	if upf.UpfAddr == nil {
		return fmt.Errorf("UPF address is nil")
	}

	return nil
}

func (upTprt *GnbUpTransport) SendToPeerBlock(peer transportcommon.TransportPeer, pkt []byte, id uint64) ([]byte, error) {
	return nil, nil
}

func (upTprt *GnbUpTransport) ConnectToPeer(peer transportcommon.TransportPeer) error {
	return nil
}
