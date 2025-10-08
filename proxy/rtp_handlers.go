/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package proxy

import (
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/logs"
	"net"
)

type rtpProxyHandlerFunc func() 

func handleMessage(msg any, exc *Exchanger, remoteAddr *net.UDPAddr, listener *net.UDPConn, seqNumber uint16) rtpProxyHandlerFunc {
	return func() {
		var err error

		switch v := msg.(type) {
		case models.PublishProxy:
			exc.addPublisher(v.Name)
		case []byte:
			err = exc.sendToMailBoxes(remoteAddr, v, seqNumber)
		}

		if err != nil {
			if _, err := listener.WriteToUDP([]byte("nack"), remoteAddr); err != nil {
				logs.Log("[RTP-PROXY][FUNC] Occured " + err.Error() + " while writing NACK message to " + remoteAddr.String())
				return
			}
		}

		_, err = listener.WriteToUDP([]byte("ack"), remoteAddr)
		if err != nil {
			logs.Log("[RTP-PROXY][FUNC] Occured " + err.Error() + " while writing ACK message to " + remoteAddr.String())
		}
	}
}