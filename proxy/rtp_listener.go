/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package proxy

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/pion/rtp"
)

type Proxy struct {
	listener           *net.UDPConn
	addr               *net.UDPAddr
	streamHandler      *Exchanger
	listenerDone       chan struct{}
	proxyGlobalContext context.Context
}

func NewProxy(host, listenPort string, router *Exchanger) *Proxy {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, listenPort))
	if err != nil {
		panic(err)
	}

	return &Proxy{
		addr:               addr,
		streamHandler:      router,
		listenerDone:       make(chan struct{}),
		proxyGlobalContext: context.Background(),
	}
}

func (p *Proxy) StartListener() {
	var err error
	p.listener, err = net.ListenUDP("udp", p.addr)
	if err != nil {
		p.listenerDone <- struct{}{}
		return
	}

	logs.Log("[INFO][RTP-PROXY] UDP listener run at " + p.addr.String())
	p.configureProxy()
	for {
		datagram := make([]byte, 2048)
		n, remoteAddr, err := p.listener.ReadFromUDP(datagram)
		if err != nil {
			p.listenerDone <- struct{}{}
			logs.Log("[ERROR][RTP-PROXY] Occured " + err.Error() + " while listening UDP connections")
			break
		}

		go p.handleDatagram(datagram, n, remoteAddr)
	}
}

func (p *Proxy) WaitForShutdown() {
	<-p.listenerDone
	p.listener.Close()
	logs.Log("[ERROR][RTP-PROXY] UDP server dropped")
}

func (p *Proxy) handleDatagram(datagram []byte, n int, remoteAddr *net.UDPAddr) {
	var (
		pkt        rtp.Packet
		header     rtp.Header
		err        error
		pubMessage models.PublishProxy
		done       = make(chan struct{}, 1)
	)

	defer close(done)

	ctx, cancel := context.WithDeadline(p.proxyGlobalContext, time.Now().Add(4*time.Second))
	defer cancel()

	go func() {
		defer func() { done <- struct{}{} }()

		err = json.Unmarshal(datagram[:n], &pubMessage)
		// if the datagram is encoded in json
		if err == nil {
			handleMessage(pubMessage, p.streamHandler, remoteAddr, p.listener, 0)()
			return
		}

		_, err = header.Unmarshal(datagram[:n])
		if err != nil {
			return
		}

		err = pkt.Unmarshal(datagram[:n])
		if err != nil {
			return
		}

		handleMessage(datagram[:n], p.streamHandler, remoteAddr, p.listener, header.SequenceNumber)()
	}()

	select {
	case <-ctx.Done():
		logs.Log("[ERROR][RTP-PROXY] timeout occured while handling UDP connection")
		ctx.Err()
	case <-done:
		return
	}
}

// lean proxy configuration
func (p *Proxy) configureProxy() {
	p.listener.SetWriteBuffer(1024 * 1024)
	p.listener.SetReadBuffer(1024 * 1024)
}
