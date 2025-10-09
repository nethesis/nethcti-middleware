/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package proxy

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
)

var (
	publishErr      = errors.New("Unable to create a new publisher")
	routePublishErr = errors.New("Unable to find the given publisher")
	indexPublishErr = errors.New("Unable to find the given publisher due to a corrupted location index")
	subSearchErr    = errors.New("Unable to find subscribers for the given routing key")
)

// The exchanger is responsible for buffering
// all RTP packets and relaying them to the
// appropriate CTI clients.
type Exchanger struct {
	pubs []*publisher

	// This field maps the publisher's UDP addresses (as keys)
	// to their corresponding subscribers (as values).
	subsRoutingTable map[string][]subscriber

	// This field provides a simple lookup optimization
	// for finding publishers, with O(1) complexity.
	pubsRoutingTable map[string]int

	// This field stores, for each WebSocket connection (i.e., job ID),
	// a shared communication channel between publisher and subscribers
	// (also referred to as mailboxes).
	mailBoxesHolder map[string]chan []byte
	size            int
	waitForPlayback bool

	// This field stores a dedicated jitter buffer for each publisher,
	// ensuring that each buffer handles packets from a single source.
	pubsJitterBuffers map[string]*jitterBuffer

	gcRounds time.Duration
	mu       sync.RWMutex
}

func NewExchanger() *Exchanger {
	e := &Exchanger{
		pubs:              make([]*publisher, 0),
		subsRoutingTable:  make(map[string][]subscriber),
		pubsRoutingTable:  make(map[string]int),
		mailBoxesHolder:   make(map[string]chan []byte),
		pubsJitterBuffers: make(map[string]*jitterBuffer),
		waitForPlayback:   false,
		size:              0,
		gcRounds:          time.Duration(3),
	}
	go e.startGarbageCollector()

	if configuration.Config.StaticJitterBuffer {
		e.waitForPlayback = true
	}

	return e
}

func (e *Exchanger) addPublisher(address string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	pub := newPublisher(address)
	if pub.addr.String() == "" {
		return publishErr
	}

	e.pubs = append(e.pubs, pub)
	e.pubsRoutingTable[pub.addr.String()] = e.size
	e.size += 1

	if e.waitForPlayback {
		e.pubsJitterBuffers[pub.addr.String()] = newJitterBuffer()
		go e.forwardFromJitterBuffer(pub.addr.String())
	}
	return nil
}

func (e *Exchanger) registerSubscriberAndJob(jobId, pubAddr string, c chan []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	resolved, _ := net.ResolveUDPAddr("udp", pubAddr)
	_, err := e.routeByKey(resolved)
	if err != nil {
		return err
	}

	sub := newSubscriber(jobId, pubAddr)
	e.mailBoxesHolder[jobId] = c

	interestedSubs, ok := e.subsRoutingTable[pubAddr]

	// if is the first registration ever
	if !ok {
		subsFragment := make([]subscriber, 0)
		subsFragment = append(subsFragment, sub)
		e.subsRoutingTable[pubAddr] = subsFragment
		return nil
	}

	interestedSubs = append(interestedSubs, sub)
	return nil
}

// This method enables publishers to forward their data
// to interested subscribers.
func (e *Exchanger) sendToMailBoxes(routingKey *net.UDPAddr, data []byte, seqNumber uint16) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	_, err := e.routeByKey(routingKey)
	if err != nil {
		logs.Log("[RTP-PROXY][EXCHANGER] Failed to route RTP packet: " + err.Error())
		return err
	}

	subs, ok := e.subsRoutingTable[routingKey.String()]
	if !ok {
		logs.Log("[RTP-PROXY][EXCHANGER] RTP packet dropped due to absent CTI clients")
		return subSearchErr
	}

	// if the jitter buffer is required each publisher
	// must push the packets to the jitter buffer
	if e.waitForPlayback {
		jb, ok := e.pubsJitterBuffers[routingKey.String()]
		if !ok {
			logs.Log("[RTP-PROXY][EXCHANGER] RTP packet dropped due to absent jitter buffer")
			return nil
		}
		jb.push(data, seqNumber)
		return nil
	}

	for _, sub := range subs {
		go func() {
			mailBox, ok := e.mailBoxesHolder[sub.jobId]
			if !ok {
				return
			}
			mailBox <- data
		}()
	}

	return nil
}

// This method takes packets from the jitter buffer
// and forwards them to the appropriate subscribers.
func (e *Exchanger) forwardFromJitterBuffer(routingKey string) {
	var (
		subs    []subscriber
		ok      bool
		mailBox chan []byte
		jb      *jitterBuffer
	)

	e.mu.RLock()
	jb, ok = e.pubsJitterBuffers[routingKey]
	e.mu.RUnlock()

	if !ok {
		logs.Log("[RTP-PROXY][EXCHANGER] Failed to run the packet reaper due to absent jitter buffer")
		return
	}

	for {
		select {
		case packet, ok := <-jb.playbackBus:
			if !ok {
				// channel is closed only when a communication
				// Timeout occurred (generally after 10 minutes)
				return
			}

			e.mu.RLock()
			subs, ok = e.subsRoutingTable[routingKey]
			e.mu.RUnlock()

			if !ok {
				logs.Log("[RTP-PROXY][EXCHANGER] " + subSearchErr.Error())
				continue
			}

			for _, sub := range subs {
				e.mu.RLock()
				mailBox, ok = e.mailBoxesHolder[sub.jobId]
				e.mu.RUnlock()
				if !ok {
					return
				}
				mailBox <- packet
			}
		}
	}
}

// This function returns the publisher instance by
// looking it up in the pubsRoutingTable.
func (e *Exchanger) routeByKey(pubAddr *net.UDPAddr) (*publisher, error) {
	locationIndex, ok := e.pubsRoutingTable[pubAddr.String()]

	if !ok {
		return nil, routePublishErr
	}

	pub := e.pubs[locationIndex]
	if pub.addr.String() == "" {
		return nil, indexPublishErr
	}

	pub.activeStatus.Store(true)
	return pub, nil
}

func (e *Exchanger) deleteMailBoxRegistration(jobId string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	mailBox, ok := e.mailBoxesHolder[jobId]
	if !ok {
		return
	}

	close(mailBox)
	delete(e.mailBoxesHolder, jobId)
}

func (e *Exchanger) startGarbageCollector() {
	gcTick := time.NewTicker(e.gcRounds * time.Second)
	defer gcTick.Stop()

	for range gcTick.C {
		e.mu.Lock()
		for pIndex := range e.pubs {
			result := e.pubs[pIndex].activeStatus.CompareAndSwap(true, false)
			if !result {
				delete(e.pubsRoutingTable, e.pubs[pIndex].addr.String())
				delete(e.pubsJitterBuffers, e.pubs[pIndex].addr.String())
				subs := e.subsRoutingTable[e.pubs[pIndex].addr.String()]
				for _, sub := range subs {
					mailBox, ok := e.mailBoxesHolder[sub.jobId]
					if !ok {
						continue
					}
					close(mailBox)
					delete(e.mailBoxesHolder, sub.jobId)
				}
				delete(e.subsRoutingTable, e.pubs[pIndex].addr.String())
			}
		}
		e.mu.Unlock()
	}
}

type publisher struct {
	addr         *net.UDPAddr
	activeStatus atomic.Bool
}

func newPublisher(address string) *publisher {
	resolvedAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil
	}

	p := &publisher{
		addr: resolvedAddr,
	}
	p.activeStatus.Store(true)
	return p
}

type subscriber struct {
	jobId         string
	publisherAddr string
}

func newSubscriber(jobNumber, publisherAddr string) subscriber {
	return subscriber{
		jobId:         jobNumber,
		publisherAddr: publisherAddr,
	}
}
