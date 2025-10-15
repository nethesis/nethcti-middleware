/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package proxy

import (
	"errors"
	"net"
	"slices"
	"sync"
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
	go e.detectIdlePublishers()

	if configuration.Config.StaticJitterBuffer {
		e.waitForPlayback = true
	}

	return e
}

func (e *Exchanger) addPublisher(address string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	_, ok := e.pubsRoutingTable[address]
	if ok {
		return publishErr
	}

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

	resolved, resolveErr := net.ResolveUDPAddr("udp", pubAddr)
	if resolveErr != nil {
		return resolveErr
	}

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
	e.subsRoutingTable[pubAddr] = interestedSubs
	return nil
}

// This method enables publishers to forward their data
// to interested subscribers.
func (e *Exchanger) sendToMailBoxes(routingKey *net.UDPAddr, data []byte, seqNumber uint16) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	pub, err := e.routeByKey(routingKey)
	if err != nil {
		logs.Log("[ERROR][RTP-PROXY] Failed to route RTP packet: " + err.Error())
		return err
	}

	if pub != nil {
		pub.timestamp = time.Now()
	}

	subs, ok := e.subsRoutingTable[routingKey.String()]
	if !ok {
		logs.Log("[ERROR][RTP-PROXY] RTP packet dropped due to absent CTI clients")
		return subSearchErr
	}

	// if the jitter buffer is required each publisher
	// must push the packets to the jitter buffer
	if e.waitForPlayback {
		jb, ok := e.pubsJitterBuffers[routingKey.String()]
		if !ok {
			logs.Log("[ERROR][RTP-PROXY] RTP packet dropped due to absent jitter buffer")
			return nil
		}
		jb.push(data, seqNumber)
		return nil
	}

	for _, sub := range subs {
		mailBox, ok := e.mailBoxesHolder[sub.jobId]
		if !ok {
			continue
		}

		func(m chan<- []byte) {
			mailBox <- data
		}(mailBox)
	}

	return nil
}

// This method takes packets from the jitter buffer
// and forwards them to the appropriate subscribers.
func (e *Exchanger) forwardFromJitterBuffer(routingKey string) {
	e.mu.RLock()
	jb, ok := e.pubsJitterBuffers[routingKey]
	e.mu.RUnlock()

	if !ok {
		logs.Log("[ERROR][RTP-PROXY] Failed to run the packet reaper due to absent jitter buffer")
		return
	}

reaper_loop:
	for {
		select {
		case packet, ok := <-jb.playbackBus:
			if !ok {
				// channel is closed only when a communication
				// Timeout occurred (generally after 10 minutes)
				break reaper_loop
			}

			e.mu.RLock()
			subs, ok := e.subsRoutingTable[routingKey]

			if !ok {
				logs.Log("[ERROR][RTP-PROXY] " + subSearchErr.Error())
			} else {
				for _, sub := range subs {
					mailBox, ok := e.mailBoxesHolder[sub.jobId]
					if !ok {
						continue
					}

					func(c chan<- []byte) {
						c <- packet
					}(mailBox)
				}
			}
			e.mu.RUnlock()
		}
	}

	go e.deletePublisherJitterBuffer(routingKey)
}

// This function returns the publisher instance by
// looking it up in the pubsRoutingTable.
func (e *Exchanger) routeByKey(addr *net.UDPAddr) (*publisher, error) {
	locationIndex, ok := e.pubsRoutingTable[addr.String()]

	if !ok {
		return nil, routePublishErr
	}

	pub := e.pubs[locationIndex]
	if pub.addr.String() == "" {
		return nil, indexPublishErr
	}

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

func (e *Exchanger) deletePublisherJitterBuffer(pubAddr string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.pubsJitterBuffers, pubAddr)
}

func (e *Exchanger) detectIdlePublishers() {
	gcTick := time.NewTicker(e.gcRounds * time.Second)
	defer gcTick.Stop()

	var (
		gcTimestamp        time.Time
		pubLatestTimestamp time.Time
		timeout            = time.Duration(5) * time.Minute
		asyncDeleter       chan int
	)

	for range gcTick.C {
		e.mu.Lock()
		asyncDeleter = make(chan int, len(e.pubs))

		gcTimestamp = time.Now()
		for pIndex := range e.pubs {
			pubLatestTimestamp = e.pubs[pIndex].timestamp
			clock := gcTimestamp.Sub(pubLatestTimestamp)
			if clock > timeout {
				delete(e.pubsRoutingTable, e.pubs[pIndex].addr.String())
				delete(e.subsRoutingTable, e.pubs[pIndex].addr.String())
				asyncDeleter <- pIndex
			}
		}
		close(asyncDeleter)
		for pubToEvict := range asyncDeleter {
			e.pubs = slices.Delete(e.pubs, pubToEvict, pubToEvict+1)
		}
		e.mu.Unlock()
	}
}

type publisher struct {
	addr      *net.UDPAddr
	timestamp time.Time
}

func newPublisher(address string) *publisher {
	resolvedAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil
	}

	p := &publisher{
		addr: resolvedAddr,
	}

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
