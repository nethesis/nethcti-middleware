/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package proxy

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
)

const defaultBufferMaxCapacity = 100

type (
	overflowPacketQueue struct {
		// FIFO queue used for temporarily storing packets
		oQueue              []node
		recentInsertionFlag bool
	}

	packetQueue struct {
		size        int
		maxCapacity int
		queue       []node
	}

	node struct {
		payload           []byte
		rtpSequenceNumber uint16
	}

	// static jitter buffer
	jitterBuffer struct {

		// primary queue
		buffer *packetQueue

		// Backup queue used only when the primary buffer is full
		packetOverflow *overflowPacketQueue
		playbackRate   int
		tick           *time.Ticker
		playbackBus    chan []byte
		mu             sync.Mutex
	}
)

func newJitterBuffer() *jitterBuffer {
	jb := &jitterBuffer{
		buffer:         newPacketQueue(),
		packetOverflow: newOverflowPacketQueue(),
		playbackBus:    make(chan []byte, 10),
	}

	ctx, _ := context.WithTimeout(context.Background(), time.Duration(10)*time.Minute)
	go jb.pop(ctx)
	return jb
}

func (j *jitterBuffer) push(payload []byte, sequenceNumber uint16) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.buffer.isQueueOverloaded() {
		j.packetOverflow.insertPacket(payload, sequenceNumber)
		return
	}

	j.buffer.enqueue(payload, sequenceNumber)
}

func (j *jitterBuffer) pop(ctx context.Context) {
	var (
		err error
		n   node
		ok  bool
	)

	j.playbackRate, err = strconv.Atoi(configuration.Config.JitterBufferPlaybackRate)

	// If an error occurred, set the default playback rate
	if err != nil {
		j.playbackRate = 20
	}

	j.tick = time.NewTicker(time.Duration(j.playbackRate) * time.Millisecond)
	defer j.tick.Stop()
	defer close(j.playbackBus)

	for range j.tick.C {
		if ctx.Err() != nil {
			return
		}

		j.mu.Lock()

		// Perform packet migration if the backup queue contains packets
		if j.packetOverflow.hasElements() {
			if n, ok := j.buffer.peekWithoutDeletion(); ok {
				if j.packetOverflow.recentInsertionFlag {
					j.packetOverflow.sortOverflowQueue()
					j.packetOverflow.recentInsertionFlag = false
				}

				packet := j.packetOverflow.popWithoutDeletion()
				if packet.rtpSequenceNumber < n.rtpSequenceNumber {
					j.playbackBus <- packet.payload
					j.packetOverflow.popFirstPacket()
					j.mu.Unlock()
					continue
				}
			}
		}

		if n, ok = j.buffer.peek(); ok {
			j.playbackBus <- n.payload
		}

		j.mu.Unlock()
	}

	logs.Log("[INFO][RTP-PROXY] jitter buffer reader dropped due to a connection timeout")
}

func newPacketQueue() *packetQueue {
	return &packetQueue{
		size:        0,
		maxCapacity: defaultBufferMaxCapacity,
		queue:       make([]node, 0),
	}
}

func (p *packetQueue) enqueue(payload []byte, sequenceNumber uint16) {
	n := newNode(payload, sequenceNumber)

	p.queue = append(p.queue, n)
	slices.SortFunc(p.queue, func(a, b node) int {
		return cmp.Compare(a.rtpSequenceNumber, b.rtpSequenceNumber)
	})
	p.size += 1
}

func (p *packetQueue) dequeue(locationIndex int) {
	p.queue = slices.Delete(p.queue, locationIndex, locationIndex+1)
	p.size -= 1
}

// This method is responsible for retrieving the first node from the primary queue
func (p *packetQueue) peek() (node, bool) {
	if p.size == 0 {
		return node{}, false
	}

	n := p.queue[0]
	p.dequeue(0)
	return n, true
}

func (p *packetQueue) peekWithoutDeletion() (node, bool) {
	if p.size == 0 {
		return node{}, false
	}

	return p.queue[0], true
}

func (p *packetQueue) isQueueOverloaded() bool {
	return p.size >= p.maxCapacity
}

func newNode(payload []byte, sequenceNumber uint16) node {
	return node{
		payload:           payload,
		rtpSequenceNumber: sequenceNumber,
	}
}

func newOverflowPacketQueue() *overflowPacketQueue {
	return &overflowPacketQueue{
		oQueue: make([]node, 0),
	}
}

// All packets that cannot be stored in the primary queue are frozen,
// i.e., they are temporarily stored in the backup queue.
func (o *overflowPacketQueue) insertPacket(payload []byte, sequenceNumber uint16) {
	node := newNode(payload, sequenceNumber)
	o.oQueue = append(o.oQueue, node)
	o.recentInsertionFlag = true
}

// FIFO retrieval
func (o *overflowPacketQueue) popFirstPacket() node {
	packet := o.oQueue[0]
	o.oQueue = slices.Delete(o.oQueue, 0, 1)
	return packet
}

func (o *overflowPacketQueue) sortOverflowQueue() {
	slices.SortFunc(o.oQueue, func(a, b node) int {
		return cmp.Compare(a.rtpSequenceNumber, b.rtpSequenceNumber)
	})
}

func (o *overflowPacketQueue) popWithoutDeletion() node {
	return o.oQueue[0]
}

func (o *overflowPacketQueue) hasElements() bool {
	return len(o.oQueue) > 0
}
