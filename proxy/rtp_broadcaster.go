/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
)

const basePrefix string = "job"

type Broadcaster struct {
	jobs        []string
	subHandler  *Exchanger
	mu          sync.Mutex
	jobsCounter atomic.Uint32
}

func NewBroadcaster(exc *Exchanger) *Broadcaster {
	return &Broadcaster{
		jobs:       make([]string, 0),
		subHandler: exc,
	}
}

// the broadcast abstraction provided is based on a best-effort one
// some CTI clients might not receive the same set of delivered messages
func (r *Broadcaster) HandleBroadcast(c *gin.Context) {
	var (
		messageType      int
		data             []byte
		err              error
		ctiMessage       models.SubscribeProxy
		rtpStreamMailBox chan []byte
		conn             *websocket.Conn
		wg               sync.WaitGroup
		jobId            string
	)

	conn, err = r.makeWebSocketConnection(c)
	if err != nil {
		return
	}
	defer conn.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			messageType, data, err = conn.ReadMessage()
			if err != nil || messageType != websocket.TextMessage {
				r.nack(conn, err)
				continue
			}

			err = json.Unmarshal(data, &ctiMessage)
			if err != nil {
				r.nack(conn, err)
				continue
			}

			jobId = r.createNewJob()
			rtpStreamMailBox = make(chan []byte)
			err := r.subHandler.registerSubscriberAndJob(jobId, ctiMessage.PubAddr, rtpStreamMailBox)
			if err != nil {
				close(rtpStreamMailBox)
				r.deleteJob(jobId)
				r.nack(conn, err)
				continue
			}
			r.ack(conn)
			break
		}
	}()

	wg.Wait()
	for {
		streamingPacket, ok := <-rtpStreamMailBox
		if !ok {
			r.deleteJob(jobId)
			r.nack(conn, errors.New("Mail Box closed due to an idle publisher"))
			break
		}

		err = conn.WriteMessage(websocket.BinaryMessage, streamingPacket)
		if err != nil {
			logs.Log("[RTP-PROXY][CLIENT] Broadcaster dropped due to following error: " + err.Error())
			r.deleteJob(jobId)
			r.subHandler.deleteMailBoxRegistration(jobId)
			break
		}
	}
}

func (r *Broadcaster) makeWebSocketConnection(c *gin.Context) (*websocket.Conn, error) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.String(http.StatusInternalServerError, "WebSocket upgrade failed: %v", err)
		return nil, err
	}

	return conn, nil
}

func (r *Broadcaster) createNewJob() string {
	var b strings.Builder

	r.jobsCounter.Add(1)
	jobNumber := strconv.Itoa(int(r.jobsCounter.Load()))

	b.WriteString(basePrefix)
	b.WriteString(jobNumber)

	go r.appendJob(b.String())

	return b.String()
}

func (r *Broadcaster) deleteJob(jobId string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var exitIndex int

	for jobIndex := range r.jobs {
		if r.jobs[jobIndex] == jobId {
			exitIndex = jobIndex
			break
		}
	}

	r.jobs = slices.Delete(r.jobs, exitIndex, exitIndex+1)
}

func (r *Broadcaster) appendJob(job string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.jobs = append(r.jobs, job)
}

func (r *Broadcaster) nack(conn *websocket.Conn, err error) {
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte(err.Error()))
		return
	}

	conn.WriteMessage(websocket.TextMessage, []byte("An error occurred while processing the message"))
}

func (r *Broadcaster) ack(conn *websocket.Conn) {
	conn.WriteMessage(websocket.TextMessage, []byte("Subscription executed successfully"))
}
