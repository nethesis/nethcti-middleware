package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"os/exec"
	"time"
)

var udpServerAddr = "127.0.0.1:5004"

func main() {
	udpConn, err := net.Dial("udp", udpServerAddr)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer udpConn.Close()

	localAddr := udpConn.LocalAddr().String()

	pubMsg := map[string]string{
		"intercom_name": localAddr,
	}

	log.Printf("Intercome Address: %s", localAddr)

	data, err := json.Marshal(pubMsg)
	if err != nil {
		log.Fatal(err)
		return
	}
	_, err = udpConn.Write(data)
	if err != nil {
		log.Fatal(err)
		return
	}

	time.Sleep(25 * time.Second)

	_, port, _ := net.SplitHostPort(localAddr)

	cmd := exec.Command("ffmpeg", 
		"-loglevel", "debug",
		"-re", 
		"-i", "pub_test.mp4", 
		"-vf", "fps=25", 
		"-q:v", "3", 
		"-an",
		"-huffman", "0",
		"-codec", "mjpeg",
		"-f", "rtp", 
		"udp://127.0.0.1:5004?localport="+port,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmdErr := cmd.Start()
	if cmdErr != nil {
		log.Fatal(cmdErr)
		return
	}
}