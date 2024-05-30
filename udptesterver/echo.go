package main

import (
	"fmt"
	"net"
	"os"
)

// https://stackoverflow.com/questions/26028700/write-to-client-udp-socket-in-go
var (
	proto = "udp"
	addr  = ":11000"
)

func main() {

	if value, ok := os.LookupEnv("PORT"); ok {
		addr = value
	}

	conn, err := net.ListenPacket(proto, addr)
	if err != nil {
		fmt.Errorf("error listening on sock: %v\n", err)
	}
	for {
		buf := make([]byte, 1500)
		n, dst, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Errorf("error reading from sock: %v\n", err)
		}

		fmt.Println("echoing : %s from %s", string(buf[:n]), dst)

		conn.WriteTo(buf, dst)
	}
}
