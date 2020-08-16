package main

import (
	"crypto/tls"
	"log"
)

func main() {
	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{
		//InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "python.org:443", conf)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	n, err := conn.Write([]byte("GET / http1.1\r\nHost: python.org\r\n"))
	if err != nil {
		log.Println(n, err)
		return
	}

	buf := make([]byte, 4096)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		return
	}

	println(string(buf[:n]))
}
