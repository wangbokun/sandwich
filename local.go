package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	socks5         = 0x05
	noAuthRequired = 0x00
)

const (
	succeeded = 0x00
	rsv       = 0x00
	ipv4      = 0x01
)

const (
	connectCmd = 0x01
)

const (
	typeIPv4   = 0x01
	typeDomain = 0x03
	typeIPv6   = 0x04
)

type localProxy struct {
	listener      net.Listener
	timeout       time.Duration
	serverWebsite string
}

func newLocalProxy(listener net.Listener, o options) *localProxy {
	return &localProxy{
		listener:      listener,
		timeout:       o.timeout,
		serverWebsite: o.serverWebsite,
	}
}

func (l *localProxy) listen() {
	listener := l.listener.(*net.TCPListener)
	var client *net.TCPConn
	for {
		client, _ = listener.AcceptTCP()
		go l.handleConn(client)
	}
}

func (l *localProxy) handleConn(client *net.TCPConn) {
	defer client.Close()

	if !l.authenticate(client) {
		return
	}

	destAddr, ok := l.handleRequest(client)
	if !ok {
		return
	}

	reply := []byte{socks5, succeeded, rsv, ipv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := client.Write(reply); err != nil {
		return
	}

	u, _ := url.Parse(l.serverWebsite)
	var server net.Conn
	var err error

	if u.Scheme == "https" {
		server, err = tls.Dial("tcp", u.Host, &tls.Config{})
	} else {
		server, err = net.DialTimeout("tcp", u.Host, l.timeout)
	}
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", l.serverWebsite, nil)
	if err != nil {
		return
	}
	req.Header.Set(crossFirewallHeader, destAddr)

	if err := req.Write(server); err != nil {
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(server), req)
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		return
	}

	go transfer(server, client)
	transfer(client, server)
}

func (l *localProxy) authenticate(client *net.TCPConn) bool {
	/*
	   +----+----------+----------+
	   |VER | NMETHODS | METHODS  |
	   +----+----------+----------+
	   | 1  |    1     | 1 to 255 |
	   +----+----------+----------+
	*/
	buf := make([]byte, 257)
	n, err := io.ReadAtLeast(client, buf, 2)
	if err != nil {
		return false
	}

	if buf[0] != socks5 {
		return false
	}

	authLen := int(buf[1]) + 2
	if n < authLen {
		if _, err := io.ReadFull(client, buf[n:authLen]); err != nil {
			return false
		}
	} else if n > authLen {
		return false
	}

	if _, err := client.Write([]byte{socks5, noAuthRequired}); err != nil {
		return false
	}

	return true
}

func (l *localProxy) handleRequest(clientConn *net.TCPConn) (string, bool) {
	/*
	   +----+-----+-------+------+----------+----------+
	   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	   +----+-----+-------+------+----------+----------+
	   | 1  |  1  | X'00' |  1   | Variable |    2     |
	   +----+-----+-------+------+----------+----------+
	*/
	buf := make([]byte, 262)
	n, err := io.ReadAtLeast(clientConn, buf, 5)
	if err != nil {
		return "", false
	}

	if buf[0] != socks5 {
		return "", false
	}
	if buf[1] != connectCmd {
		return "", false
	}

	var reqLen int
	switch buf[3] {
	case typeIPv4:
		reqLen = 10
	case typeDomain:
		reqLen = int(buf[4]) + 7
	case typeIPv6:
		reqLen = 22
	default:
		return "", false
	}

	if n < reqLen {
		if _, err := io.ReadFull(clientConn, buf[n:reqLen]); err != nil {
			return "", false
		}
	} else if n > reqLen {
		return "", false
	}

	rawDstAddr := buf[3:reqLen]
	return parseDestAddr(rawDstAddr)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()

	io.Copy(dst, src)
}

func parseDestAddr(rawDestAddr []byte) (host string, ok bool) {
	/*
	   +------+----------+----------+
	   | ATYP | DST.ADDR | DST.PORT |
	   +------+----------+----------+
	   |  1   | Variable |    2     |
	   +------+----------+----------+
	*/
	var destIP string
	var destPort []byte

	switch rawDestAddr[0] {
	case typeDomain:
		destIP = string(rawDestAddr[2 : 2+int(rawDestAddr[1])])
		destPort = rawDestAddr[2+int(rawDestAddr[1]) : 2+int(rawDestAddr[1])+2]
	case typeIPv4:
		destIP = net.IP(rawDestAddr[1 : 1+net.IPv4len]).String()
		destPort = rawDestAddr[1+net.IPv4len : +1+net.IPv4len+2]
	case typeIPv6:
		destIP = net.IP(rawDestAddr[1 : 1+net.IPv6len]).String()
		destPort = rawDestAddr[1+net.IPv6len : 1+net.IPv6len+2]
	default:
		return "", false
	}
	host = net.JoinHostPort(destIP, strconv.Itoa(int(binary.BigEndian.Uint16(destPort))))
	return host, true
}
