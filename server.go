package main

import (
	"net"
	"net/http"
	"time"
)

const (
	crossGFWHost = "Cross-GFW-Host"
)

type server struct {
	timeout time.Duration
}

func newServer(timeout time.Duration) *server {
	return &server{
		timeout: timeout,
	}
}

func (s *server) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get(crossGFWHost) != "" {
		s.crossGFW(rw, req)
		return
	}
	s.reverseProxy(rw, req)
}

func (s *server) crossGFW(w http.ResponseWriter, req *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}

	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}

	destAddr := req.Header.Get(crossGFWHost)

	destConn, err := net.DialTimeout("tcp", destAddr, s.timeout)
	if err != nil {
		return
	}

	go transfer(client, destConn)
	transfer(destConn, client)
}

func (s *server) reverseProxy(rw http.ResponseWriter, req *http.Request) {

}
