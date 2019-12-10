package main

import (
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	crossGFWHost = "Cross-GFW-Host"
)

const (
	reversedWebsite = "http://mirrors.codec-cluster.org/"
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
	u, _ := url.Parse(reversedWebsite)
	req.URL = u
	req.Header.Del(crossGFWHost)
	req.Host = u.Host
	http.DefaultClient.Do(req)

	// TODO
}
