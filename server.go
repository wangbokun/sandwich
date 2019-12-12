package main

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

const (
	crossFirewallHeader = "Cross-Firewall"
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
	targetHost := req.Header.Get(crossFirewallHeader)
	if targetHost != "" {
		s.crossFirewall(rw, targetHost)
		return
	}

	req.Header.Del(crossFirewallHeader)
	s.reverseProxy(rw, req)
}

func (s *server) crossFirewall(rw http.ResponseWriter, targetHost string) {
	hijacker, _ := rw.(http.Hijacker)
	client, _, _ := hijacker.Hijack()

	target, err := net.DialTimeout("tcp", targetHost, s.timeout)
	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		return
	}

	client.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	go transfer(client, target)
	transfer(target, client)
}

func (s *server) reverseProxy(rw http.ResponseWriter, req *http.Request) {
	u, _ := url.Parse(reversedWebsite)
	req.URL.Host = u.Host
	req.URL.Scheme = u.Scheme
	req.Host = ""
	httputil.NewSingleHostReverseProxy(u).ServeHTTP(rw, req)
}
