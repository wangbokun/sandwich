package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

const crossFirewallHeader = "Cross-Firewall"
const reversedWebsite = "http://mirrors.codec-cluster.org/"

var statusOK = []byte("HTTP/1.0 200 OK\r\n\r\n")
var statusServiceUnavailable = []byte("HTTP/1.0 503 Service Unavailable\r\n\r\n")

type localProxy struct {
	timeout            time.Duration
	remoteProxyWebsite string
}

func newLocalProxy(timeout time.Duration, remoteProxyWebsite string) *localProxy {
	return &localProxy{timeout: timeout, remoteProxyWebsite: remoteProxyWebsite}
}

func (l *localProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	isConnectRequest := req.Method == http.MethodConnect
	destHost := req.Host
	if !isConnectRequest && req.URL.Port() == "" {
		destHost += ":80"
	}

	hijacker, _ := rw.(http.Hijacker)
	client, _, _ := hijacker.Hijack()

	u, _ := url.Parse(l.remoteProxyWebsite)
	var remoteProxy net.Conn
	var err error

	defer func() {
		if err != nil {
			client.Write(statusServiceUnavailable)
		}
	}()

	if u.Scheme == "https" {
		remoteProxy, err = tls.Dial("tcp", u.Host, nil)
	} else {
		remoteProxy, err = net.DialTimeout("tcp", u.Host, l.timeout)
	}
	if err != nil {
		return
	}

	var remotePorxyReq *http.Request
	if remotePorxyReq, err = http.NewRequest("GET", l.remoteProxyWebsite, nil); err != nil {
		return
	}

	remotePorxyReq.Header.Set(crossFirewallHeader, destHost)
	if err = remotePorxyReq.Write(remoteProxy); err != nil {
		return
	}

	var resp *http.Response
	if resp, err = http.ReadResponse(bufio.NewReader(remoteProxy), remotePorxyReq); err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = nil
		client.Write(statusServiceUnavailable)
		return
	}

	if isConnectRequest {
		client.Write(statusOK)
	} else {
		req.Write(remoteProxy)
	}

	go transfer(remoteProxy, client)
	transfer(client, remoteProxy)
}

type remoteProxy struct {
	timeout time.Duration
}

func newRemoteProxy(timeout time.Duration) *remoteProxy {
	return &remoteProxy{
		timeout: timeout,
	}
}

func (s *remoteProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	targetHost := req.Header.Get(crossFirewallHeader)
	if targetHost != "" {
		s.crossFirewall(rw, targetHost)
		return
	}

	req.Header.Del(crossFirewallHeader)
	s.reverseProxy(rw, req)
}

func (s *remoteProxy) crossFirewall(rw http.ResponseWriter, targetHost string) {
	hijacker, _ := rw.(http.Hijacker)
	client, _, _ := hijacker.Hijack()

	target, err := net.DialTimeout("tcp", targetHost, s.timeout)
	if err != nil {
		rw.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	client.Write(statusOK)

	go transfer(client, target)
	transfer(target, client)
}

func (s *remoteProxy) reverseProxy(rw http.ResponseWriter, req *http.Request) {
	u, _ := url.Parse(reversedWebsite)
	req.URL.Host = u.Host
	req.URL.Scheme = u.Scheme
	req.Host = ""
	httputil.NewSingleHostReverseProxy(u).ServeHTTP(rw, req)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()

	io.Copy(dst, src)
}
