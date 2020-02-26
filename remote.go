package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type remoteProxy struct {
	secretKey       string
	reversedWebsite string
}

func (s *remoteProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get(HeaderDNSQuery) != "" && req.Header.Get(HeaderSecret) == s.secretKey {
		s.lookup(rw, req)
		return
	}

	if req.Header.Get(HeaderSecret) == s.secretKey {
		s.crossWall(rw, req)
		return
	}

	s.reverseProxy(rw, req)
}

func (s *remoteProxy) crossWall(rw http.ResponseWriter, req *http.Request) {
	req.Header.Del(HeaderSecret)

	appendPort(req)

	localProxy, _, _ := rw.(http.Hijacker).Hijack()
	target, err := net.Dial("tcp", req.Host)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		localProxy.Write([]byte(fmt.Sprintf("%s 200 OK\r\n\r\n", req.Proto)))
	} else {
		req.Write(target)
	}

	go transfer(localProxy, target)
	transfer(target, localProxy)
}

func (s *remoteProxy) reverseProxy(rw http.ResponseWriter, req *http.Request) {
	var u *url.URL
	var err error
	if u, err = url.Parse(s.reversedWebsite); err != nil {
		log.Panic(err)
	}

	req.URL.Host = u.Host
	req.URL.Scheme = u.Scheme
	req.Host = ""
	httputil.NewSingleHostReverseProxy(u).ServeHTTP(rw, req)
}

func (s *remoteProxy) lookup(rw http.ResponseWriter, req *http.Request) {
	addrs, err := net.LookupIP(req.Header.Get(HeaderDNSQuery))
	if err != nil || len(addrs) == 0 {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(addrs[0].String() + "\n"))
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}
