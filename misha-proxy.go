package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const crossWall = "daf07cfb73d0af0777e5"
const reversedWebsite = "http://mirrors.codec-cluster.org/"

type localProxy struct {
	remoteProxyAddr string
	secure          bool
}

func (l *localProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	hijacker, _ := rw.(http.Hijacker)
	client, _, _ := hijacker.Hijack()

	var remoteProxy net.Conn
	var err error

	if l.secure {
		remoteProxy, err = tls.Dial("tcp", l.remoteProxyAddr, nil)
	} else {
		remoteProxy, err = net.Dial("tcp", l.remoteProxyAddr)
	}
	if err != nil {
		return
	}

	req.Header.Set(crossWall, "on")
	req.Write(remoteProxy)

	go transfer(remoteProxy, client)
	transfer(client, remoteProxy)
}

type remoteProxy struct{}

func (s *remoteProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	crossWall := req.Header.Get(crossWall)
	req.Header.Del(crossWall)
	if crossWall == "on" {
		s.crossWall(rw, req)
		return
	}
	s.reverseProxy(rw, req)
}

func (s *remoteProxy) crossWall(rw http.ResponseWriter, req *http.Request) {
	if strings.Index(req.Host, ":") < 0 || strings.HasSuffix(req.Host, "]") {
		req.Host += ":80"
	}

	hijacker, _ := rw.(http.Hijacker)
	localProxy, _, _ := hijacker.Hijack()

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

type options struct {
	typo            string
	remoteProxyAddr string
	listenAddr      string
	certFile        string
	keyFile         string
	secure          bool
}

func main() {
	var o options

	flag.StringVar(&o.typo, "typo", "local", "start local or remote proxy. [local, remote]")
	flag.StringVar(&o.remoteProxyAddr, "remote-proxy-addr", "yourdomain.com:443", "the remote proxy address to connect to")
	flag.StringVar(&o.listenAddr, "addr", "127.0.0.1:8080", "listens on given address")
	flag.StringVar(&o.certFile, "cert", "", "cert file path")
	flag.StringVar(&o.keyFile, "key", "", "key file path")
	flag.BoolVar(&o.secure, "secure", false, "secure mode")
	flag.Parse()

	var listener net.Listener
	var err error

	if listener, err = net.Listen("tcp", o.listenAddr); err != nil {
		log.Panic(err)
	}

	if o.typo == "local" {
		err = startLocalProxy(o, listener)
	} else {
		err = startRemoteProxy(o, listener)
	}
	if err != nil {
		log.Panic(err)
	}
}

func startLocalProxy(o options, listener net.Listener) error {
	return http.Serve(listener, &localProxy{remoteProxyAddr: o.remoteProxyAddr, secure: o.secure})
}

func startRemoteProxy(o options, listener net.Listener) error {
	var err error

	if o.certFile != "" && o.keyFile != "" {
		err = http.ServeTLS(listener, &remoteProxy{}, o.certFile, o.keyFile)
	} else {
		err = http.Serve(listener, &remoteProxy{})
	}

	return err
}
