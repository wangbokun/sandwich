package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"time"
)

type options struct {
	typo               string
	timeout            time.Duration
	remoteProxyWebsite string
	listenAddr         string
	certFile           string
	keyFile            string
}

func main() {
	var o options

	flag.StringVar(&o.typo, "typo", "local", "start local proxy or server. [local remote]")
	flag.DurationVar(&o.timeout, "timeout", 10*time.Second, "timeout for waiting to connect to the server")
	flag.StringVar(&o.remoteProxyWebsite, "remote-proxy-website", "https://yourdomain.com:443", "the server website to connect to")
	flag.StringVar(&o.listenAddr, "addr", "127.0.0.1:8080", "local or remote proxy listens on given address")
	flag.StringVar(&o.certFile, "cert", "", "cert file path")
	flag.StringVar(&o.keyFile, "key", "", "key file path")
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
	return http.Serve(listener, newLocalProxy(o.timeout, o.remoteProxyWebsite))
}

func startRemoteProxy(o options, listener net.Listener) error {
	var err error
	server := newRemoteProxy(o.timeout)

	if o.certFile != "" && o.keyFile != "" {
		err = http.ServeTLS(listener, server, o.certFile, o.keyFile)
	} else {
		err = http.Serve(listener, server)
	}

	return err
}
