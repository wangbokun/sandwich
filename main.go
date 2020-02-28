package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/golang/groupcache/lru"
)

type options struct {
	typo              string
	remoteProxy       string
	listenAddr        string
	certFile          string
	privateKeyFile    string
	secretKey         string
	reversedWebsite   string
	autoCrossFirewall bool
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var o options

	flag.StringVar(&o.typo, "typo", "local", "start local or remote proxy. [local, remote]")
	flag.StringVar(&o.remoteProxy, "remote-proxy", "https://yourdomain.com:443", "the remote proxy address to connect to")
	flag.StringVar(&o.listenAddr, "listen-addr", "127.0.0.1:9876", "listens on given address")
	flag.StringVar(&o.certFile, "cert-file", "", "cert file path")
	flag.StringVar(&o.privateKeyFile, "private-key-file", "", "private key file path")
	flag.StringVar(&o.secretKey, "secret-key", "daf07cfb73d0af0777e5", "secrect header key to cross firewall")
	flag.StringVar(&o.reversedWebsite, "reversed-website", "http://mirrors.codec-cluster.org/", "reversed website to fool firewall")
	flag.BoolVar(&o.autoCrossFirewall, "auto-cross-firewall", true, "auto cross firewall")
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

func startLocalProxy(o options, listener net.Listener) (err error) {
	u, err := url.Parse(o.remoteProxy)
	if err != nil {
		return err
	}

	h := make(http.Header, 0)
	h.Set(headerSecret, o.secretKey)

	err = http.Serve(listener, &localProxy{
		remoteProxy:       u,
		secretKey:         o.secretKey,
		chinaIP:           newChinaIPRangeDB(),
		dnsCache:          lru.New(8192),
		autoCrossFirewall: o.autoCrossFirewall,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: func(request *http.Request) (i *url.URL, e error) {
					return u, nil
				},
				TLSClientConfig:    &tls.Config{InsecureSkipVerify: false},
				ProxyConnectHeader: h,
			},
		},
	})
	return err
}

func startRemoteProxy(o options, listener net.Listener) error {
	var err error

	r := &remoteProxy{
		secretKey:       o.secretKey,
		reversedWebsite: o.reversedWebsite,
	}
	if o.certFile != "" && o.privateKeyFile != "" {
		err = http.ServeTLS(listener, r, o.certFile, o.privateKeyFile)
	} else {
		err = http.Serve(listener, r)
	}

	return err
}
