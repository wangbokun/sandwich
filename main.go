package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/golang/groupcache/lru"
	"github.com/jasonlvhit/gocron"
)

type options struct {
	remoteMode        bool
	remoteProxy       string
	listenAddr        string
	certFile          string
	privateKeyFile    string
	secretKey         string
	reversedWebsite   string
	autoCrossFirewall bool
	useDoH            bool
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var o options

	flag.BoolVar(&o.remoteMode, "remote-mode", true, "start remote proxy. default: local-mode")
	flag.StringVar(&o.remoteProxy, "remote-proxy", "https://yourdomain.com:443", "the remote proxy address to connect to")
	flag.StringVar(&o.listenAddr, "listen-addr", "127.0.0.1:9876", "listens on given address")
	flag.StringVar(&o.certFile, "cert-file", "", "cert file path")
	flag.StringVar(&o.privateKeyFile, "private-key-file", "", "private key file path")
	flag.StringVar(&o.secretKey, "secret-key", "daf07cfb73d0af0777e5", "secrect header key to cross firewall")
	flag.StringVar(&o.reversedWebsite, "reversed-website", "http://mirrors.codec-cluster.org/", "reversed website to fool firewall")
	flag.BoolVar(&o.autoCrossFirewall, "auto-cross-firewall", true, "auto cross firewall")
	flag.BoolVar(&o.useDoH, "use-doh", true, "use DoH method to lookup a domain. default: use traditional lookup method")
	flag.Parse()

	var listener net.Listener
	var err error

	if listener, err = net.Listen("tcp", o.listenAddr); err != nil {
		log.Panic(err)
	}

	if isFlagPassed("remote-mode") {
		err = startRemoteProxy(o, listener)
	} else {
		err = startLocalProxy(o, listener)
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

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(request *http.Request) (i *url.URL, e error) {
				request.Header.Set(headerSecret, o.secretKey)
				return u, nil
			},
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: false},
			ProxyConnectHeader: h,
		},
	}

	var dns dns
	if isFlagPassed("use-doh") {
		dns = &dnsOverHTTPS{client: client}
	} else {
		dns = &dnsOverUDP{}
	}

	local := &localProxy{
		remoteProxy:       u,
		secretKey:         o.secretKey,
		chinaIP:           newChinaIPRangeDB(),
		dnsCache:          lru.New(8192),
		autoCrossFirewall: isFlagPassed("auto-cross-firewall"),
		client:            client,
		dns:               dns,
	}

	ctx, cancel := context.WithCancel(context.Background())

	go local.pullLatestIPRange(ctx)

	gocron.Every(4).Hours().DoSafely(local.pullLatestIPRange, ctx)
	gocron.Start()

	defer cancel()

	return http.Serve(listener, local)
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

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
