package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/golang/groupcache/lru"
)

const (
	HeaderDNSQuery = "Misha-DNS"
	HeaderSecret   = "Misha-Secret"
)

type localProxy struct {
	*sync.RWMutex
	remoteProxyAddr   string
	secureMode        bool
	secretKey         string
	chinaIP           *chinaIPRangeDB
	dnsCache          *lru.Cache
	autoCrossFirewall bool
}

func (l *localProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	appendPort(req)

	client, _, _ := rw.(http.Hijacker).Hijack()
	host, _, _ := net.SplitHostPort(req.Host)

	if l.autoCrossFirewall && (l.chinaIP.contains(net.ParseIP(host)) || l.chinaIP.contains(l.lookup(host))) {
		l.direct(client, req)
		return
	}

	l.remote(client, req)
}

func (l *localProxy) direct(client net.Conn, req *http.Request) {
	target, err := net.Dial("tcp", req.Host)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		client.Write([]byte(fmt.Sprintf("%s 200 OK\r\n\r\n", req.Proto)))
	} else {
		req.Write(target)
	}

	go transfer(client, target)
	transfer(target, client)
}

func (l *localProxy) remote(client net.Conn, req *http.Request) {
	var remoteProxy net.Conn
	var err error

	if l.secureMode {
		remoteProxy, err = tls.Dial("tcp", l.remoteProxyAddr, nil)
	} else {
		remoteProxy, err = net.Dial("tcp", l.remoteProxyAddr)
	}
	if err != nil {
		return
	}

	req.Header.Set(HeaderSecret, l.secretKey)
	req.Write(remoteProxy)

	go transfer(remoteProxy, client)
	transfer(client, remoteProxy)
}

func (l *localProxy) lookup(host string) net.IP {
	if net.ParseIP(host) != nil {
		return net.ParseIP(host)
	}

	l.RLock()
	if v, ok := l.dnsCache.Get(host); ok {
		l.RUnlock()
		return v.(net.IP)
	}
	l.RUnlock()

	var url string
	if l.secureMode {
		url = fmt.Sprintf("https://%s/", l.remoteProxyAddr)
	} else {
		url = fmt.Sprintf("http://%s/", l.remoteProxyAddr)
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set(HeaderDNSQuery, host)
	req.Header.Set(HeaderSecret, l.secretKey)

	res, err := http.DefaultClient.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil
	}

	if res.StatusCode != http.StatusOK {
		return nil
	}

	reader := bufio.NewReader(res.Body)
	line, _, err := reader.ReadLine()
	if err != nil {
		return nil
	}

	ip := net.ParseIP(string(line))
	if ip != nil {
		l.Lock()
		defer l.Unlock()
		l.dnsCache.Add(host, ip)
	}

	return ip
}

func appendPort(req *http.Request) {
	if strings.Index(req.Host, ":") < 0 || strings.HasSuffix(req.Host, "]") {
		req.Host += ":80"
	}
}
