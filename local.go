package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/golang/groupcache/lru"
)

const (
	headerSecret = "Misha-Secret"
)

type answer struct {
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type response struct {
	Status int      `json:"Status"`
	Answer []answer `json:"Answer"`
}

type localProxy struct {
	sync.RWMutex
	remoteProxyAddr   string
	secureMode        bool
	secretKey         string
	chinaIP           *chinaIPRangeDB
	dnsCache          *lru.Cache
	autoCrossFirewall bool
	client            *http.Client
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

	req.Header.Set(headerSecret, l.secretKey)
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

	provider := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=A", host)
	req, _ := http.NewRequest(http.MethodGet, provider, nil)
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set(headerSecret, l.secretKey)

	res, err := l.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil
	}

	rr := &response{}
	json.NewDecoder(bytes.NewBuffer(buf)).Decode(rr)
	if rr.Status != 0 {
		return nil
	}
	if len(rr.Answer) == 0 {
		return nil
	}

	var ip net.IP
	for _, a := range rr.Answer {
		if a.Type == 1 {
			ip = net.ParseIP(a.Data)
			break
		}
	}

	if ip != nil {
		l.Lock()
		l.dnsCache.Add(host, ip)
		l.Unlock()
	}

	return ip
}

func appendPort(req *http.Request) {
	if strings.Index(req.Host, ":") < 0 || strings.HasSuffix(req.Host, "]") {
		req.Host += ":80"
	}
}
