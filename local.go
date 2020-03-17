package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
)

const (
	headerSecret = "Misha-Secret"
)

const (
	typeIPv4 = 1
	typeIPv6 = 28
)

type answerCache struct {
	ip        net.IP
	expiredAt time.Time
}

type answer struct {
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
	ip   net.IP
}

type response struct {
	Status int      `json:"Status"`
	Answer []answer `json:"Answer"`
}

type localProxy struct {
	sync.RWMutex
	remoteProxyAddr   *url.URL
	secretKey         string
	chinaIPRangeDB    *IPRangeDB
	dnsCache          *lru.Cache
	autoCrossFirewall bool
	client            *http.Client
	dns               dns
}

func (l *localProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	targetAddr := appendPort(req.Host, req.URL.Scheme)
	client, _, _ := rw.(http.Hijacker).Hijack()
	host, _, _ := net.SplitHostPort(targetAddr)

	if !l.autoCrossFirewall {
		l.remote(client, req)
		return
	}

	targetIP := net.ParseIP(host)

	if targetIP != nil && l.chinaIPRangeDB.contains(targetIP) {
		l.direct(client, req, targetAddr)
		return
	}

	if targetIP == nil && l.chinaIPRangeDB.contains(l.lookup(host)) {
		l.direct(client, req, targetAddr)
		return
	}

	if targetIP != nil && privateIPRange.contains(targetIP) && isUnPollutedPrivateDNSAnswer(targetAddr) {
		l.direct(client, req, targetAddr)
		return
	}

	if targetIP == nil && privateIPRange.contains(l.lookup(host)) && isUnPollutedPrivateDNSAnswer(targetAddr) {
		l.direct(client, req, targetAddr)
		return
	}

	l.remote(client, req)
}

func (l *localProxy) direct(client net.Conn, req *http.Request, targetAddr string) {
	target, err := net.Dial("tcp", targetAddr)
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

	remoteProxyAddr := appendPort(l.remoteProxyAddr.Host, l.remoteProxyAddr.Scheme)

	if l.remoteProxyAddr.Scheme == "https" {
		remoteProxy, err = tls.Dial("tcp", remoteProxyAddr, nil)
	} else {
		remoteProxy, err = net.Dial("tcp", remoteProxyAddr)
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
	l.Lock()
	if v, ok := l.dnsCache.Get(host); ok {
		r := v.(*answerCache)
		if time.Now().Before(r.expiredAt) {
			l.Unlock()
			return r.ip
		}
		l.dnsCache.Remove(host)
	}
	l.Unlock()

	ip, expiredAt := l.dns.lookup(host)
	if ip != nil {
		l.Lock()
		l.dnsCache.Add(host, &answerCache{
			ip:        ip,
			expiredAt: expiredAt,
		})
		l.Unlock()
	}
	return ip
}

func (l *localProxy) pullLatestIPRange(ctx context.Context) error {
	addr := "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	res, err := l.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return err
	}

	reader := bufio.NewReader(res.Body)
	var line []byte
	var db []*ipRange
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if line, _, err = reader.ReadLine(); err != nil && err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(string(line), "|", 6)
		if len(parts) != 6 {
			continue
		}

		cc, typ, start, value := parts[1], parts[2], parts[3], parts[4]
		if !(cc == "CN" && (typ == "ipv4" || typ == "ipv6")) {
			continue
		}

		prefixLength, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if typ == "ipv4" {
			prefixLength = 32 - int(math.Log(float64(prefixLength))/math.Log(2))
		}

		db = append(db, &ipRange{value: fmt.Sprintf("%s/%d", start, prefixLength)})
	}

	if len(db) == 0 {
		return errors.New("empty ip range db")
	}

	l.chinaIPRangeDB.Lock()
	defer l.chinaIPRangeDB.Unlock()
	l.chinaIPRangeDB.db = db
	l.chinaIPRangeDB.init()
	sort.Sort(l.chinaIPRangeDB)
	return nil
}

func appendPort(host string, schema string) string {
	if strings.Index(host, ":") < 0 || strings.HasSuffix(host, "]") {
		if schema == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host
}

func isUnPollutedPrivateDNSAnswer(address string) bool {
	c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err != nil {
		return false
	}

	c.Close()
	return true
}
