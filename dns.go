package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	_ "unsafe"
)

const (
	defaultTTL = 24 * time.Hour
)

type dns interface {
	lookup(host string) (ip net.IP, expriedAt time.Time)
}

type dnsOverHostsFile struct {
}

func (d *dnsOverHostsFile) lookup(host string) (ip net.IP, expriedAt time.Time) {
	res := goLookupIPFiles(host)
	if len(res) == 0 {
		return nil, time.Now()
	}
	return res[0].IP, time.Now()
}

type dnsOverUDP struct {
}

func (d *dnsOverUDP) lookup(host string) (ip net.IP, expriedAt time.Time) {
	answers, err := net.LookupIP(host)
	if err != nil {
		return nil, time.Now()
	}

	return answers[0], time.Now().Add(defaultTTL)
}

type smartDNS struct {
	lookups []func(host string) (net.IP, time.Time)
}

func newSmartDNS(lookups ...func(host string) (net.IP, time.Time)) *smartDNS {
	d := &smartDNS{}
	d.lookups = append(d.lookups, lookups...)
	return d
}

func (d *smartDNS) lookup(host string) (ip net.IP, expriedAt time.Time) {
	for _, lookup := range d.lookups {
		ip, expriedAt = lookup(host)
		if ip != nil {
			break
		}
	}
	return
}

type dnsOverHTTPS struct {
	client *http.Client
}

func (d *dnsOverHTTPS) lookup(host string) (ip net.IP, expriedAt time.Time) {
	provider := fmt.Sprintf("https://rubyfish.cn/dns-query?name=%s", host)
	req, _ := http.NewRequest(http.MethodGet, provider, nil)
	req.Header.Set("Accept", "application/dns-json")

	res, err := d.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, time.Now()
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, time.Now()
	}

	rr := &response{}
	json.NewDecoder(bytes.NewBuffer(buf)).Decode(rr)
	if rr.Status != 0 {
		return nil, time.Now()
	}
	if len(rr.Answer) == 0 {
		return nil, time.Now()
	}

	var answer *answer
	for _, a := range rr.Answer {
		if a.Type == typeIPv4 || a.Type == typeIPv6 {
			answer = &a
			break
		}
	}

	if answer != nil {
		ip = net.ParseIP(answer.Data)
		expriedAt = time.Now().Add(time.Duration(answer.TTL) * time.Second)
	}

	return ip, expriedAt
}

//go:linkname goLookupIPFiles net.goLookupIPFiles
func goLookupIPFiles(name string) (addrs []net.IPAddr)
