package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

const (
	defaultTTL = 4 * time.Hour
)

type dns interface {
	lookup(host string) (ip net.IP, expriedAt time.Time)
}

type dnsOverHTTPS struct {
	client *http.Client
}

func (d *dnsOverHTTPS) lookup(host string) (ip net.IP, expriedAt time.Time) {
	provider := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s", host)
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

type dnsOverUDP struct {
}

func (d *dnsOverUDP) lookup(host string) (ip net.IP, expriedAt time.Time) {
	answers, err := net.LookupIP(host)
	if err != nil {
		return nil, time.Now()
	}

	return answers[0], time.Now().Add(defaultTTL)
}
