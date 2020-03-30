package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

const (
	defaultTTL = 24 * time.Hour
)

type dns interface {
	lookup(host string, port string) (ip net.IP, expriedAt time.Time)
}

type dnsOverHTTPS struct {
	client *http.Client
}

func (d *dnsOverHTTPS) lookup(host string, _ string) (ip net.IP, expriedAt time.Time) {
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

func (d *dnsOverUDP) lookup(host string, _ string) (ip net.IP, expriedAt time.Time) {
	answers, err := net.LookupIP(host)
	if err != nil {
		return nil, time.Now()
	}

	return answers[0], time.Now().Add(defaultTTL)
}

type smartDNS struct {
	dnsOverUDP   *dnsOverUDP
	dnsOverHTTPS *dnsOverHTTPS
}

func (d *smartDNS) lookup(host string, port string) (ip net.IP, expriedAt time.Time) {
	ip, t := d.dnsOverUDP.lookup(host, port)

	addr := host + ":" + port

	if privateIPRange.contains(ip) {
		if isUnPollutedPrivateDNSAnswer(addr) {
			return ip, t
		}
		return d.dnsOverHTTPS.lookup(host, "")
	}

	if d.isBlockedByGFW(host) {
		return d.dnsOverHTTPS.lookup(host, "")
	}

	return ip, t
}

func (d *smartDNS) isBlockedByGFW(domain string) bool {
	id := make([]byte, 5)
	_, err := io.ReadFull(rand.Reader, id)
	if err != nil {
		panic(err)
	}
	nonexistentDomain := hex.EncodeToString(id) + "." + domain
	ip, _ := d.dnsOverUDP.lookup(nonexistentDomain, "")
	return ip != nil
}

func isUnPollutedPrivateDNSAnswer(address string) bool {
	c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err != nil {
		return false
	}

	c.Close()
	return true
}
