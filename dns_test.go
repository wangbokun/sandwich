package main

import (
	"net/http"
	"testing"
)
import _ "unsafe"

func TestLookupStaticHost(t *testing.T) {
	t.Log(goLookupIPFiles("youtube.com"))
}

func TestSmartDNSLookUP(t *testing.T) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	dns := newSmartDNS(
		(&dnsOverHostsFile{}).lookup,
		(&dnsOverHTTPS{client: client}).lookup,
		(&dnsOverUDP{}).lookup,
	)
	t.Log(dns.lookup("youtube.com"))
	t.Log(dns.lookup("localhost"))
	t.Log(dns.lookup("www.google.com"))
}
