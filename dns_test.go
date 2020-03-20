package main

import (
	"log"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSmartDNS_IsBlockedByGFW(t *testing.T) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	s := smartDNS{
		dnsOverUDP:   &dnsOverUDP{},
		dnsOverHTTPS: &dnsOverHTTPS{client: client},
	}
	require.True(t, s.isBlockedByGFW("youtube.com"))
	require.False(t, s.isBlockedByGFW("baidu.com"))
}

func TestSmartDNS_Lookup(t *testing.T) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	s := smartDNS{
		dnsOverUDP:   &dnsOverUDP{},
		dnsOverHTTPS: &dnsOverHTTPS{client: client},
	}
	ip, _ := s.lookup("youtube.com", "443")
	log.Println(ip.String())
	require.NotNil(t, ip)
	china := newChinaIPRangeDB()
	require.False(t, china.contains(ip))
}
