package main

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/golang/groupcache/lru"

	"github.com/stretchr/testify/require"
)

func TestLookup(t *testing.T) {
	local := &localProxy{
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: nil,
			},
		},
		dnsCache: lru.New(10),
	}
	host := "www.baidu.com"
	answer := local.lookup(host)
	require.NotNil(t, answer)
	t.Log(answer.String())

	cache, ok := local.dnsCache.Get(host)
	require.True(t, ok)
	require.EqualValues(t, answer, cache.(*answerCache).ip)
}

func TestPullLatestIPRange(t *testing.T) {
	local := &localProxy{
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: nil,
			},
		},
		chinaIP: newChinaIPRangeDB(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	t.Log(local.chinaIP.Len())
	err := local.pullLatestIPRange(ctx)
	require.Nil(t, err)
	require.NotZero(t, local.chinaIP.Len())
	t.Log(local.chinaIP.Len())

	cn := "2001:da8:1001:7::88"
	require.True(t, local.chinaIP.contains(net.ParseIP(cn)))

	usa := "172.217.11.68"
	require.False(t, local.chinaIP.contains(net.ParseIP(usa)))

	cn = "106.85.37.170"
	require.True(t, local.chinaIP.contains(net.ParseIP(cn)))
}
