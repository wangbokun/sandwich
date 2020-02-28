package main

import (
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
