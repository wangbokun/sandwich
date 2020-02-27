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
	answer := local.lookup("www.baidu.com")
	require.NotNil(t, answer)
	t.Log(answer.String())
}
