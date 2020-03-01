// +build darwin

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetSysProxy(t *testing.T) {
	err := setSysProxy("Wi-Fi", ":9090")
	require.Nil(t, err)
}

func TestUnsetSysProxy(t *testing.T) {
	setSysProxy("Wi-Fi", ":9191")
	err := unsetSysProxy("Wi-Fi")
	require.Nil(t, err)
}

func TestIsWebProxyON(t *testing.T) {
	setSysProxy("Wi-Fi", ":9090")
	require.True(t, isWebProxyON("Wi-Fi", "127.0.0.1", "9090"))

	unsetSysProxy("Wi-Fi")
	require.False(t, isWebProxyON("Wi-Fi", "127.0.0.1", "9090"))
}

func TestIsSecureWebProxyON(t *testing.T) {
	setSysProxy("Wi-Fi", ":9090")
	require.True(t, isSecureWebProxyON("Wi-Fi", "127.0.0.1", "9090"))

	unsetSysProxy("Wi-Fi")
	require.False(t, isSecureWebProxyON("Wi-Fi", "127.0.0.1", "9090"))
}
