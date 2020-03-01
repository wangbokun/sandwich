// +build darwin

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func setSysProxy(networkservice string, listenAddr string) error {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}
	if strings.Trim(host, " ") == "" {
		host = "127.0.0.1"
	}

	if !isSecureWebProxyON(networkservice, host, port) {
		cmd := exec.Command("networksetup", "-setsecurewebproxy", networkservice, host, port)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	if !isWebProxyON(networkservice, host, port) {
		cmd := exec.Command("networksetup", "-setwebproxy", networkservice, host, port)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	return nil
}

func unsetSysProxy(networkservice string) error {
	cmd := exec.Command("networksetup", "-setsecurewebproxystate", networkservice, "off")
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("networksetup", "-setwebproxystate", networkservice, "off")
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func isWebProxyON(networkservice string, host, port string) bool {
	return isProxyON(networkservice, "-getwebproxy", host, port)
}

func isSecureWebProxyON(networkservice string, host, port string) bool {
	return isProxyON(networkservice, "-getsecurewebproxy", host, port)
}

func isProxyON(networkservice string, flag string, host string, port string) bool {
	cmd := exec.Command("networksetup", flag, networkservice)
	buf := bytes.NewBuffer(nil)
	cmd.Stdout = bufio.NewWriter(buf)
	if err := cmd.Run(); err != nil {
		return false
	}

	output := buf.String()
	return strings.Contains(output, "Enabled: Yes") &&
		strings.Contains(output, fmt.Sprintf("Server: %s", host)) &&
		strings.Contains(output, fmt.Sprintf("Port: %s", port))
}
