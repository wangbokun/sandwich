package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

type options struct {
	typo       string
	timeout    time.Duration
	serverHost string
	listenAddr string
}

func main() {
	var o options

	var root *cobra.Command
	var flags *flag.FlagSet

	root = &cobra.Command{
		SilenceUsage: true,
		Use:          "littleshadow",
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.typo == "local" {
				return startLocalProxy(o)
			}
			return startServer(o)
		},
	}

	flags = root.Flags()
	flags.StringVarP(&o.typo, "type", "y", "local", "start local proxy or server")
	flags.DurationVarP(&o.timeout, "timeout", "t", 10*time.Second, "timeout for waiting to connect to the server")
	flags.StringVarP(&o.serverHost, "server", "s", "server.com", "the server host to connect to")
	flags.StringVarP(&o.listenAddr, "addr", "a", "127.0.0.1:1186", "listen on given address")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func startLocalProxy(o options) error {
	var listener net.Listener
	var err error

	if listener, err = net.Listen("tcp", o.listenAddr); err != nil {
		return fmt.Errorf("can't start local proxy: %s", err)
	}

	local := newLocalProxy(listener, o)

	local.listen()
	return nil
}

func startServer(o options) error {
	var listener net.Listener
	var err error

	if listener, err = net.Listen("tcp", o.listenAddr); err != nil {
		return fmt.Errorf("can't start server: %s", err)
	}

	server := newServer(o.timeout)
	if err := http.ServeTLS(listener, server, "", ""); err != nil {
		return fmt.Errorf("can't start server: %s", err)
	}

	return nil
}
