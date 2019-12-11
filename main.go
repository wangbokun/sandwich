package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

type options struct {
	typo          string
	timeout       time.Duration
	serverWebsite string
	listenAddr    string
	certFile      string
	keyFile       string
}

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate)
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
	flags.DurationVarP(&o.timeout, "timeout", "t", 10*time.Second, "timeout for waiting to connect to the server website")
	flags.StringVarP(&o.serverWebsite, "server-website", "s", "https://server.com:443", "the server website to connect to")
	flags.StringVarP(&o.listenAddr, "addr", "a", "127.0.0.1:1186", "listen on given address")
	flags.StringVarP(&o.certFile, "cert", "c", "", "cert file path")
	flags.StringVarP(&o.keyFile, "key", "k", "", "key file path")

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

	if o.certFile != "" && o.keyFile != "" {
		err = http.ServeTLS(listener, server, o.certFile, o.keyFile)
	} else {
		err = http.Serve(listener, server)
	}
	if err != nil {
		return fmt.Errorf("can't start server: %s", err)
	}
	return nil
}
