package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/golang/groupcache/lru"
	"github.com/robfig/cron/v3"
	"github.com/sevlyar/go-daemon"
)

type options struct {
	remoteProxyMode          bool
	remoteProxyAddr          string
	listenAddr               string
	certFile                 string
	privateKeyFile           string
	secretKey                string
	reversedWebsite          string
	disableAutoCrossFirewall bool
	alwaysUseDoH             bool
	action                   string
	networkservice           string
}

var (
	quit  = make(chan struct{})
	flags options
)

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetOutput(os.Stdout)

	workDir := filepath.Join(os.Getenv("HOME"), ".sandwich")
	logFile := filepath.Join(workDir, "sandwich.log")

	flag.BoolVar(&flags.remoteProxyMode, "remote-proxy-mode", false, "remote proxy mode")
	flag.StringVar(&flags.remoteProxyAddr, "remote-proxy-addr", "https://yourdomain.com:443", "the remote proxy address to connect to")
	flag.StringVar(&flags.listenAddr, "listen-addr", "127.0.0.1:2286", "listens on given address")
	flag.StringVar(&flags.certFile, "cert-file", "", "cert file path")
	flag.StringVar(&flags.privateKeyFile, "private-key-file", "", "private key file path")
	flag.StringVar(&flags.secretKey, "secret-key", "dbf07cfb73d0bf0777b5", "secrect header key to cross firewall")
	flag.StringVar(&flags.reversedWebsite, "reversed-website", "http://mirrors.codec-cluster.org/", "reversed website to fool firewall")
	flag.BoolVar(&flags.disableAutoCrossFirewall, "disable-auto-cross-firewall", false, "disable auto cross firewall")
	flag.BoolVar(&flags.alwaysUseDoH, "always-use-doh", false, "always use DNS Over HTTPS method to lookup a domain")
	flag.StringVar(&flags.action, "action", "", "do actions to the process [actions: quit]")
	flag.StringVar(&flags.networkservice, "ns", "Wi-Fi", "the networkservice to auto set proxy")
	flag.Parse()

	daemon.AddCommand(daemon.StringFlag(&flags.action, "quit"), syscall.SIGQUIT, termHandler)
	daemon.SetSigHandler(termHandler, syscall.SIGQUIT, syscall.SIGTERM)

	os.MkdirAll(workDir, 0755)

	cntxt := &daemon.Context{
		PidFileName: filepath.Join(workDir, "sandwich.pid"),
		PidFilePerm: 0644,
		LogFileName: logFile,
		LogFilePerm: 0640,
		Umask:       027,
		Args:        nil,
	}

	if len(daemon.ActiveFlags()) > 0 {
		d, err := cntxt.Search()
		if err != nil {
			log.Fatalf("error: unable send signal to the daemon: %s", err.Error())
		}
		daemon.SendCommands(d)
		return
	}

	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatalf("error: %s", strings.ToLower(err.Error()))
	}
	if d != nil {
		return
	}
	defer cntxt.Release()

	var listener net.Listener
	if listener, err = net.Listen("tcp", flags.listenAddr); err != nil {
		log.Fatalf("error: %s", err.Error())
	}

	var errCh = make(chan error, 2)
	if flags.remoteProxyMode {
		go startRemoteProxy(flags, listener, errCh)
	} else {
		go startLocalProxy(flags, listener, errCh)
	}

	select {
	case err := <-errCh:
		log.Fatalf("error: %s", err)
	default:
	}
	if err = daemon.ServeSignals(); err != nil {
		log.Fatalf("error: %s", strings.ToLower(err.Error()))
	}
}

func startLocalProxy(o options, listener net.Listener, errChan chan<- error) {
	var err error
	u, err := url.Parse(o.remoteProxyAddr)
	if err != nil {
		errChan <- err
		return
	}

	h := make(http.Header, 0)
	h.Set(headerSecret, o.secretKey)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(request *http.Request) (i *url.URL, e error) {
				request.Header.Set(headerSecret, o.secretKey)
				return u, nil
			},
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: false},
			ProxyConnectHeader: h,
		},
	}

	var dns dns
	if o.alwaysUseDoH {
		dns = &dnsOverHTTPS{client: client}
	} else {
		dns = &smartDNS{
			dnsOverUDP:   &dnsOverUDP{},
			dnsOverHTTPS: &dnsOverHTTPS{client: client},
		}
	}

	local := &localProxy{
		remoteProxyAddr:   u,
		secretKey:         o.secretKey,
		chinaIPRangeDB:    newChinaIPRangeDB(),
		dnsCache:          lru.New(8192),
		autoCrossFirewall: !o.disableAutoCrossFirewall,
		client:            client,
		dns:               dns,
	}

	ctx, cancel := context.WithCancel(context.Background())

	setSysProxy(o.networkservice, o.listenAddr)

	s := cron.New()
	s.AddFunc("@every 4h", func() {
		local.pullLatestIPRange(ctx)
	})
	s.AddFunc("@every 3s", func() {
		sysProxy(o.networkservice, o.listenAddr)
	})
	s.Start()

	defer cancel()

	errChan <- http.Serve(listener, local)
}

func startRemoteProxy(o options, listener net.Listener, errChan chan<- error) {
	var err error
	r := &remoteProxy{
		secretKey:       o.secretKey,
		reversedWebsite: o.reversedWebsite,
	}
	if o.certFile != "" && o.privateKeyFile != "" {
		err = http.ServeTLS(listener, r, o.certFile, o.privateKeyFile)
	} else {
		err = http.Serve(listener, r)
	}
	errChan <- err
}

func termHandler(_ os.Signal) (err error) {
	close(quit)
	unsetSysProxy(flags.networkservice)
	return daemon.ErrStop
}

func sysProxy(networkservice string, listenAddr string) (err error) {
	select {
	case <-quit:
	default:
		err = setSysProxy(networkservice, listenAddr)
	}
	return err
}
