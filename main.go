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
	"github.com/jasonlvhit/gocron"
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
	useDoH                   bool
	action                   string
	networkservice           string
}

var (
	quit     = make(chan struct{})
	cronDone chan bool
	flags    options
)

func main() {
	log.SetFlags(0)

	flag.BoolVar(&flags.remoteProxyMode, "remote-proxy-mode", false, "remote proxy mode")
	flag.StringVar(&flags.remoteProxyAddr, "remote-proxy-addr", "https://yourdomain.com:443", "the remote proxy address to connect to")
	flag.StringVar(&flags.listenAddr, "listen-addr", "127.0.0.1:2286", "listens on given address")
	flag.StringVar(&flags.certFile, "cert-file", "", "cert file path")
	flag.StringVar(&flags.privateKeyFile, "private-key-file", "", "private key file path")
	flag.StringVar(&flags.secretKey, "secret-key", "daf07cfb73d0af0777e5", "secrect header key to cross firewall")
	flag.StringVar(&flags.reversedWebsite, "reversed-website", "http://mirrors.codec-cluster.org/", "reversed website to fool firewall")
	flag.BoolVar(&flags.disableAutoCrossFirewall, "disable-auto-cross-firewall", false, "disable auto cross firewall")
	flag.BoolVar(&flags.useDoH, "use-doh", false, "use DNS Over HTTPS method to lookup a domain.")
	flag.StringVar(&flags.action, "action", "", "do actions to the process [actions: quit]")
	flag.StringVar(&flags.networkservice, "ns", "Wi-Fi", "the networkservice to auto set proxy")
	flag.Parse()

	daemon.AddCommand(daemon.StringFlag(&flags.action, "quit"), syscall.SIGQUIT, termHandler)
	daemon.SetSigHandler(termHandler, syscall.SIGQUIT, syscall.SIGTERM)

	workDir := filepath.Join(os.Getenv("HOME"), ".sandwich")
	os.MkdirAll(workDir, 0755)

	cntxt := &daemon.Context{
		PidFileName: filepath.Join(workDir, "sandwich.pid"),
		PidFilePerm: 0644,
		LogFileName: filepath.Join(workDir, "sandwich.log"),
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
	if o.useDoH {
		dns = &dnsOverHTTPS{client: client}
	} else {
		dns = &dnsOverUDP{}
	}

	local := &localProxy{
		remoteProxyAddr:   u,
		secretKey:         o.secretKey,
		chinaIP:           newChinaIPRangeDB(),
		dnsCache:          lru.New(8192),
		autoCrossFirewall: !o.disableAutoCrossFirewall,
		client:            client,
		dns:               dns,
	}

	ctx, cancel := context.WithCancel(context.Background())

	go local.pullLatestIPRange(ctx)

	setSysProxy(o.networkservice, o.listenAddr)

	gocron.Every(4).Hours().DoSafely(local.pullLatestIPRange, ctx)
	gocron.Every(3).Seconds().DoSafely(sysProxy, o.networkservice, o.listenAddr)
	cronDone = gocron.Start()

	defer cancel()

	errChan <- http.Serve(listener, local)
}

func startRemoteProxy(o options, listener net.Listener, errChan chan<- error) {
	cronDone = make(chan bool)
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
	close(cronDone)
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
