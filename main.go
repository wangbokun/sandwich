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
}

var (
	quit     = make(chan struct{})
	done     = make(chan struct{})
	cronDone chan bool
)

func main() {
	log.SetFlags(0)
	var o options

	flag.BoolVar(&o.remoteProxyMode, "remote-proxy-mode", false, "remote proxy mode")
	flag.StringVar(&o.remoteProxyAddr, "remote-proxy-addr", "https://yourdomain.com:443", "the remote proxy address to connect to")
	flag.StringVar(&o.listenAddr, "listen-addr", "127.0.0.1:9876", "listens on given address")
	flag.StringVar(&o.certFile, "cert-file", "", "cert file path")
	flag.StringVar(&o.privateKeyFile, "private-key-file", "", "private key file path")
	flag.StringVar(&o.secretKey, "secret-key", "daf07cfb73d0af0777e5", "secrect header key to cross firewall")
	flag.StringVar(&o.reversedWebsite, "reversed-website", "http://mirrors.codec-cluster.org/", "reversed website to fool firewall")
	flag.BoolVar(&o.disableAutoCrossFirewall, "disable-auto-cross-firewall", false, "disable auto cross firewall")
	flag.BoolVar(&o.useDoH, "use-doh", false, "use DNS Over HTTPS method to lookup a domain.")
	flag.StringVar(&o.action, "action", "", "do actions to the process [actions: quit]")
	flag.Parse()

	daemon.AddCommand(daemon.StringFlag(&o.action, "quit"), syscall.SIGQUIT, termHandler)

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
	if listener, err = net.Listen("tcp", o.listenAddr); err != nil {
		log.Fatalf("error: %s", err.Error())
	}

	if o.remoteProxyMode {
		go startRemoteProxy(o, listener)
	} else {
		go startLocalProxy(o, listener)
	}

	if err = daemon.ServeSignals(); err != nil {
		log.Fatalf("error: %s", strings.ToLower(err.Error()))
	}
}

func startLocalProxy(o options, listener net.Listener) {
	u, err := url.Parse(o.remoteProxyAddr)
	if err != nil {
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

	gocron.Every(4).Hours().DoSafely(local.pullLatestIPRange, ctx)
	gocron.Every(3).Seconds().DoSafely(sysProxy)
	cronDone = gocron.Start()

	defer cancel()

	if err := http.Serve(listener, local); err != nil {
		log.Fatalf("error: %s", err.Error())
	}
}

func startRemoteProxy(o options, listener net.Listener) {
	gocron.Every(1).Seconds().DoSafely(func() {
		select {
		case <-quit:
			close(cronDone)
			close(done)
		default:
		}
	})
	cronDone = gocron.Start()

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
	if err != nil {
		log.Fatalf("error: %s", err.Error())
	}
}

func termHandler(sig os.Signal) (err error) {
	close(quit)
	if sig == syscall.SIGQUIT {
		<-done
	}
	return daemon.ErrStop
}

func sysProxy() (err error) {
	select {
	case <-quit:
		close(cronDone)
		err = unsetSysProxy()
		close(done)
	default:
		err = setSysProxy()
	}
	return err
}

func setSysProxy() error {
	return nil
}

func unsetSysProxy() error {
	return nil
}
