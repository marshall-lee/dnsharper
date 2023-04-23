package main

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/mailgun/holster/v3/collections"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type CLI struct {
	Iface       string        `kong:"arg,placeholder='eth0',help='Network interface.'"`
	Debug       bool          `kong:"short='d',help='Enable debug logging.'"`
	TTL         time.Duration `kong:"short='t',help='Cache TTL.',default=30s"`
	Listen      string        `kong:"short='l',default='127.0.0.1:5333',help='DNS server listen on.'"`
	Domain      string        `kong:"short='n',default='.dnsharper.local',help='Domain.'"`
	AliasesFile *os.File      `kong:"name='aliases',short='a',help='MAC to hostname mapping file.'"`
}

func main() {
	var cli CLI
	kong.Parse(&cli)

	if cli.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if _, ok := dns.IsDomainName(cli.Domain); !ok {
		log.Fatalf("%q doesn't look like a valid domain", cli.Domain)
		return
	}
	cli.Domain = strings.TrimPrefix(cli.Domain, ".")

	cache := collections.NewLRUCache(256 * 256)
	cache.OnEvicted = func(key collections.Key, value interface{}) {
		domain := strings.ReplaceAll(key.(string), ":", "-") + "." + cli.Domain
		domain, _ = strings.CutPrefix(domain, "ipv4-")
		domain, _ = strings.CutPrefix(domain, "ipv6-")
		log.WithFields(log.Fields{
			"domain": domain,
			"ip":     value.(net.IP),
		}).Debug("Evicted from cache")
	}

	var err error

	var aliases map[string]string
	if cli.AliasesFile != nil {
		if aliases, err = readAliases(cli.AliasesFile, cli.Domain); err != nil {
			log.WithError(err).Fatal("Failed to read aliases file")
			return
		}
	}

	scanner, err := NewScanner(cli.Iface, cli.TTL, cli.Domain, aliases, cache)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize scanner")
		return
	}
	server, err := NewServer(cli.Listen, cli.Domain, aliases, cache)
	if err != nil {
		log.WithError(err).Fatal("Failed to DNS server")
		return
	}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.WithError(err).Error("Failed to listen")
		}
	}()
	if err := scanner.Scan(context.Background()); err != nil {
		log.WithError(err).Error("Failed to scan")
	}
}
