package main

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/mailgun/holster/v3/collections"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	dns          *dns.Server
	aliases      map[string][]string
	cache        *collections.LRUCache
	domainRegexp *regexp.Regexp
}

func NewServer(listenAddr string, domain string, aliases map[string][]string, cache *collections.LRUCache) (Server, error) {
	var (
		srv Server
		err error
	)
	srv.dns = &dns.Server{Addr: listenAddr, Net: "udp", Handler: &srv}
	srv.aliases = aliases
	srv.cache = cache
	srv.domainRegexp, err = regexp.Compile(fmt.Sprintf(`(?i)^([0-9a-f]{2}(-[0-9a-f]{2}){1,19})\.%s\.$`, domain))
	if err != nil {
		return Server{}, err
	}
	return srv, nil
}

func (srv Server) ListenAndServe() error {
	return srv.dns.ListenAndServe()
}

func (srv Server) Shutdown(ctx context.Context) error {
	return srv.dns.ShutdownContext(ctx)
}

func (srv Server) ServeDNS(rw dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		log.Warn("Got empty question")
		formatError(rw, req)
		return
	}

	question := req.Question[0]
	domain := question.Name
	log := log.WithField("domain", strings.TrimSuffix(domain, "."))

	qclass := question.Qclass
	if qclass != dns.ClassINET {
		log.Debugf("Got unsupported qclass %s", dns.Class(qclass))
		formatError(rw, req)
		return
	}

	qtype := question.Qtype
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		log.Debugf("Got unsupported qtype %s", dns.Type(qtype))
		formatError(rw, req)
		return
	}

	var candidates []string
	if names, ok := srv.aliases[domain]; ok {
		candidates = names
	} else {
		candidates = []string{domain}
	}

	for _, candidate := range candidates {
		matches := srv.domainRegexp.FindStringSubmatch(candidate)
		if len(matches) == 0 {
			log.WithField("candidate", candidate).Debug("Domain does not match the pattern")
			continue
		}

		mac := matches[1]
		hwAddr, err := net.ParseMAC(mac)
		if err != nil {
			log.WithError(err).WithField("mac", mac).Debug("Failed to parse MAC")
			continue
		}

		var (
			ip     net.IP
			record dns.RR
		)
		hdr := dns.RR_Header{
			Name:   question.Name,
			Rrtype: qtype,
			Class:  qclass,
			Ttl:    0,
		}
		switch qtype {
		case dns.TypeA:
			key := "ipv4-" + hwAddr.String()
			value, ok := srv.cache.Get(key)
			if !ok {
				log.WithField("key", key).Debug("Cache entry NOT found")
				continue
			}
			log.WithField("key", key).Debug("Cache entry found")
			ip = value.(net.IP)
			record = &dns.A{
				Hdr: hdr,
				A:   ip.To4(),
			}
		case dns.TypeAAAA:
			key := "ipv6-" + hwAddr.String()
			value, ok := srv.cache.Get(key)
			if !ok {
				log.WithField("key", key).Debug("Cache entry NOT found")
				continue
			}
			log.WithField("key", key).Debug("Cache entry found")
			ip = value.(net.IP)
			record = &dns.AAAA{
				Hdr:  hdr,
				AAAA: ip.To16(),
			}
		}

		log.WithField("ip", ip).Debug("Sending reply")

		var reply dns.Msg
		reply.SetReply(req)
		reply.Answer = []dns.RR{record}
		if err := rw.WriteMsg(&reply); err != nil {
			log.WithError(err).Error("Failed to write a dns reply")
		}
		return
	}
	nameError(rw, req)
}

func formatError(rw dns.ResponseWriter, req *dns.Msg) {
	var reply dns.Msg
	reply.SetRcodeFormatError(req)
	if err := rw.WriteMsg(&reply); err != nil {
		log.Println("Failed to write a format error reply", err)
	}
}

func nameError(rw dns.ResponseWriter, req *dns.Msg) {
	var reply dns.Msg
	reply.SetRcode(req, dns.RcodeNameError)
	if err := rw.WriteMsg(&reply); err != nil {
		log.Println("Failed to write an name error reply", err)
	}
}
