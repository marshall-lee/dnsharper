package main

import (
	"context"
	"fmt"
	"net"
	"regexp"

	"github.com/mailgun/holster/v3/collections"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	dns          *dns.Server
	cache        *collections.LRUCache
	domainRegexp *regexp.Regexp
}

func NewServer(listenAddr string, domain string, cache *collections.LRUCache) (Server, error) {
	var (
		srv Server
		err error
	)
	srv.dns = &dns.Server{Addr: listenAddr, Net: "udp", Handler: &srv}
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
	if qclass := question.Qclass; qclass != dns.ClassINET {
		log.Debugf("Got unsupported qclass %s", dns.Class(qclass))
		formatError(rw, req)
		return
	}
	if qtype := question.Qtype; qtype != dns.TypeA {
		log.Debugf("Got unsupported qtype %s", dns.Type(qtype))
		formatError(rw, req)
		return
	}

	domain := question.Name
	log := log.WithField("domain", domain)
	matches := srv.domainRegexp.FindStringSubmatch(domain)
	if len(matches) == 0 {
		log.Debug("Domain does not match the pattern")
		nameError(rw, req)
		return
	}

	hwAddr, err := net.ParseMAC(matches[1])
	if err != nil {
		log.WithError(err).Debug("Failed to parse MAC")
		nameError(rw, req)
		return
	}

	value, ok := srv.cache.Get(hwAddr.String())
	if !ok {
		log.Debug("Cache entry not found")
		nameError(rw, req)
		return
	}
	ip := value.(net.IP)

	var reply dns.Msg
	reply.SetReply(req)
	reply.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: ip.To4(),
	}}
	if err := rw.WriteMsg(&reply); err != nil {
		log.WithError(err).Error("Failed to write a dns reply")
	}
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
