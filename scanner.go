package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mailgun/holster/v3/collections"
	log "github.com/sirupsen/logrus"
)

const maxTimeout = 10 * time.Second

type Scanner struct {
	iface        *net.Interface
	handle       *pcap.Handle
	ip4net       *net.IPNet
	arpTargets   ip4targets
	cacheTTL     time.Duration
	interval     time.Duration
	timeout      time.Duration
	domainFormat string
	revAliases   map[string][]string
	cache        *collections.LRUCache
}

var ErrNoNetworksFound = errors.New("no networks found")

func NewScanner(ifaceName string, cacheTTL time.Duration, domain string, aliases map[string]string, cache *collections.LRUCache) (Scanner, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return Scanner{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return Scanner{}, err
	}
	var ip4net *net.IPNet
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		ip4net = &net.IPNet{
			IP:   ip4,
			Mask: ipnet.Mask[len(ipnet.Mask)-4:],
		}
	}
	if ip4net == nil {
		return Scanner{}, ErrNoNetworksFound
	}
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return Scanner{}, err
	}
	if linkType := handle.LinkType(); linkType != layers.LinkTypeEthernet {
		return Scanner{}, fmt.Errorf("network interface %q has unsupported link type %q", iface.Name, linkType)
	}

	revAliases := make(map[string][]string, len(aliases))
	for host, hwAddr := range aliases {
		revAliases[hwAddr] = append(revAliases[hwAddr], host)
	}

	// TODO: move to parameters
	interval := 4 * time.Millisecond
	timeout := 500 * time.Millisecond

	var (
		arpTargets ip4targets
	)

	if ip4net != nil {
		arpTargets = makeip4targets(ip4net, timeout)
	}

	return Scanner{
		iface:        iface,
		handle:       handle,
		ip4net:       ip4net,
		arpTargets:   arpTargets,
		cacheTTL:     cacheTTL,
		interval:     interval,
		timeout:      timeout,
		domainFormat: "%s." + domain + ".",
		revAliases:   revAliases,
		cache:        cache,
	}, nil
}

func (scanner Scanner) Scan(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	errors := make(chan error, 2)
	defer close(errors)
	go func() {
		defer wg.Done()
		if err := scanner.reader(ctx); err != nil && err != context.DeadlineExceeded {
			cancel()
			errors <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := scanner.writerARP(ctx); err != nil && err != context.DeadlineExceeded {
			cancel()
			errors <- err
		}
	}()
	wg.Wait()

	select {
	case err := <-errors:
		return err
	default:
		return nil
	}
}

func (scanner Scanner) reader(ctx context.Context) error {
	var eth layers.Ethernet
	var arp layers.ARP

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)

	var decoded []gopacket.LayerType
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		data, _, err := scanner.handle.ReadPacketData()
		if err == io.EOF {
			return nil
		} else if err != nil {
			log.Error("Error reading packet:", err)
			continue
		}
		if err = parser.DecodeLayers(data, &decoded); err != nil {
			continue
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeARP:
				if arp.Operation != layers.ARPReply {
					continue
				}
				if bytes.Equal(scanner.iface.HardwareAddr, arp.SourceHwAddress) {
					continue
				}
				ip := net.IP(arp.SourceProtAddress).To4()

				scanner.arpTargets.reset(ip4(ip))

				hwAddr := net.HardwareAddr(arp.SourceHwAddress)
				hwAddrKey := hwAddr.String()
				if !scanner.cache.AddWithTTL(hwAddrKey, ip, scanner.cacheTTL) {
					domain := fmt.Sprintf(scanner.domainFormat, strings.ReplaceAll(hwAddrKey, ":", "-"))
					log := log.WithFields(log.Fields{
						"ip":     ip,
						"domain": strings.TrimSuffix(domain, "."),
					})
					if aliases, ok := scanner.revAliases[domain]; ok {
						for i, alias := range aliases {
							key := "domalias"
							if i > 0 {
								key = key + strconv.Itoa(i)
							}
							log = log.WithField(key, strings.TrimSuffix(alias, "."))
						}
					}
					log.Infof("Added to cache")
				}
			}
		}
	}
}

func (scanner Scanner) writerARP(ctx context.Context) error {
	eth := layers.Ethernet{
		SrcMAC:       scanner.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(scanner.iface.HardwareAddr),
		SourceProtAddress: []byte(scanner.ip4net.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	return scanner.arpTargets.loop(ctx, scanner.interval, func(ip4 ip4) error {
		arp.DstProtAddress = ip4[:]
		if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
			return err
		}
		if err := scanner.handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
		return nil
	})
}
