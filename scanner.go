package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
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
	ip6net       *net.IPNet
	ip4net       *net.IPNet
	arpTargets   ip4targets
	ndpTargets   *ip6targets
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
	var ip4net, ip6net *net.IPNet
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ip4 := ipnet.IP.To4(); ip4 != nil {
			ip4net = &net.IPNet{
				IP:   ip4,
				Mask: ipnet.Mask[len(ipnet.Mask)-4:],
			}
		} else if ip6 := ipnet.IP.To16(); ip6 != nil {
			ip6net = ipnet
		}
	}
	if ip4net == nil && ip6net == nil {
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
	interval := 10 * time.Millisecond
	timeout := 1000 * time.Millisecond

	var (
		arpTargets ip4targets
		ndpTargets *ip6targets
	)

	if ip4net != nil {
		arpTargets = makeip4targets(ip4net, timeout)
	}
	if ip6net != nil {
		ndpTargets = makeip6targets(timeout)
	}

	return Scanner{
		iface:        iface,
		handle:       handle,
		ip4net:       ip4net,
		ip6net:       ip6net,
		arpTargets:   arpTargets,
		ndpTargets:   ndpTargets,
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
	wg.Add(1)
	errors := make(chan error, 4)
	defer close(errors)
	go func() {
		defer wg.Done()
		if err := scanner.reader(ctx); err != nil && err != context.DeadlineExceeded {
			cancel()
			errors <- err
		}
	}()
	if scanner.ip4net != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := scanner.writerARP(ctx); err != nil && err != context.DeadlineExceeded {
				cancel()
				errors <- err
			}
		}()
	}
	if scanner.ip6net != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := scanner.writerNDP(ctx); err != nil && err != context.DeadlineExceeded {
				cancel()
				errors <- err
			}
		}()
		go func() {
			defer wg.Done()
			if err := scanner.writerICMPPing6Multicast(ctx); err != nil && err != context.DeadlineExceeded {
				cancel()
				errors <- err
			}
		}()
	}
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
	var ipv6 layers.IPv6
	var icmpv6 layers.ICMPv6
	var icmpv6echo layers.ICMPv6Echo
	var icmpv6ns layers.ICMPv6NeighborSolicitation
	var icmpv6na layers.ICMPv6NeighborAdvertisement

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp, &ipv6, &icmpv6, &icmpv6echo, &icmpv6na, &icmpv6ns)

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
		var (
			targetIP     net.IP
			targetHwAddr net.HardwareAddr
		)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeARP:
				if arp.Operation != layers.ARPReply {
					continue
				}
				if bytes.Equal(scanner.iface.HardwareAddr, arp.SourceHwAddress) {
					continue
				}

				targetIP = net.IP(arp.SourceProtAddress).To4()
				targetHwAddr = net.HardwareAddr(arp.SourceHwAddress)
				scanner.arpTargets.reset(ip4(targetIP))

			case layers.LayerTypeICMPv6:
				switch icmpv6.TypeCode.Type() {
				case layers.ICMPv6TypeEchoReply:
					if ipv6.SrcIP.Equal(scanner.ip6net.IP) {
						continue
					}
					scanner.ndpTargets.add(ip6(ipv6.SrcIP.To16()))
				case layers.ICMPv6TypeNeighborAdvertisement:
					targetIP = icmpv6na.TargetAddress
					for _, opt := range icmpv6na.Options {
						if opt.Type == layers.ICMPv6OptTargetAddress {
							targetHwAddr = net.HardwareAddr(opt.Data)
						}
					}
					scanner.ndpTargets.reset(ip6(targetIP))
				}
			}
		}
		if targetIP == nil || targetHwAddr == nil {
			continue
		}

		targetHwAddrStr := targetHwAddr.String()
		var targetHwAddrKey string
		if targetIP4 := targetIP.To4(); targetIP4 != nil {
			targetHwAddrKey = "ipv4-" + targetHwAddrStr
		} else if targetIP16 := targetIP.To16(); targetIP16 != nil {
			targetHwAddrKey = "ipv6-" + targetHwAddrStr
		} else {
			panic(fmt.Sprintf("invalid ip address %v", targetIP))
		}
		if !scanner.cache.AddWithTTL(targetHwAddrKey, targetIP, scanner.cacheTTL) {
			domain := fmt.Sprintf(scanner.domainFormat, strings.ReplaceAll(targetHwAddrStr, ":", "-"))
			log := log.WithFields(log.Fields{
				"ip":     targetIP,
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

func (scanner Scanner) writerNDP(ctx context.Context) error {
	eth := layers.Ethernet{
		SrcMAC:       scanner.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
		SrcIP:      scanner.ip6net.IP,
		DstIP:      net.ParseIP("ff02:0000:0000:0000:0000:0001:ff00:0000"),
	}
	icmpv6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
	}
	icmpv6ns := layers.ICMPv6NeighborSolicitation{
		Options: layers.ICMPv6Options{
			layers.ICMPv6Option{Type: layers.ICMPv6OptSourceAddress, Data: []byte(scanner.iface.HardwareAddr)},
		},
	}
	if err := icmpv6.SetNetworkLayerForChecksum(&ipv6); err != nil {
		return err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	return scanner.ndpTargets.loop(ctx, scanner.interval, func(ip6 ip6) error {
		targetIP := net.IP(ip6[:])
		copy(ipv6.DstIP[13:], targetIP[len(targetIP)-3:])
		copy(eth.DstMAC[2:], ipv6.DstIP[len(ipv6.DstIP)-4:])
		icmpv6ns.TargetAddress = targetIP
		if err := gopacket.SerializeLayers(buf, opts, &eth, &ipv6, &icmpv6, &icmpv6ns); err != nil {
			return err
		}
		if err := scanner.handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
		return nil
	})
}

func (scanner Scanner) writerICMPPing6Multicast(ctx context.Context) error {
	eth := layers.Ethernet{
		SrcMAC:       scanner.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
		SrcIP:      scanner.ip6net.IP,
		DstIP:      net.ParseIP("ff02::1"),
	}
	icmpv6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	icmpv6echo := layers.ICMPv6Echo{
		Identifier: uint16(rand.Int31()),
	}
	if err := icmpv6.SetNetworkLayerForChecksum(&ipv6); err != nil {
		return err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	seqNumber := uint16(0)
	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}

		icmpv6echo.SeqNumber = seqNumber
		seqNumber++
		if err := gopacket.SerializeLayers(buf, opts, &eth, &ipv6, &icmpv6, &icmpv6echo); err != nil {
			return err
		}
		if err := scanner.handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
}
