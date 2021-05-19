package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mailgun/holster/v3/collections"
	log "github.com/sirupsen/logrus"
)

type Scanner struct {
	iface        *net.Interface
	handle       *pcap.Handle
	ipnet        *net.IPNet
	period       time.Duration
	domainFormat string
	cache        *collections.LRUCache
}

var ErrNoNetworksFound = errors.New("no networks found")

func NewScanner(ifaceName string, period time.Duration, domain string, cache *collections.LRUCache) (Scanner, error) {
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
	return Scanner{
		iface:        iface,
		handle:       handle,
		ipnet:        ip4net,
		period:       period,
		domainFormat: "%s." + domain,
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
		if err := scanner.writer(ctx); err != nil && err != context.DeadlineExceeded {
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

func (scanner Scanner) writer(ctx context.Context) error {
	ticker := time.NewTicker(scanner.period)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := scanner.doWrite(ctx); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (scanner Scanner) reader(ctx context.Context) error {
	src := gopacket.NewPacketSource(scanner.handle, layers.LayerTypeEthernet)
	for {
		select {
		case packet := <-src.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}
			if bytes.Equal(scanner.iface.HardwareAddr, arp.SourceHwAddress) {
				continue
			}
			ip := net.IP(arp.SourceProtAddress).To4()
			hwAddr := net.HardwareAddr(arp.SourceHwAddress)
			hwAddrKey := hwAddr.String()
			if !scanner.cache.AddWithTTL(hwAddrKey, ip, scanner.period+time.Second) {
				log.Infof("Added IP %v at %v", ip, fmt.Sprintf(scanner.domainFormat, strings.ReplaceAll(hwAddrKey, ":", "-")))
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (scanner Scanner) doWrite(ctx context.Context) error {
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
		SourceProtAddress: []byte(scanner.ipnet.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	var err error
	scanner.RangeIPs(func(ip net.IP) bool {
		if err = ctx.Err(); err != nil {
			return false
		}

		arp.DstProtAddress = []byte(ip)
		if err = gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
			return false
		}
		if err = scanner.handle.WritePacketData(buf.Bytes()); err != nil {
			return false
		}
		return true
	})
	return err
}

func (scanner Scanner) RangeIPs(fn func(net.IP) bool) {
	num := binary.BigEndian.Uint32([]byte(scanner.ipnet.IP))
	mask := binary.BigEndian.Uint32([]byte(scanner.ipnet.Mask))
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		if ip := net.IP(buf[:]); !fn(ip) {
			break
		}
	}
}
