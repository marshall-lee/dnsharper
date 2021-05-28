package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode"
)

func readAliases(readerCloser io.ReadCloser, domain string) (map[string]string, error) {
	defer readerCloser.Close()
	input := bufio.NewReader(readerCloser)
	result := make(map[string]string)
	var eof bool
	for !eof {
		line, err := input.ReadString('\n')
		if err != nil {
			if eof = (err == io.EOF); !eof {
				return nil, err
			}
		}
		if parts := strings.SplitN(line, "#", 2); len(parts) > 0 {
			line = parts[0]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var builder strings.Builder
		builder.Grow(64)
		var parts []string
		for _, r := range line {
			if !unicode.IsSpace(r) {
				builder.WriteRune(r)
			} else {
				if str := builder.String(); str != "" {
					parts = append(parts, str)
					builder.Reset()
					builder.Grow(64)
				}
			}
		}
		parts = append(parts, builder.String())
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad line %q %#v", line, parts)
		}

		hostName := parts[1]
		if _, err := net.ParseMAC(hostName); err == nil {
			return nil, fmt.Errorf("%q must not parse as MAC address", hostName)
		}

		hwAddr, err := net.ParseMAC(parts[0])
		if err != nil {
			return nil, err
		}
		result[fmt.Sprintf("%s.%s.", hostName, domain)] = fmt.Sprintf("%s.%s.", strings.ReplaceAll(hwAddr.String(), ":", "-"), domain)
	}
	return result, nil
}
