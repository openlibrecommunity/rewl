package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

func refine(country, iface, ports, routerMAC string, rate, retries int) error {
	country = strings.ToLower(country)
	input := fmt.Sprintf("data/pub/%s.alive.yaml", country)
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}

	var previous scanOutput
	if err := yaml.Unmarshal(data, &previous); err != nil {
		return err
	}

	subnets := make(map[string]struct{})
	for _, result := range previous.Results {
		ip := net.ParseIP(result.IP).To4()
		if ip == nil {
			continue
		}
		subnets[fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])] = struct{}{}
	}

	list := make([]string, 0, len(subnets))
	for subnet := range subnets {
		list = append(list, subnet)
	}
	sort.Strings(list)

	zone := fmt.Sprintf("data/raw/%s.refine.zone", country)
	if err := os.WriteFile(zone, []byte(strings.Join(list, "\n")+"\n"), 0644); err != nil {
		return err
	}

	fmt.Printf("loaded %d endpoints from %s\n", len(previous.Results), input)
	fmt.Printf("scanning %d discovered /24 subnets (%d addresses)\n", len(list), len(list)*256)

	output := fmt.Sprintf("data/raw/%s.refined.yaml", country)
	return scanZone(country, zone, output, iface, ports, routerMAC, rate, false, retries)
}
