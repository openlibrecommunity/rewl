package app

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"rewl/pkg/model"
)

type analyzeReport struct {
	Country     string         `yaml:"country"`
	TotalEndpts int            `yaml:"total_endpoints"`
	UniqueIPs   int            `yaml:"unique_ips"`
	ByPort      map[string]int `yaml:"by_port"`
	ByProto     map[string]int `yaml:"by_proto"`
	TopSubnets  []subnetStat   `yaml:"top_subnets"`
}

type subnetStat struct {
	CIDR  string `yaml:"cidr"`
	Count int    `yaml:"count"`
}

func analyze(country string) error {
	inPath := fmt.Sprintf("data/pub/%s.alive.yaml", strings.ToLower(country))
	if _, err := os.Stat(inPath); err != nil {
		inPath = fmt.Sprintf("data/raw/%s.alive.yaml", strings.ToLower(country))
	}

	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}

	var scan model.Scan
	if err := yaml.Unmarshal(data, &scan); err != nil {
		return err
	}

	uniqIP := make(map[string]struct{})
	byPort := make(map[string]int)
	byProto := make(map[string]int)
	bySubnet := make(map[string]int)

	for _, r := range scan.Results {
		uniqIP[r.IP] = struct{}{}
		byPort[fmt.Sprintf("%d", r.Port)]++
		proto := r.Proto
		if proto == "" {
			proto = "tcp"
		}
		byProto[proto]++
		if s := subnet24(r.IP); s != "" {
			bySubnet[s]++
		}
	}

	// top /24 by endpoint count
	subs := make([]subnetStat, 0, len(bySubnet))
	for c, n := range bySubnet {
		subs = append(subs, subnetStat{CIDR: c, Count: n})
	}
	sort.Slice(subs, func(i, j int) bool {
		if subs[i].Count != subs[j].Count {
			return subs[i].Count > subs[j].Count
		}
		return subs[i].CIDR < subs[j].CIDR
	})
	if len(subs) > 20 {
		subs = subs[:20]
	}

	report := analyzeReport{
		Country:     scan.Country,
		TotalEndpts: len(scan.Results),
		UniqueIPs:   len(uniqIP),
		ByPort:      byPort,
		ByProto:     byProto,
		TopSubnets:  subs,
	}

	out, err := yaml.Marshal(&report)
	if err != nil {
		return err
	}

	outPath := fmt.Sprintf("data/pub/%s.report.yaml", strings.ToLower(country))
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return err
	}

	fmt.Printf("endpoints: %d\n", report.TotalEndpts)
	fmt.Printf("unique ips: %d\n", report.UniqueIPs)
	fmt.Printf("by port: %v\n", byPort)
	fmt.Printf("by proto: %v\n", byProto)
	fmt.Printf("top /24 subnets:\n")
	for _, s := range subs {
		fmt.Printf("  %s  %d\n", s.CIDR, s.Count)
	}
	fmt.Printf("saved to %s\n", outPath)
	return nil
}

// subnet24 returns the /24 CIDR for an IPv4 address.
func subnet24(ip string) string {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", parsed[0], parsed[1], parsed[2])
}
