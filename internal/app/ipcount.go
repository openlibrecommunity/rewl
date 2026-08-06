package app

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func ipcount(country string) error {
	path := fmt.Sprintf("data/raw/%s.zone", strings.ToLower(country))

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	total := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}

		ones, _ := ipnet.Mask.Size()
		count := 1 << (32 - ones)
		total += count
	}

	fmt.Printf("%d IPs in %s\n", total, path)
	return nil
}
