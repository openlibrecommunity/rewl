package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

type scanResult struct {
	IP   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

type scanOutput struct {
	Country    string       `yaml:"country"`
	Iface      string       `yaml:"iface"`
	Ports      []int        `yaml:"ports"`
	Rate       int          `yaml:"rate"`
	StartedAt  time.Time    `yaml:"started_at"`
	FinishedAt time.Time    `yaml:"finished_at"`
	Total      int          `yaml:"total"`
	Results    []scanResult `yaml:"results"`
}

// masscan json record
type masscanRec struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port int `json:"port"`
	} `json:"ports"`
}

func checkRawAccess(iface string) error {
	// masscan needs CAP_NET_RAW. probe by running with --iflist or a dry check.
	cmd := exec.Command("masscan", "--interface", iface, "-p1", "127.0.0.0/32", "--rate", "1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		s := string(out)
		if strings.Contains(s, "permission") || strings.Contains(s, "raw") || strings.Contains(s, "root") {
			return fmt.Errorf("no raw packet access. run with sudo or: sudo setcap cap_net_raw=eip $(which masscan)")
		}
	}
	return nil
}

func parsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, n)
	}
	return ports, nil
}

func scan(country, iface, portsStr string, rate int) error {
	zone := fmt.Sprintf("data/raw/%s.zone", strings.ToLower(country))
	outPath := fmt.Sprintf("data/raw/%s.alive.yaml", strings.ToLower(country))

	if _, err := os.Stat(zone); err != nil {
		return fmt.Errorf("zone file not found: %s (run ipload first)", zone)
	}

	ports, err := parsePorts(portsStr)
	if err != nil {
		return err
	}

	if err := checkRawAccess(iface); err != nil {
		return err
	}

	started := time.Now()

	cmd := exec.Command("masscan",
		"-iL", zone,
		"-p", portsStr,
		"--interface", iface,
		"--rate", fmt.Sprintf("%d", rate),
		"-oJ", "-",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	var results []scanResult
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimSuffix(line, ",")
		if line == "" || line == "[" || line == "]" || strings.HasPrefix(line, "{finished") {
			continue
		}
		var rec masscanRec
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		for _, p := range rec.Ports {
			results = append(results, scanResult{IP: rec.IP, Port: p.Port})
		}
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	finished := time.Now()

	out := scanOutput{
		Country:    strings.ToLower(country),
		Iface:      iface,
		Ports:      ports,
		Rate:       rate,
		StartedAt:  started,
		FinishedAt: finished,
		Total:      len(results),
		Results:    results,
	}

	data, err := yaml.Marshal(&out)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return err
	}

	fmt.Printf("found %d alive endpoints, saved to %s\n", len(results), outPath)
	return nil
}
