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

func checkRawAccess() error {
	// raw sockets require root or CAP_NET_RAW
	if os.Geteuid() != 0 {
		return fmt.Errorf("no raw packet access. run with sudo or: sudo setcap cap_net_raw=eip $(which masscan)")
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

func scan(country, iface, portsStr, routerMAC string, rate int) error {
	zone := fmt.Sprintf("data/raw/%s.zone", strings.ToLower(country))
	outPath := fmt.Sprintf("data/raw/%s.alive.yaml", strings.ToLower(country))

	if _, err := os.Stat(zone); err != nil {
		return fmt.Errorf("zone file not found: %s (run ipload first)", zone)
	}

	ports, err := parsePorts(portsStr)
	if err != nil {
		return err
	}

	if err := checkRawAccess(); err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "rewl-scan-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	started := time.Now()

	// -oJ to temp file so masscan progress stays on stderr/tty
	args := []string{
		"-iL", zone,
		"-p", portsStr,
		"--interface", iface,
		"--rate", fmt.Sprintf("%d", rate),
		"--wait", "3",
		"-oJ", tmpPath,
	}
	if routerMAC != "" {
		args = append(args, "--router-mac", routerMAC)
	}
	cmd := exec.Command("masscan", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	finished := time.Now()

	f, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	var results []scanResult
	scanner := bufio.NewScanner(f)
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
