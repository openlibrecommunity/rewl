package app

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"rewl/pkg/model"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     []nmapPort    `xml:"ports>port"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapPort struct {
	Protocol string    `xml:"protocol,attr"`
	Port     int       `xml:"portid,attr"`
	State    nmapState `xml:"state"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type verifyCheckpoint struct {
	Next    int            `yaml:"next"`
	Results []model.Result `yaml:"results"`
}

func verify(country, iface, ports string, rate, retries, batchSize int) error {
	if err := checkRawAccess(); err != nil {
		return err
	}

	country = strings.ToLower(country)
	input := fmt.Sprintf("data/raw/%s.refined.yaml", country)
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}

	var scan model.Scan
	if err := yaml.Unmarshal(data, &scan); err != nil {
		return err
	}

	ipSet := make(map[string]struct{})
	for _, result := range scan.Results {
		ipSet[result.IP] = struct{}{}
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	checkpointPath := fmt.Sprintf("data/raw/%s.verify.checkpoint.yaml", country)
	checkpoint, err := loadVerifyCheckpoint(checkpointPath)
	if err != nil {
		return err
	}
	if checkpoint.Next > len(ips) {
		return fmt.Errorf("invalid checkpoint index %d for %d targets", checkpoint.Next, len(ips))
	}

	started := time.Now()
	fmt.Printf("verifying %d unique IPs with nmap on ports %s\n", len(ips), ports)
	if checkpoint.Next > 0 {
		fmt.Printf("resuming at %d/%d with %d open endpoints\n", checkpoint.Next, len(ips), len(checkpoint.Results))
	}

	for start := checkpoint.Next; start < len(ips); start += batchSize {
		end := min(start+batchSize, len(ips))
		results, err := runNmapBatch(ips[start:end], iface, ports, rate, retries)
		if err != nil {
			return fmt.Errorf("batch %d-%d failed, rerun to resume: %w", start, end, err)
		}
		checkpoint.Results = append(checkpoint.Results, results...)
		checkpoint.Next = end
		if err := saveYAML(checkpointPath, &checkpoint); err != nil {
			return err
		}
		fmt.Printf("verified %d/%d IPs, open endpoints: %d\n", end, len(ips), len(checkpoint.Results))
	}

	verifiedPorts, err := parsePorts(ports)
	if err != nil {
		return err
	}
	output := model.Scan{
		Country:    country,
		Iface:      iface,
		Ports:      verifiedPorts,
		Rate:       rate,
		StartedAt:  started,
		FinishedAt: time.Now(),
		Total:      len(checkpoint.Results),
		Results:    checkpoint.Results,
	}
	outPath := fmt.Sprintf("data/raw/%s.verified.yaml", country)
	if err := saveYAML(outPath, &output); err != nil {
		return err
	}
	if err := os.Remove(checkpointPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	fmt.Printf("verified %d open endpoints, saved to %s\n", len(checkpoint.Results), outPath)
	return nil
}

func runNmapBatch(ips []string, iface, ports string, rate, retries int) ([]model.Result, error) {
	targets, err := os.CreateTemp("", "rewl-nmap-targets-*.txt")
	if err != nil {
		return nil, err
	}
	targetsPath := targets.Name()
	defer func() { _ = os.Remove(targetsPath) }()
	if _, err := targets.WriteString(strings.Join(ips, "\n") + "\n"); err != nil {
		_ = targets.Close()
		return nil, err
	}
	if err := targets.Close(); err != nil {
		return nil, err
	}

	xmlFile, err := os.CreateTemp("", "rewl-nmap-*.xml")
	if err != nil {
		return nil, err
	}
	xmlPath := xmlFile.Name()
	_ = xmlFile.Close()
	defer func() { _ = os.Remove(xmlPath) }()

	args := []string{
		"-sS", "-Pn", "-n",
		"-e", iface,
		"-p", ports,
		"--min-rate", strconv.Itoa(rate),
		"--max-rate", strconv.Itoa(rate),
		"--max-retries", strconv.Itoa(retries),
		"--host-timeout", "20s",
		"--stats-every", "5s",
		"-iL", targetsPath,
		"-oX", xmlPath,
	}
	cmd := exec.Command("nmap", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, err
	}
	var run nmapRun
	if err := xml.Unmarshal(xmlData, &run); err != nil {
		return nil, err
	}

	var results []model.Result
	for _, host := range run.Hosts {
		ip := ""
		for _, address := range host.Addresses {
			if address.Type == "ipv4" {
				ip = address.Addr
				break
			}
		}
		for _, port := range host.Ports {
			if ip != "" && port.State.State == "open" {
				results = append(results, model.Result{IP: ip, Proto: port.Protocol, Port: port.Port})
			}
		}
	}
	return results, nil
}

func loadVerifyCheckpoint(path string) (verifyCheckpoint, error) {
	var checkpoint verifyCheckpoint
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return checkpoint, nil
	}
	if err != nil {
		return checkpoint, err
	}
	if err := yaml.Unmarshal(data, &checkpoint); err != nil {
		return checkpoint, err
	}
	return checkpoint, nil
}

func saveYAML(path string, value any) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
