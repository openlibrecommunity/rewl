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
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

func verify(country, iface, ports string, rate, retries int) error {
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

	ips := make(map[string]struct{})
	for _, result := range scan.Results {
		ips[result.IP] = struct{}{}
	}
	list := make([]string, 0, len(ips))
	for ip := range ips {
		list = append(list, ip)
	}
	sort.Strings(list)

	targets, err := os.CreateTemp("", "rewl-nmap-targets-*.txt")
	if err != nil {
		return err
	}
	targetsPath := targets.Name()
	defer func() { _ = os.Remove(targetsPath) }()
	if _, err := targets.WriteString(strings.Join(list, "\n") + "\n"); err != nil {
		_ = targets.Close()
		return err
	}
	if err := targets.Close(); err != nil {
		return err
	}

	xmlFile, err := os.CreateTemp("", "rewl-nmap-*.xml")
	if err != nil {
		return err
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

	fmt.Printf("verifying %d unique IPs with nmap on ports %s\n", len(list), ports)
	cmd := exec.Command("nmap", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	started := time.Now()
	if err := cmd.Run(); err != nil {
		return err
	}
	finished := time.Now()

	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		return err
	}
	var run nmapRun
	if err := xml.Unmarshal(xmlData, &run); err != nil {
		return err
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
		if ip == "" {
			continue
		}
		for _, port := range host.Ports {
			if port.State.State == "open" {
				results = append(results, model.Result{IP: ip, Proto: port.Protocol, Port: port.Port})
			}
		}
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
		FinishedAt: finished,
		Total:      len(results),
		Results:    results,
	}
	out, err := yaml.Marshal(&output)
	if err != nil {
		return err
	}
	outPath := fmt.Sprintf("data/raw/%s.verified.yaml", country)
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return err
	}

	fmt.Printf("verified %d open endpoints, saved to %s\n", len(results), outPath)
	return nil
}
