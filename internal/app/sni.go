package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"

	"rewl/pkg/model"
)

type sniObservation struct {
	IP      string              `json:"ip"`
	Names   map[string][]string `json:"names"`
	Checked bool                `json:"checked"`
}

type nameSet map[string]map[string]struct{}

var absoluteURLPattern = regexp.MustCompile(`https?://([a-zA-Z0-9*_.:-]+)`)

func collectSNI(country string, workers int, timeout time.Duration) error {
	country = strings.ToLower(country)
	input := fmt.Sprintf("data/pub/%s.enriched.yaml", country)
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var enriched model.Enriched
	if err := yaml.Unmarshal(data, &enriched); err != nil {
		return err
	}

	checkpointPath := fmt.Sprintf("data/raw/%s.sni.jsonl", country)
	observations, completed, err := loadSNIObservations(checkpointPath)
	if err != nil {
		return err
	}

	started := time.Now()
	checkpoint, err := os.OpenFile(checkpointPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = checkpoint.Close() }()

	jobs := make(chan model.Host)
	results := make(chan sniObservation)
	var wg sync.WaitGroup
	var done atomic.Int64
	remaining := 0
	for _, host := range enriched.Hosts {
		if !completed[host.IP] {
			remaining++
		}
	}

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				observation := inspectSNIHost(host, timeout)
				n := done.Add(1)
				if n%100 == 0 || n == int64(remaining) {
					fmt.Fprintf(os.Stderr, "\rsni %d/%d", n, remaining)
				}
				results <- observation
			}
		}()
	}

	go func() {
		for _, host := range enriched.Hosts {
			if !completed[host.IP] {
				jobs <- host
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	encoder := json.NewEncoder(checkpoint)
	written := 0
	for observation := range results {
		if err := encoder.Encode(&observation); err != nil {
			return err
		}
		written++
		if written%100 == 0 {
			if err := checkpoint.Sync(); err != nil {
				return err
			}
		}
		observations = append(observations, observation)
	}
	if err := checkpoint.Sync(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr)

	finished := time.Now()
	report := buildSNIReport(country, len(enriched.Hosts), observations, started, finished)
	out, err := yaml.Marshal(&report)
	if err != nil {
		return err
	}
	outPath := fmt.Sprintf("data/pub/%s.sni.yaml", country)
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return err
	}
	fmt.Printf("collected %d names from %d hosts, saved to %s\n", report.Total, report.Hosts, outPath)
	return nil
}

func inspectSNIHost(host model.Host, timeout time.Duration) sniObservation {
	names := make(nameSet)
	for _, name := range host.PTR {
		addName(names, name, "ptr")
	}
	if len(host.PTR) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		if ptr, err := net.DefaultResolver.LookupAddr(ctx, host.IP); err == nil {
			for _, name := range ptr {
				addName(names, name, "ptr")
			}
		}
		cancel()
	}

	ports := make(map[int]bool)
	for _, port := range host.OpenPorts {
		ports[port] = true
	}
	if ports[443] {
		for name := range tlsNames(host.IP, "", timeout) {
			addName(names, name, "tls_default")
		}
		mergeHTTPNames(names, fetchNames(host.IP, 443, "", true, timeout), "https_default")
	}
	if ports[80] {
		mergeHTTPNames(names, fetchNames(host.IP, 80, "", false, timeout), "http")
	}

	candidates := sortedNameKeys(names)
	if len(candidates) > 8 {
		candidates = candidates[:8]
	}
	for _, candidate := range candidates {
		if strings.Contains(candidate, "*") || net.ParseIP(candidate) != nil {
			continue
		}
		if ports[443] {
			for name := range tlsNames(host.IP, candidate, timeout) {
				addName(names, name, "tls_sni")
			}
			mergeHTTPNames(names, fetchNames(host.IP, 443, candidate, true, timeout), "https_sni")
		}
	}

	encoded := make(map[string][]string, len(names))
	for name, sources := range names {
		for source := range sources {
			encoded[name] = append(encoded[name], source)
		}
		sort.Strings(encoded[name])
	}
	return sniObservation{IP: host.IP, Names: encoded, Checked: true}
}

func tlsNames(ip, serverName string, timeout time.Duration) map[string]struct{} {
	result := make(map[string]struct{})
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: serverName})
	if err := tlsConn.Handshake(); err != nil {
		return result
	}
	for _, cert := range tlsConn.ConnectionState().PeerCertificates {
		for _, name := range cert.DNSNames {
			if cleaned := normalizeDomain(name); cleaned != "" {
				result[cleaned] = struct{}{}
			}
		}
		if cleaned := normalizeDomain(cert.Subject.CommonName); cleaned != "" {
			result[cleaned] = struct{}{}
		}
	}
	return result
}

func fetchNames(ip string, port int, host string, secure bool, timeout time.Duration) []string {
	scheme := "http"
	if secure {
		scheme = "https"
	}
	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	requestHost := ip
	if host != "" {
		requestHost = host
	}
	req, err := http.NewRequest(http.MethodGet, scheme+"://"+requestHost+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	var names []string
	for _, header := range []string{"Location", "Content-Location", "Refresh"} {
		names = append(names, domainsFromText(resp.Header.Get(header))...)
	}
	return cleanNames(names)
}

func domainsFromText(value string) []string {
	var names []string
	if parsed, err := url.Parse(strings.TrimSpace(value)); err == nil && parsed.Hostname() != "" {
		names = append(names, parsed.Hostname())
	}
	for _, match := range absoluteURLPattern.FindAllStringSubmatch(value, -1) {
		if len(match) > 1 {
			host := match[1]
			if parsed, err := url.Parse("http://" + host); err == nil {
				names = append(names, parsed.Hostname())
			}
		}
	}
	return cleanNames(names)
}

func mergeHTTPNames(names nameSet, found []string, source string) {
	for _, name := range found {
		addName(names, name, source)
	}
}

func addName(names nameSet, name, source string) {
	name = normalizeDomain(name)
	if name == "" {
		return
	}
	if names[name] == nil {
		names[name] = make(map[string]struct{})
	}
	names[name][source] = struct{}{}
}

func normalizeDomain(name string) string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	name = strings.TrimPrefix(name, "*.")
	if name == "" || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return ""
		}
	}
	return name
}

func sortedNameKeys(names nameSet) []string {
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func loadSNIObservations(path string) ([]sniObservation, map[string]bool, error) {
	completed := make(map[string]bool)
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, completed, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = file.Close() }()

	var observations []sniObservation
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var observation sniObservation
		if err := json.Unmarshal(scanner.Bytes(), &observation); err != nil {
			return nil, nil, err
		}
		observations = append(observations, observation)
		if observation.Checked {
			completed[observation.IP] = true
		}
	}
	return observations, completed, scanner.Err()
}

func buildSNIReport(country string, hosts int, observations []sniObservation, started, finished time.Time) model.SNIReport {
	type aggregate struct {
		ips     map[string]struct{}
		sources map[string]struct{}
	}
	byName := make(map[string]*aggregate)
	for _, observation := range observations {
		for name, sources := range observation.Names {
			if byName[name] == nil {
				byName[name] = &aggregate{ips: make(map[string]struct{}), sources: make(map[string]struct{})}
			}
			byName[name].ips[observation.IP] = struct{}{}
			for _, source := range sources {
				byName[name].sources[source] = struct{}{}
			}
		}
	}

	names := make([]model.SNIName, 0, len(byName))
	for name, aggregate := range byName {
		entry := model.SNIName{Name: name}
		for ip := range aggregate.ips {
			entry.IPs = append(entry.IPs, ip)
		}
		for source := range aggregate.sources {
			entry.Sources = append(entry.Sources, source)
		}
		sort.Strings(entry.IPs)
		sort.Strings(entry.Sources)
		names = append(names, entry)
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
	return model.SNIReport{Country: country, StartedAt: started, FinishedAt: finished, Hosts: hosts, Total: len(names), Names: names}
}
