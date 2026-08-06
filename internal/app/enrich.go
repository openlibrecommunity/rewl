package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/oschwald/maxminddb-golang"

	"rewl/pkg/model"
)

type asnRecord struct {
	ASN  uint   `maxminddb:"autonomous_system_number"`
	Name string `maxminddb:"autonomous_system_organization"`
}

func enrich(country, iface, dbPath string, workers int, timeout time.Duration) error {
	country = strings.ToLower(country)
	input := fmt.Sprintf("data/raw/%s.verified.yaml", country)
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var verified model.Scan
	if err := yaml.Unmarshal(data, &verified); err != nil {
		return err
	}

	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	portsByIP := make(map[string]map[int]struct{})
	for _, result := range verified.Results {
		if portsByIP[result.IP] == nil {
			portsByIP[result.IP] = make(map[int]struct{})
		}
		portsByIP[result.IP][result.Port] = struct{}{}
	}
	ips := make([]string, 0, len(portsByIP))
	for ip := range portsByIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	localIP, err := interfaceIPv4(iface)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: localIP}}
	resolver := &net.Resolver{PreferGo: true}

	jobs := make(chan string)
	results := make(chan model.Host)
	var done atomic.Int64
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				host := enrichHost(ip, portsByIP[ip], db, dialer, resolver, timeout)
				n := done.Add(1)
				if n%100 == 0 || n == int64(len(ips)) {
					fmt.Fprintf(os.Stderr, "\renriched %d/%d", n, len(ips))
				}
				results <- host
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	started := time.Now()
	hosts := make([]model.Host, 0, len(ips))
	for host := range results {
		hosts = append(hosts, host)
	}
	fmt.Fprintln(os.Stderr)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP < hosts[j].IP })

	output := model.Enriched{
		Country:    country,
		Iface:      iface,
		StartedAt:  started,
		FinishedAt: time.Now(),
		Total:      len(hosts),
		Hosts:      hosts,
	}
	out, err := yaml.Marshal(&output)
	if err != nil {
		return err
	}
	outPath := fmt.Sprintf("data/raw/%s.enriched.yaml", country)
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return err
	}
	fmt.Printf("enriched %d hosts, saved to %s\n", len(hosts), outPath)
	return nil
}

func enrichHost(ip string, portSet map[int]struct{}, db *maxminddb.Reader, dialer *net.Dialer, resolver *net.Resolver, timeout time.Duration) model.Host {
	host := model.Host{IP: ip}
	for port := range portSet {
		host.OpenPorts = append(host.OpenPorts, port)
	}
	sort.Ints(host.OpenPorts)

	var asn asnRecord
	if err := db.Lookup(net.ParseIP(ip), &asn); err == nil {
		host.ASN = asn.ASN
		host.ASName = asn.Name
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	if ptr, err := resolver.LookupAddr(ctx, ip); err == nil {
		host.PTR = cleanNames(ptr)
	}
	cancel()

	if _, ok := portSet[443]; ok {
		host.TLSNames, host.TLSIssuer = certificateNames(ip, dialer, timeout)
	}
	if _, ok := portSet[80]; ok {
		host.HTTPHost = httpName(ip, dialer, timeout)
	}
	return host
}

func certificateNames(ip string, dialer *net.Dialer, timeout time.Duration) ([]string, string) {
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, ""
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		return nil, ""
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, ""
	}
	cert := certs[0]
	names := append([]string{}, cert.DNSNames...)
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	return cleanNames(names), cert.Issuer.CommonName
}

func httpName(ip string, dialer *net.Dialer, timeout time.Duration) string {
	transport := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + ip + "/")
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	location := resp.Header.Get("Location")
	if location == "" {
		return ""
	}
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func interfaceIPv4(name string) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet.IP.To4(), nil
		}
	}
	return nil, fmt.Errorf("no ipv4 address on %s", name)
}

func cleanNames(names []string) []string {
	set := make(map[string]struct{})
	for _, name := range names {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name != "" {
			set[name] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for name := range set {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
