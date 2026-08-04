package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func ipload(country string) error {
	urlStr := fmt.Sprintf("https://scanitex.com/resources/ipdb/ipv4/%s.zone", strings.ToLower(country))
	path := fmt.Sprintf("data/raw/%s.zone", strings.ToLower(country))

	client := &http.Client{Timeout: 30 * time.Second}

	if proxy := os.Getenv("all_proxy"); proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return fmt.Errorf("invalid proxy: %v", err)
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to download: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	lines := strings.Count(string(data), "\n")
	fmt.Printf("downloaded %d IPs to %s\n", lines, path)
	return nil
}
