package model

import "time"

type Result struct {
	IP    string `yaml:"ip"`
	Proto string `yaml:"proto"`
	Port  int    `yaml:"port"`
}

type Scan struct {
	Country    string    `yaml:"country"`
	Iface      string    `yaml:"iface"`
	Ports      []int     `yaml:"ports"`
	Rate       int       `yaml:"rate"`
	StartedAt  time.Time `yaml:"started_at"`
	FinishedAt time.Time `yaml:"finished_at"`
	Total      int       `yaml:"total"`
	Results    []Result  `yaml:"results"`
}

type Host struct {
	IP        string   `yaml:"ip"`
	ASN       uint     `yaml:"asn,omitempty"`
	ASName    string   `yaml:"as_name,omitempty"`
	PTR       []string `yaml:"ptr,omitempty"`
	TLSNames  []string `yaml:"tls_names,omitempty"`
	TLSIssuer string   `yaml:"tls_issuer,omitempty"`
	HTTPHost  string   `yaml:"http_host,omitempty"`
	OpenPorts []int    `yaml:"open_ports"`
}

type Enriched struct {
	Country    string    `yaml:"country"`
	Iface      string    `yaml:"iface"`
	StartedAt  time.Time `yaml:"started_at"`
	FinishedAt time.Time `yaml:"finished_at"`
	Total      int       `yaml:"total"`
	Hosts      []Host    `yaml:"hosts"`
}

type SNIName struct {
	Name    string   `yaml:"name"`
	IPs     []string `yaml:"ips"`
	Sources []string `yaml:"sources"`
}

type SNIReport struct {
	Country    string    `yaml:"country"`
	StartedAt  time.Time `yaml:"started_at"`
	FinishedAt time.Time `yaml:"finished_at"`
	Hosts      int       `yaml:"hosts"`
	Total      int       `yaml:"total"`
	Names      []SNIName `yaml:"names"`
}
