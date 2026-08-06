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
