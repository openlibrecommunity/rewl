package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: rewl <command> [args]")
		fmt.Println("Commands:")
		fmt.Println("  ipload <country>  download IP list for country")
		fmt.Println("  ipcount <country>  count IPs from file")
		fmt.Println("  scan <country> --iface <if> --ports <p,p> --rate <n>  scan alive IPs")
		fmt.Println("  analyze <country>  analyze scan results")
		fmt.Println("  refine <country> --iface <if> --ports <p,p> --rate <n>  rescan discovered /24 subnets")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "ipload":
		if len(os.Args) < 3 {
			fmt.Println("Usage: rewl ipload <country>")
			os.Exit(1)
		}
		if err := ipload(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "ipcount":
		if len(os.Args) < 3 {
			fmt.Println("Usage: rewl ipcount <country>")
			os.Exit(1)
		}
		if err := ipcount(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: rewl scan <country> --iface <if> --ports <p,p> --rate <n>")
			os.Exit(1)
		}
		country := os.Args[2]
		fs := flag.NewFlagSet("scan", flag.ExitOnError)
		iface := fs.String("iface", "", "network interface")
		ports := fs.String("ports", "", "ports comma separated (e.g. 80,443)")
		rate := fs.Int("rate", 0, "scan rate")
		routerMAC := fs.String("router-mac", "", "router MAC (for USB modems etc)")
		resume := fs.Bool("resume", false, "resume from paused.conf")
		if err := fs.Parse(os.Args[3:]); err != nil {
			os.Exit(1)
		}
		if !*resume && (*iface == "" || *ports == "" || *rate == 0) {
			fmt.Println("Usage: rewl scan <country> --iface <if> --ports <p,p> --rate <n> [--router-mac <mac>] [--resume]")
			os.Exit(1)
		}
		if err := scan(country, *iface, *ports, *routerMAC, *rate, *resume); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "analyze":
		if len(os.Args) < 3 {
			fmt.Println("Usage: rewl analyze <country>")
			os.Exit(1)
		}
		if err := analyze(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "refine":
		if len(os.Args) < 3 {
			fmt.Println("Usage: rewl refine <country> --iface <if> --ports <p,p> --rate <n> [--retries <n>]")
			os.Exit(1)
		}
		country := os.Args[2]
		fs := flag.NewFlagSet("refine", flag.ExitOnError)
		iface := fs.String("iface", "", "network interface")
		ports := fs.String("ports", "", "ports comma separated")
		rate := fs.Int("rate", 0, "scan rate")
		retries := fs.Int("retries", 3, "masscan retries")
		routerMAC := fs.String("router-mac", "", "router MAC")
		if err := fs.Parse(os.Args[3:]); err != nil {
			os.Exit(1)
		}
		if *iface == "" || *ports == "" || *rate == 0 || *retries < 0 {
			fmt.Println("Usage: rewl refine <country> --iface <if> --ports <p,p> --rate <n> [--retries <n>]")
			os.Exit(1)
		}
		if err := refine(country, *iface, *ports, *routerMAC, *rate, *retries); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
