package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: rewl <command> [args]")
		fmt.Println("Commands:")
		fmt.Println("  ipload <country>  download IP list for country")
		fmt.Println("  ipcount <country>  count IPs from file")
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
	default:
		fmt.Printf("unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
