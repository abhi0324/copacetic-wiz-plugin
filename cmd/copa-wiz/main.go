package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/abhi0324/copacetic-wiz-plugin/pkg/parser"
)

func main() {
	reportPath := flag.String("report", "", "Path to Wiz scan report JSON file")
	flag.Parse()

	if *reportPath == "" {
		fmt.Println("Error: -report flag is required")
		flag.Usage()
		os.Exit(1)
	}

	parser := parser.NewWizParser()
	manifest, err := parser.Parse(*reportPath)
	if err != nil {
		fmt.Printf("Error parsing report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully parsed report. Found %d vulnerabilities.\n", len(manifest.Updates))
}
