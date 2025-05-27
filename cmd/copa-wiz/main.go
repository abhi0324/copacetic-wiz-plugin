package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/project-copacetic/wiz-scanner-plugin/pkg/parser"
)

func main() {
	// Parse command line arguments
	reportFile := flag.String("report", "", "Path to Wiz scan report file")
	flag.Parse()

	if *reportFile == "" {
		log.Fatal("Please provide a scan report file using -report flag")
	}

	// Create Wiz parser
	wizParser := parser.NewWizParser()

	// Parse the report
	manifest, err := wizParser.Parse(*reportFile)
	if err != nil {
		log.Fatalf("Error parsing Wiz report: %v", err)
	}

	// Output the manifest as JSON
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		log.Fatalf("Error encoding manifest: %v", err)
	}
}
