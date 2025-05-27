# Copacetic Wiz Plugin

A plugin for [Copacetic](https://github.com/project-copacetic/copacetic) that adds support for Wiz vulnerability scan reports.

## Overview

This project demonstrates how to extend Copacetic's vulnerability scanning capabilities by adding support for Wiz scanning reports. It implements a parser that converts Wiz scan reports into Copacetic's standard format.

## Features

- Parse Wiz scan reports
- Convert Wiz vulnerability data to Copacetic's format
- Support for Wiz's scanning schema
- Severity-based filtering
- Comprehensive test coverage
- Docker support

## Project Structure

```
copacetic-wiz-plugin/
├── cmd/            # Command-line interface
├── pkg/            # Core package code
│   ├── parser/     # Wiz report parser
│   └── types/      # Data types
└── test/           # Test files
```

## Getting Started

### Prerequisites

- Go 1.21 or later
- Docker (optional)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/abhi0324/copacetic-wiz-plugin.git
cd copacetic-wiz-plugin
```

2. Build the plugin:
```bash
go build -o copa-wiz ./cmd/copa-wiz
```

### Usage

```bash
# Process a Wiz scan report
./copa-wiz -report path/to/wiz-report.json

# Build and run with Docker
docker build -t copa-wiz .
docker run -v $(pwd):/reports copa-wiz -report /reports/wiz-report.json
```

## Development

### Running Tests

```bash
go test ./...
```

### Building Docker Image

```bash
docker build -t copa-wiz .
```

## Integration with Copacetic

This plugin is designed to work with Copacetic's plugin system. To use it:

1. Build the plugin
2. Place it in Copacetic's plugin directory
3. Use it with Copacetic's command-line interface

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the same license as Copacetic.

## About

This project was created as a sample implementation for the CNCF - Copacetic: Wiz Scanning Support mentorship project. It demonstrates the implementation of a Wiz scanner plugin for Copacetic. 