# Domain Health (dh) CLI Tool

A command-line interface tool for checking the email security configuration of a domain.

## Features

- Checks mail provider (e.g., Google, Microsoft, Mimecast)
- Verifies SPF (Sender Policy Framework) records
- Checks DMARC (Domain-based Message Authentication, Reporting, and Conformance) configuration
- Verifies DKIM (DomainKeys Identified Mail) records
- Displays an easy-to-read summary of domain email security

## Usage

```shell
dh <domain>
```

Example:

```shell
dh example.com
```

## Output

The tool provides a formatted table output including:

- Domain being checked
- Detected mail provider
- SPF record status and trusted senders
- DMARC configuration
- DKIM record status

## Requirements

- Rust (latest stable version)

## Installation

1. Clone the repository
2. Run `cargo build --release`
3. The binary will be available in `target/release/dh`

## License

[GNU GENERAL PUBLIC LICENSE](LICENSE)
