# Contributing to TimeHammer

Thank you for your interest in contributing to TimeHammer! This document provides guidelines and instructions for contributing.

## 🔒 Security Notice

TimeHammer is a security testing tool. Please ensure that:
- You only test devices and networks you own or have explicit permission to test
- You do not use this tool for malicious purposes
- You report any security vulnerabilities responsibly

## 🚀 Getting Started

### Prerequisites

- Go 1.21 or later
- Make (optional, for build automation)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/neutrinoguy/timehammer.git
cd timehammer

# Download dependencies
go mod download

# Build
go build -o timehammer ./cmd/timehammer

# Or use make
make build
```

### Running Tests

```bash
go test -v ./...
```

## 📝 How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/neutrinoguy/timehammer/issues)
2. If not, create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - OS and Go version
   - Any relevant logs

### Suggesting Features

1. Open a new issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain how it would benefit security testing

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `go test ./...`
5. Run linter: `go vet ./...`
6. Commit with clear messages: `git commit -m "Add: new feature description"`
7. Push to your fork: `git push origin feature/my-feature`
8. Open a Pull Request

### Code Style

- Follow standard Go conventions
- Use `gofmt` to format code
- Add comments for exported functions
- Keep functions focused and small
- Write tests for new functionality

## 📁 Project Structure

```
.
├── cmd/timehammer/     # Main application entry point
├── internal/           # Private application code
│   ├── attacks/        # NTP attack implementations
│   ├── config/         # Configuration management
│   ├── logger/         # Logging system
│   ├── ntp/            # Upstream NTP client
│   ├── server/         # NTP server implementation
│   ├── session/        # Session recording
│   └── tui/            # Terminal user interface
├── pkg/ntpcore/        # Public NTP packet library
└── .github/workflows/  # CI/CD pipelines
```

## 🎯 Areas for Contribution

- Additional NTP/SNTP attacks
- Improved client fingerprinting
- More attack presets
- Documentation improvements
- Bug fixes
- Performance optimizations

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 💬 Questions?

Feel free to open an issue for any questions about contributing.

Thank you for helping make TimeHammer better! 🔨⏰
