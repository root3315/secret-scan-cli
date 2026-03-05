# secret-scan-cli

A CLI tool to scan codebases for leaked secrets and credentials. Because we've all accidentally committed something we shouldn't have at 2am.

## Why This Exists

I got tired of manually checking if I leaked API keys before pushing. Also useful for auditing old projects or that one repo you inherited from someone who left the company.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Scan current directory
python secret_scan.py .

# Scan a specific project
python secret_scan.py /path/to/project

# Verbose mode (see what's being scanned)
python secret_scan.py . --verbose

# Output as JSON (for CI/CD pipelines)
python secret_scan.py . --format json --output results.json

# Exclude specific directories
python secret_scan.py . --exclude-dirs node_modules,venv,.git
```

## What It Detects

The scanner looks for common secret patterns:

- AWS Access Keys and Secret Keys
- GitHub tokens (ghp_, gho_, ghu_, ghr_)
- GitLab tokens
- Slack tokens and webhooks
- Stripe API keys (live and test)
- Google API keys and OAuth client IDs
- Heroku API keys
- Twilio API keys and SIDs
- SendGrid and Mailgun API keys
- NPM and PyPI tokens
- Docker Hub tokens
- DigitalOcean tokens
- Private keys (RSA, EC, DSA, OPENSSH)
- Database connection strings with credentials
- JWT tokens
- Generic API key patterns
- Basic auth headers

## Configuration File

Set default options in a `.secret_scan.json` file. The tool looks for this file in:

1. Current working directory
2. User's home directory

CLI arguments always override config file values.

### Config File Format

```json
{
  "exclude_dirs": ["node_modules", "venv", ".git", "build"],
  "exclude_files": ["*.min.js", "*.lock", "yarn.lock"],
  "format": "json",
  "verbose": false,
  "patterns": "custom_patterns.json",
  "default_patterns": true
}
```

### Config Options

| Option | Type | Description |
|--------|------|-------------|
| `exclude_dirs` | array/string | Directories to exclude from scanning |
| `exclude_files` | array/string | File patterns to exclude from scanning |
| `format` | string | Output format: `text` or `json` |
| `verbose` | boolean | Enable verbose output |
| `patterns` | string | Path to custom patterns JSON file |
| `default_patterns` | boolean | Use only default patterns (ignore custom) |

### Example Config

```json
{
  "exclude_dirs": ["node_modules", "venv", ".git", "dist", "build"],
  "exclude_files": ["*.min.js", "*.min.css", "*.lock"],
  "format": "text",
  "verbose": true
}
```

## Custom Patterns

Add your own detection patterns for project-specific secrets.

### Using a JSON File

Create a JSON file with your custom patterns:

```json
{
    "Internal API Key": {
        "pattern": "INT_API_[a-zA-Z0-9]{32}",
        "message": "Internal API key detected"
    },
    "Database Password": {
        "pattern": "(?i)db_password\\s*=\\s*[\"'][^\"']+[\"']",
        "message": "Database password in config detected"
    }
}
```

Then use it with:

```bash
python secret_scan.py . --patterns custom_patterns.json
```

### Inline Patterns

Add patterns directly via command line:

```bash
python secret_scan.py . --pattern "MyService:MS_[a-z]{20}:MyService API key detected"
```

Format: `name:regex:message`

Multiple patterns can be added:

```bash
python secret_scan.py . \
  --pattern "Service1:SVC1_[a-z]{10}:Service1 key" \
  --pattern "Service2:SVC2_[a-z]{10}:Service2 key"
```

### Combining Patterns

Use custom patterns only (no default patterns):

```bash
python secret_scan.py . --patterns custom.json --default-patterns
```

Or combine custom patterns with defaults (default behavior):

```bash
python secret_scan.py . --patterns custom.json --pattern "Extra:EX_[0-9]{5}:Extra pattern"
```

### Listing Active Patterns

See all patterns that will be used during scanning:

```bash
python secret_scan.py . --list-patterns
```

## Exit Codes

- `0` - No secrets found, all good
- `1` - Secrets detected or error occurred

This makes it easy to integrate into CI/CD pipelines and fail builds when secrets are found.

## Output

Text output looks like:

```
============================================================
  WARNING: 3 potential secret(s) found!
============================================================

[1] AWS Access Key
    File: /project/config.py
    Line: 15
    Issue: AWS Access Key ID detected
    Match: AKIAIOSFODNN7EXAMPLE

[2] GitHub Token
    File: /project/.env
    Line: 3
    Issue: GitHub Personal Access Token detected
    Match: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Tips

- Run this in your pre-commit hooks
- Add it to your CI pipeline before deployment
- Use `--verbose` to see what's being scanned (helpful for debugging exclude patterns)
- The default exclusions cover common directories like `node_modules`, `venv`, `.git`, etc.
- Use a config file to avoid repeating the same options every time

## Limitations

- This is pattern-based, so there might be false positives
- It won't catch everything (obfuscated secrets, encrypted values, etc.)
- Binary files are skipped
- Very large files might slow things down

## Dependencies

Just `colorama` for nice colored output. If it's not installed, the tool still works but without colors.

## License

Do whatever you want with it.
