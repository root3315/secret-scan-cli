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

## Limitations

- This is pattern-based, so there might be false positives
- It won't catch everything (obfuscated secrets, encrypted values, etc.)
- Binary files are skipped
- Very large files might slow things down

## Dependencies

Just `colorama` for nice colored output. If it's not installed, the tool still works but without colors.

## License

Do whatever you want with it.
