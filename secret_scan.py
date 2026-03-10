#!/usr/bin/env python3
"""
Secret Scan CLI - Scan codebases for leaked secrets and credentials
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


SECRET_PATTERNS: Dict[str, Tuple[str, str]] = {
    "AWS Access Key": (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID detected"),
    "AWS Secret Key": (r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Access Key detected"),
    "GitHub Token": (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token detected"),
    "GitHub OAuth": (r'gho_[A-Za-z0-9]{36}', "GitHub OAuth Token detected"),
    "GitHub App": (r'ghu_[A-Za-z0-9]{36}', "GitHub App Token detected"),
    "GitHub Refresh": (r'ghr_[A-Za-z0-9]{36}', "GitHub Refresh Token detected"),
    "GitLab Token": (r'glpat-[A-Za-z0-9\-]{20,}', "GitLab Personal Access Token detected"),
    "Slack Token": (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', "Slack Token detected"),
    "Slack Webhook": (r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}', "Slack Webhook URL detected"),
    "Stripe API Key": (r'sk_live_[0-9a-zA-Z]{24}', "Stripe Live API Key detected"),
    "Stripe Test Key": (r'sk_test_[0-9a-zA-Z]{24}', "Stripe Test API Key detected"),
    "Google API Key": (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key detected"),
    "Google OAuth": (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "Google OAuth Client ID detected"),
    "Heroku API Key": (r'(?i)heroku[_\-]?api[_\-]?key["\']?\s*[:=]\s*["\']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']?', "Heroku API Key detected"),
    "Twilio API Key": (r'SK[0-9a-fA-F]{32}', "Twilio API Key detected"),
    "Twilio SID": (r'AC[0-9a-fA-F]{32}', "Twilio Account SID detected"),
    "SendGrid API Key": (r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}', "SendGrid API Key detected"),
    "Mailgun API Key": (r'key-[0-9a-zA-Z]{32}', "Mailgun API Key detected"),
    "NPM Token": (r'npm_[A-Za-z0-9]{36}', "NPM Access Token detected"),
    "PyPI Token": (r'pypi-[A-Za-z0-9]{50,}', "PyPI API Token detected"),
    "Docker Hub": (r'dckr_pat_[A-Za-z0-9]{59}', "Docker Hub Personal Access Token detected"),
    "DigitalOcean": (r'dop_v1_[a-fA-F0-9]{64}', "DigitalOcean API Token detected"),
    "Private Key": (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key detected"),
    "Password in URL": (r'(?i)(password|passwd|pwd|secret|token|api[_\-]?key)["\']?\s*[:=]\s*["\']?[^"\'\s]{8,}["\']?', "Potential password/secret in config detected"),
    "Generic API Key": (r'(?i)(api[_\-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?', "Generic API Key pattern detected"),
    "Database URL": (r'(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@', "Database connection string with credentials detected"),
    "JWT Token": (r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "Potential JWT Token detected"),
    "Basic Auth": (r'(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}', "Base64 encoded Basic Auth detected"),
}

DEFAULT_EXCLUDE_DIRS = {
    '.git', '.svn', '.hg', 'node_modules', '__pycache__', 'venv',
    'env', '.venv', 'vendor', 'dist', 'build', '.idea', '.vscode',
    'coverage', '.tox', '.eggs', '*.egg-info', 'migrations'
}

DEFAULT_EXCLUDE_FILES = {
    '*.pyc', '*.pyo', '*.so', '*.dll', '*.dylib', '*.class',
    '*.min.js', '*.min.css', '*.lock', 'package-lock.json', 'yarn.lock'
}

CONFIG_FILENAMES = ['.secret_scan.json', 'secret_scan.json']


def colorize(text: str, color: str) -> str:
    if COLORS_AVAILABLE:
        color_map = {
            'red': Fore.RED,
            'yellow': Fore.YELLOW,
            'green': Fore.GREEN,
            'cyan': Fore.CYAN,
            'magenta': Fore.MAGENTA,
            'reset': Style.RESET_ALL
        }
        return f"{color_map.get(color, '')}{text}{Style.RESET_ALL}"
    return text


def load_config() -> Dict[str, Any]:
    """Load configuration from JSON file.
    
    Searches for config file in:
    1. Current working directory
    2. User's home directory
    
    Returns empty dict if no config file is found.
    """
    search_paths = [
        Path.cwd() / '.secret_scan.json',
        Path.cwd() / 'secret_scan.json',
        Path.home() / '.secret_scan.json',
        Path.home() / 'secret_scan.json',
    ]
    
    for config_path in search_paths:
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                if not isinstance(config, dict):
                    print(colorize(f"Warning: Config file {config_path} is not a JSON object, ignoring", "yellow"))
                    return {}
                return config
            except json.JSONDecodeError as e:
                print(colorize(f"Warning: Invalid JSON in {config_path}: {e}", "yellow"))
                return {}
            except (IOError, OSError) as e:
                print(colorize(f"Warning: Could not read {config_path}: {e}", "yellow"))
                return {}
    
    return {}


def parse_config_value(key: str, value: Any) -> Any:
    """Parse and validate config values based on key."""
    if key in ('exclude_dirs', 'exclude_files'):
        if isinstance(value, list):
            return set(value)
        elif isinstance(value, str):
            return set(v.strip() for v in value.split(','))
    elif key == 'verbose':
        return bool(value)
    elif key == 'format':
        if value in ('text', 'json'):
            return value
    elif key == 'patterns':
        if isinstance(value, str):
            return value
    elif key == 'default_patterns':
        return bool(value)
    return value


def should_exclude_file(filepath: Path, exclude_files: set) -> bool:
    name = filepath.name
    for pattern in exclude_files:
        if pattern.startswith('*.') and name.endswith(pattern[1:]):
            return True
        if name == pattern:
            return True
    return False


def should_exclude_dir(dirname: str, exclude_dirs: set) -> bool:
    if dirname in exclude_dirs:
        return True
    for pattern in exclude_dirs:
        if pattern.startswith('*') and dirname.endswith(pattern[1:]):
            return True
    return False


def scan_file(filepath: Path, patterns: Dict[str, Tuple[str, str]]) -> List[Dict]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (IOError, OSError) as e:
        return findings
    except UnicodeDecodeError:
        return findings

    for line_num, line in enumerate(lines, 1):
        for pattern_name, (pattern, message) in patterns.items():
            try:
                matches = re.finditer(pattern, line)
                for match in matches:
                    findings.append({
                        'file': str(filepath),
                        'line': line_num,
                        'pattern': pattern_name,
                        'message': message,
                        'content': match.group(0)[:100]
                    })
            except re.error:
                continue

    return findings


def scan_directory(
    root_path: Path,
    patterns: Dict[str, Tuple[str, str]],
    exclude_dirs: set,
    exclude_files: set,
    verbose: bool = False
) -> List[Dict]:
    all_findings = []
    files_scanned = 0

    files_to_scan = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        current_dir = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not should_exclude_dir(d, exclude_dirs)]

        for filename in filenames:
            filepath = current_dir / filename

            if should_exclude_file(filepath, exclude_files):
                continue

            files_to_scan.append(filepath)

    progress_iter = tqdm(files_to_scan, desc="Scanning", unit="file", ncols=80) if TQDM_AVAILABLE else files_to_scan

    for filepath in progress_iter:
        files_scanned += 1
        if verbose:
            print(f"Scanning: {filepath}")

        findings = scan_file(filepath, patterns)
        all_findings.extend(findings)

    if verbose:
        print(f"\nTotal files scanned: {files_scanned}")

    return all_findings


def print_findings(findings: List[Dict], output_format: str = 'text') -> None:
    if not findings:
        print(colorize("\nNo secrets detected! Your codebase looks clean.", "green"))
        return

    print(colorize(f"\n{'='*60}", "red"))
    print(colorize(f"  WARNING: {len(findings)} potential secret(s) found!", "red"))
    print(colorize(f"{'='*60}\n", "red"))

    if output_format == 'json':
        import json
        print(json.dumps(findings, indent=2))
        return

    seen = set()
    for i, finding in enumerate(findings, 1):
        key = (finding['file'], finding['line'], finding['pattern'])
        if key in seen:
            continue
        seen.add(key)

        print(colorize(f"[{i}] {finding['pattern']}", "magenta"))
        print(f"    File: {colorize(finding['file'], 'cyan')}")
        print(f"    Line: {colorize(str(finding['line']), 'yellow')}")
        print(f"    Issue: {finding['message']}")
        print(f"    Match: {colorize(finding['content'], 'red')}")
        print()


def load_custom_patterns(pattern_file: str) -> Dict[str, Tuple[str, str]]:
    """Load custom patterns from a JSON file.

    Expected format:
    {
        "Pattern Name": {
            "pattern": "regex_pattern",
            "message": "Description message"
        }
    }
    """
    try:
        with open(pattern_file, 'r') as f:
            data = json.load(f)
    except (IOError, OSError) as e:
        print(colorize(f"Error reading patterns file: {e}", "red"))
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(colorize(f"Error parsing patterns file: Invalid JSON - {e}", "red"))
        sys.exit(1)

    custom_patterns = {}
    for name, config in data.items():
        if not isinstance(config, dict):
            print(colorize(f"Warning: Skipping '{name}' - invalid format", "yellow"))
            continue
        pattern = config.get('pattern')
        message = config.get('message', f"Custom pattern '{name}' detected")
        if pattern:
            try:
                re.compile(pattern)
                custom_patterns[name] = (pattern, message)
            except re.error as e:
                print(colorize(f"Warning: Skipping '{name}' - invalid regex: {e}", "yellow"))
        else:
            print(colorize(f"Warning: Skipping '{name}' - missing 'pattern' field", "yellow"))

    return custom_patterns


def parse_inline_pattern(pattern_str: str) -> Tuple[str, str, str]:
    """Parse inline pattern string in format: name:regex:message

    Returns (name, pattern, message) tuple.
    """
    parts = pattern_str.split(':', 2)
    if len(parts) < 2:
        raise ValueError("Pattern must be in format: name:regex:message")

    name = parts[0].strip()
    pattern = parts[1].strip()
    message = parts[2].strip() if len(parts) > 2 else f"Custom pattern '{name}' detected"

    re.compile(pattern)
    return name, pattern, message


def merge_args_with_config(args: argparse.Namespace, config: Dict[str, Any]) -> argparse.Namespace:
    """Merge CLI args with config values. CLI args take precedence.
    
    Only override args that weren't explicitly set via CLI.
    """
    config_mappings = {
        'exclude_dirs': ('exclude_dirs', lambda v: ','.join(v) if isinstance(v, (list, set)) else v),
        'exclude_files': ('exclude_files', lambda v: ','.join(v) if isinstance(v, (list, set)) else v),
        'format': ('format', lambda v: v),
        'verbose': ('verbose', lambda v: v),
        'patterns': ('patterns', lambda v: v),
        'default_patterns': ('default_patterns', lambda v: v),
    }
    
    for config_key, (arg_key, transform) in config_mappings.items():
        if config_key in config:
            current_value = getattr(args, arg_key, None)
            default_value = None
            
            if arg_key == 'verbose':
                default_value = False
            elif arg_key == 'default_patterns':
                default_value = False
            elif arg_key in ('exclude_dirs', 'exclude_files'):
                default_value = ''
            elif arg_key == 'format':
                default_value = 'text'
            elif arg_key == 'patterns':
                default_value = None
            
            if current_value == default_value:
                config_value = parse_config_value(config_key, config[config_key])
                if config_key in ('exclude_dirs', 'exclude_files') and isinstance(config_value, set):
                    config_value = ','.join(config_value)
                setattr(args, arg_key, config_value)
    
    return args


def main():
    config = load_config()
    
    parser = argparse.ArgumentParser(
        description='Scan codebases for leaked secrets and credentials',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project
  %(prog)s . --exclude-dirs node_modules,venv
  %(prog)s . --format json --output results.json
  %(prog)s . --verbose
  %(prog)s . --patterns custom_patterns.json
  %(prog)s . --pattern "MyAPI:api_[a-z]{10}:MyAPI key detected"

Config File:
  Create a .secret_scan.json in your project or home directory:
  {
    "exclude_dirs": ["node_modules", "venv", ".git"],
    "exclude_files": ["*.min.js", "*.lock"],
    "format": "json",
    "verbose": true,
    "patterns": "custom_patterns.json",
    "default_patterns": false
  }
  
  CLI arguments override config file values.
        """
    )

    parser.add_argument(
        'path',
        nargs='?',
        default='.',
        help='Path to scan (default: current directory)'
    )
    parser.add_argument(
        '--exclude-dirs',
        type=str,
        default='',
        help='Comma-separated list of directories to exclude'
    )
    parser.add_argument(
        '--exclude-files',
        type=str,
        default='',
        help='Comma-separated list of file patterns to exclude'
    )
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='',
        help='Output file path (default: stdout)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show verbose output including files being scanned'
    )
    parser.add_argument(
        '--list-patterns',
        action='store_true',
        help='List all detection patterns and exit'
    )
    parser.add_argument(
        '--patterns',
        type=str,
        metavar='FILE',
        help='Load custom patterns from a JSON file'
    )
    parser.add_argument(
        '--pattern',
        action='append',
        metavar='NAME:REGEX:MESSAGE',
        help='Add a custom pattern (format: name:regex:message). Can be used multiple times.'
    )
    parser.add_argument(
        '--default-patterns',
        action='store_true',
        help='Use only default patterns (ignore custom patterns from --patterns/--pattern)'
    )

    args = parser.parse_args()
    args = merge_args_with_config(args, config)

    patterns = {}

    if not args.default_patterns:
        patterns = SECRET_PATTERNS.copy()

    if args.patterns:
        custom_file_patterns = load_custom_patterns(args.patterns)
        patterns.update(custom_file_patterns)

    if args.pattern:
        for pattern_str in args.pattern:
            try:
                name, pattern, message = parse_inline_pattern(pattern_str)
                patterns[name] = (pattern, message)
            except re.error as e:
                print(colorize(f"Error in pattern '{pattern_str}': Invalid regex - {e}", "red"))
                return 1
            except ValueError as e:
                print(colorize(f"Error in pattern '{pattern_str}': {e}", "red"))
                return 1

    if args.list_patterns:
        print("Available secret detection patterns:\n")
        for name, (pattern, message) in patterns.items():
            print(f"  - {name}")
            print(f"    {message}")
            print(f"    Pattern: {pattern}")
            print()
        return 0

    root_path = Path(args.path).resolve()

    if not root_path.exists():
        print(colorize(f"Error: Path '{root_path}' does not exist", "red"))
        return 1

    if not root_path.is_dir():
        print(colorize(f"Error: '{root_path}' is not a directory", "red"))
        return 1

    exclude_dirs = DEFAULT_EXCLUDE_DIRS.copy()
    if args.exclude_dirs:
        exclude_dirs.update(d.strip() for d in args.exclude_dirs.split(','))

    exclude_files = DEFAULT_EXCLUDE_FILES.copy()
    if args.exclude_files:
        exclude_files.update(f.strip() for f in args.exclude_files.split(','))

    if args.verbose:
        print(f"Scanning directory: {root_path}")
        print(f"Excluded directories: {', '.join(sorted(exclude_dirs))}")
        print(f"Active patterns: {len(patterns)}")
        print()

    findings = scan_directory(
        root_path,
        patterns,
        exclude_dirs,
        exclude_files,
        args.verbose
    )

    if args.output:
        try:
            with open(args.output, 'w') as f:
                if args.format == 'json':
                    import json
                    json.dump(findings, f, indent=2)
                else:
                    for finding in findings:
                        f.write(f"{finding['file']}:{finding['line']} - {finding['pattern']}\n")
            print(f"Results written to: {args.output}")
        except IOError as e:
            print(colorize(f"Error writing output file: {e}", "red"))
            return 1
    else:
        print_findings(findings, args.format)

    return 1 if findings else 0


if __name__ == '__main__':
    sys.exit(main())
