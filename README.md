# PII Log Redactor


## Overview

A lightweight, regex-driven log redaction tool that uses deterministic tokenization to mask sensitive data in SAS logs. The PII Log Redactor scans log files, identifies sensitive values using configurable regex patterns, and replaces them with consistent, repeatable tokens. This approach preserves the original log structure, maintaining usability for troubleshooting while minimizing exposure of private or sensitive information.

## What is masked?

The current version masks common values such as:

- Email addresses
- IP addresses
- UUIDs / session IDs
- 16-character hexadecimal IDs
- `id=...` values
- `user=...` values
- Process IDs
- Hostnames inside `http://` and `https://` URLs
- Selected DN entries
- Selected CAS table path values

CASLIB names are intentionally preserved to support CAS-related troubleshooting.

## Important limitation

This tool uses regex-based anonymization. It can reduce sensitive data exposure, but it cannot guarantee that every possible PII value will be detected. Always review redacted logs before sharing them externally.

## Output behavior

The tool writes redacted files to a separate output directory.

Input:

```text
logs/
├── sas-compute.log
├── sas-data-quality.log
├── previous/sas-compute_previous.log
└── previous/sas-data-quality_previous.log
```

Command:

```bash
python log_redactor.py --in ./logs --out ./redacted_logs --recursive
```

Output:

```text
redacted_logs/
├── sas-compute_redacted.log
├── sas-data-quality_redacted.log
├── previous/sas-compute_previous_redacted.log
├── previous/sas-data-quality_previous_redacted.log
└── redacted_summary.txt
```

## Examples

### For single file

```bash
python log_redactor.py --in input.log --out ./redacted --salt "your-private-salt"
```

### For directory

```bash
python log_redactor.py --in ./logs --out ./redacted_logs --recursive --salt "your-private-salt"
```

### Optional deletion of original files

Original files are not deleted by default.

To delete original files after successful anonymization:

```bash
python log_redactor.py --in ./logs --out ./redacted_logs --recursive --salt "your-private-salt" --delete-original
```

## Salt

The tool uses a salt to generate deterministic redacted tokens, ensuring that the same input always produces the same redacted value when the same salt is used.


Generate a strong random salt:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Linux/macOS:

```bash
export SALT="your-generated-secret"
python log_redactor.py --in ./logs --out ./redacted_logs --recursive
```

Windows Command Line/PowerShell:

```command line
set SALT="your-generated-secret"
python log_redactor.py --in ./logs --out ./redacted_logs --recursive
```

```powershell
$env:SALT="your-generated-secret"
python log_redactor.py --in ./logs --out ./redacted_logs --recursive
```

Do not commit your salt to GitHub.


## Supported file extensions

Directory mode processes:

```text
.log
.txt
.json
.csv
```

Already-redacted files ending in `_redacted` are skipped.

## Dependencies

For basic usage, the script uses the Python standard library only. See [Python licensing details](https://docs.python.org/3/license.html#python-software-foundation-license-version-2) for more information on accessing and using Python.


## Contributing

Maintainers are not currently accepting patches and contributions to this project.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).
