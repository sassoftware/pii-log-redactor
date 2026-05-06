# PII SAS Log Redactor

A lightweight regex-based log redactor with deterministic tokenization for masking sensitive data in SAS logs.

## High-level summary

The PII Log Redactor scans log files, detects sensitive values using regex patterns, and replaces them with consistent redacted tokens. It preserves the overall log structure so logs remain useful for troubleshooting while reducing exposure of private or sensitive information.

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

## Usage

### Single file

```bash
python log_redactor.py --in input.log --out ./redacted --salt "your-private-salt"
```

### Directory

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

For basic usage, the script uses the Python standard library only.



## Safety notes

- Test with copied logs first.
- Keep your salt private.
- Use the same salt when you need consistent tokens across multiple runs.
- Use `--delete-original` only when you are sure you no longer need the original files.
- Regex anonymization is not a guarantee of complete privacy protection.

