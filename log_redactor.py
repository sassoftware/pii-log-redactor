"""
PII Log Redactor for SAS Logs
-----------------------------
Regex-only deterministic SAS log redactor.

Default behavior:
- Reads one file or a folder of log files.
- Writes redacted files to a separate output folder.
- Preserves input folder structure when processing directories.
- Writes redacted files as <original_file_name>_redacted.<extension>.
- Writes one summary file for the whole run.
- Does NOT delete original files unless --delete-original is provided.
- Preserves CASLIB names to help CAS-related troubleshooting.
"""
from __future__ import annotations

import os
import re
import hmac
import base64
import hashlib
import argparse
from pathlib import Path
from typing import Callable, Iterable, List



class Tokenizer:
    def __init__(self, salt: bytes) -> None:
        self._salt = salt

    @staticmethod
    def _b32(h: bytes) -> str:
        return base64.b32encode(h).decode("ascii").rstrip("=")

    def token(self, value: str, n: int = 16) -> str:
        h = hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256).digest()
        return self._b32(h)[:n]


class Stats:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def inc(self, key: str, n: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + n

    def as_lines(self) -> list[str]:
        total = sum(self.counts.values())
        lines = [f"Total sensitive items replaced: {total}"]

        sid_total = self.counts.get("SID", 0) + self.counts.get("SID2", 0)
        if sid_total > 0:
            lines.append(f"SESSION IDs: {sid_total}")

        for k, v in sorted(self.counts.items(), key=lambda kv: (-kv[1], kv[0])):
            if k in ("SID", "SID2"):
                continue
            lines.append(f"{k}: {v}")

        return lines


def counted_sub(
    stats: Stats,
    pattern: re.Pattern,
    key: str,
    replacement: str | Callable[[re.Match], str],
) -> Callable[[str], str]:
    def f(text: str) -> str:
        def _repl(m: re.Match) -> str:
            stats.inc(key)
            return replacement(m) if callable(replacement) else replacement

        return pattern.sub(_repl, text)

    return f


def load_salt(cli_salt: str | None = None) -> bytes:
    if cli_salt:
        return cli_salt.encode("utf-8")

    salt_env = os.environ.get("SALT")
    if salt_env:
        return salt_env.encode("utf-8")

    kv_url = os.environ.get("KEYVAULT_URL")
    salt_name = os.environ.get("HASH_SALT_NAME", "log-anon-salt")

    raise RuntimeError(
        "No salt provided. Use --salt, set SALT, or configure KEYVAULT_URL/HASH_SALT_NAME."
    )


sessionID1_re = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
sessionID2_1_re = re.compile(r"[0-9a-f]{16}", re.IGNORECASE)

IPAddress_re = re.compile(
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
)
url_with_host_re = re.compile(r"\b(https?)://([^/\s:]+)(:\d+)?([^\s]*)")

email_re = re.compile(r"[\w.\-_]+@[\w.\-_]+")
cnentries_re = re.compile(r"DN \[[^\]]*\]")

type_re = re.compile(r"type=[^,\.]+")
id_re = re.compile(r"id=[^,\.]+")
user_re = re.compile(r"user=[^,\.]+")
pid_re = re.compile(r"PID\s+\d+")

cas_3_re = re.compile(r"(Full job is: {{).*?(\})")
castable_re = re.compile(r"(/tables/)([^/]+)")

port2port_re = re.compile(r":\d{1,5}->:\d{1,5}")


def make_redactors(tokenizer: Tokenizer, stats: Stats) -> List[Callable[[str], str]]:
    redactCNEntries = counted_sub(stats, cnentries_re, "CN_ENTRIES", "<<DN>>")
    redactCASTable = counted_sub(stats, castable_re, "CASTABLE", r"/tables/<<TABLE>>")

    def redactsessionID(s: str) -> str:
        return sessionID1_re.sub(
            lambda m: (stats.inc("SID") or f"<<UUID_{tokenizer.token(m.group(0), 12)}>>"),
            s,
        )

    def redactsessionID2(s: str) -> str:
        return sessionID2_1_re.sub(
            lambda m: (stats.inc("SID") or f"<<UUID_{tokenizer.token(m.group(0), 10)}>>"),
            s,
        )

    def redactIPAddress(s: str) -> str:
        s = IPAddress_re.sub(
            lambda m: (stats.inc("IP ADDRESSES") or f"<<IP_{tokenizer.token(m.group(0), 8)}>>"),
            s,
        )
        return port2port_re.sub("", s)

    def redactHostname(s: str) -> str:
        def repl(m: re.Match) -> str:
            scheme, host, port, rest = m.group(1), m.group(2), m.group(3) or "", m.group(4) or ""
            stats.inc("HOSTNAMES")
            return f"{scheme}://<<HOST_{tokenizer.token(host, 8)}>>{port}{rest}"

        return url_with_host_re.sub(repl, s)

    def redactEmailAddresses(s: str) -> str:
        def repl(m: re.Match) -> str:
            stats.inc("EMAIL ADDRESSES")
            return f"<<EMAIL_{tokenizer.token(m.group(0), 8)}>>"

        return email_re.sub(repl, s)

    def redactMisc(s: str) -> str:
        s = type_re.sub("type=<<TYPE>>", s)

        def repl_id(m: re.Match) -> str:
            stats.inc("IDs")
            rhs = m.group(0).split("=", 1)[1]
            return f"id=<<ID_{tokenizer.token(rhs, 8)}>>"

        def repl_user(m: re.Match) -> str:
            stats.inc("USERNAMES")
            rhs = m.group(0).split("=", 1)[1]
            return f"user=<<USER_{tokenizer.token(rhs, 8)}>>"

        s = id_re.sub(repl_id, s)
        return user_re.sub(repl_user, s)

    def redactPID(s: str) -> str:
        def repl(m: re.Match) -> str:
            stats.inc("PROCESS IDs")
            return f"PID <<PROCESSID_{tokenizer.token(m.group(0), 8)}>>"

        return pid_re.sub(repl, s)

    def redactCASSpecific(s: str) -> str:
        return cas_3_re.sub(r"\1*\2", s)

    return [
        redactsessionID,
        redactsessionID2,
        redactIPAddress,
        redactHostname,
        redactEmailAddresses,
        redactCNEntries,
        redactMisc,
        redactPID,
        redactCASSpecific,
        redactCASTable,
    ]


def apply_pipeline(text: str, funcs: Iterable[Callable[[str], str]]) -> str:
    for f in funcs:
        text = f(text)
    return text


def process_text(text: str, pipeline: List[Callable[[str], str]]) -> str:
    return "\n".join(apply_pipeline(line, pipeline) for line in text.splitlines())


def should_skip_file(path: Path) -> bool:
    return path.stem.endswith("_redacted")


def get_redacted_name(path: Path) -> str:
    return f"{path.stem}_redacted{path.suffix}"


def get_output_path(inp: Path, input_root: Path, output_root: Path) -> Path:
    if inp.is_file() and input_root.is_file():
        return output_root / get_redacted_name(inp)

    relative_parent = inp.parent.relative_to(input_root)
    return output_root / relative_parent / get_redacted_name(inp)


def iter_paths(root: Path, recursive: bool) -> Iterable[Path]:
    allowed_extensions = {".log", ".txt", ".json", ".csv"}

    if root.is_dir():
        walker = root.rglob("*") if recursive else root.glob("*")
        for path in walker:
            if path.is_file() and path.suffix.lower() in allowed_extensions and not should_skip_file(path):
                yield path
    elif root.is_file():
        if not should_skip_file(root):
            yield root


def process_file(
    inp: Path,
    outp: Path,
    pipeline: List[Callable[[str], str]],
    encoding: str = "utf-8",
    delete_original: bool = False,
) -> None:
    outp.parent.mkdir(parents=True, exist_ok=True)

    with inp.open("r", encoding=encoding, errors="ignore") as f:
        data = f.read()

    redacted = process_text(data, pipeline)

    with outp.open("w", encoding=encoding) as f:
        f.write(redacted)

    if delete_original:
        inp.unlink()


def write_summary(output_root: Path, stats: Stats) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    summary_path = output_root / "redaction_summary.txt"
    summary_path.write_text("\n".join(stats.as_lines()), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Regex-only deterministic PII log redactor")
    parser.add_argument("--in", dest="inp", required=True, help="Input file or directory")
    parser.add_argument("--out", dest="out", required=True, help="Output directory for redacted files")
    parser.add_argument("--recursive", action="store_true", help="Recurse when input is a directory")
    parser.add_argument("--salt", dest="cli_salt", help="Secret salt. Prefer SALT env var for shared usage.")
    parser.add_argument("--delete-original",action="store_true",help="Delete source files only after successful redacted files are written",
    )
    args = parser.parse_args()

    input_path = Path(args.inp).expanduser().resolve()
    output_root = Path(args.out).expanduser().resolve()

    if not input_path.exists():
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    salt = load_salt(args.cli_salt)
    tokenizer = Tokenizer(salt)
    stats = Stats()
    pipeline = make_redactors(tokenizer, stats)

    for path in iter_paths(input_path, args.recursive):
        out_path = get_output_path(path, input_path, output_root)
        process_file(path, out_path, pipeline, delete_original=args.delete_original)

    write_summary(output_root, stats)


if __name__ == "__main__":
    main()
