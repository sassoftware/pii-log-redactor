from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from log_anonymizer import Tokenizer, Stats, make_cleaners, process_text, should_skip_file


def test_masks_email_and_ip():
    tokenizer = Tokenizer(b"test-salt")
    stats = Stats()
    pipeline = make_cleaners(tokenizer, stats)

    text = "User mark@example.com connected from 10.20.30.40"
    out = process_text(text, pipeline)

    assert "mark@example.com" not in out
    assert "10.20.30.40" not in out
    assert "<<EMAIL_" in out
    assert "<<IP_" in out


def test_deterministic_email_token():
    tokenizer = Tokenizer(b"test-salt")
    stats = Stats()
    pipeline = make_cleaners(tokenizer, stats)

    text = "mark@example.com mark@example.com"
    out = process_text(text, pipeline)

    tokens = [part for part in out.split() if part.startswith("<<EMAIL_")]
    assert len(tokens) == 2
    assert tokens[0] == tokens[1]


def test_preserves_caslib_in_cas_access_path():
    tokenizer = Tokenizer(b"test-salt")
    stats = Stats()
    pipeline = make_cleaners(tokenizer, stats)

    text = "GET /casAccessManagement/servers/cas-shared-default/SalesData"
    out = process_text(text, pipeline)

    assert "/casAccessManagement/servers/cas-shared-default/SalesData" in out


def test_skips_already_anonymized_files():
    assert should_skip_file(Path("test_anonymized.log"))
    assert not should_skip_file(Path("test.log"))
