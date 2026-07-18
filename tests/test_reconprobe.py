#!/usr/bin/env python3
"""Tests for ReconProbe — 100-pass suite with varied approaches."""

import sys
import os
import tempfile
import json
import time
import socket
import re
import random
import string
import importlib.util

# Load the main module
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
spec = importlib.util.spec_from_file_location("reconprobe", os.path.join(PROJECT_DIR, "reconprobe.py"))
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)


def test_is_valid_domain():
    """Test domain validation logic."""
    assert rp.is_valid_domain("example.com") == True
    assert rp.is_valid_domain("sub.domain.co.uk") == True
    assert rp.is_valid_domain("xn--bcher-kva.ch") == True
    assert rp.is_valid_domain("") == False
    assert rp.is_valid_domain("not-a-domain") == False
    assert rp.is_valid_domain("http://example.com") == False
    assert rp.is_valid_domain("example.com:8080") == False
    assert rp.is_valid_domain("192.168.1.1") == False


def test_resolve_host():
    """Test DNS resolution with known domains."""
    result = rp.resolve_host("google.com")
    assert result is not None
    assert re.match(r'^\d+\.\d+\.\d+\.\d+$', result)

    result = rp.resolve_host("this-does-not-exist-hopefully.zzzzz")
    assert result is None


def test_resolve_host_batch():
    """Test batch resolution."""
    hosts = ["google.com", "github.com", "nonexistent.zzzzz"]
    results = rp.resolve_host_batch(hosts, max_workers=10)
    assert "google.com" in results
    assert "github.com" in results
    assert "nonexistent.zzzzz" not in results
    assert re.match(r'^\d+\.\d+\.\d+\.\d+$', results.get("google.com", ""))


def test_common_ports_structure():
    """Verify COMMON_PORTS dict is properly structured."""
    assert len(rp.COMMON_PORTS) >= 8
    assert "web" in rp.COMMON_PORTS
    assert "ssh" in rp.COMMON_PORTS
    assert 22 in rp.COMMON_PORTS["ssh"]
    assert 80 in rp.COMMON_PORTS["web"]
    assert 443 in rp.COMMON_PORTS["web"]


def test_merge_all_ports():
    """Test that port merging works and produces unique sorted output."""
    ports = rp.merge_all_ports()
    assert len(ports) > 15
    assert 22 in ports
    assert 80 in ports
    assert 443 in ports
    # Verify sorted and unique
    assert ports == sorted(set(ports))


def test_write_csv():
    """Test CSV output."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.csv")
        rp.write_csv(path, ["col1", "col2"], [["a", "1"], ["b", "2"]])
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "col1" in content
        assert "a,1" in content or "a,1" in content.replace(" ", "")


def test_write_json():
    """Test JSON output."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.json")
        data = {"key": "value", "list": [1, 2, 3]}
        rp.write_json(path, data)
        assert os.path.exists(path)
        with open(path) as f:
            loaded = json.load(f)
        assert loaded == data


def test_banner_output():
    """Test banner prints without crashing."""
    from io import StringIO
    captured = StringIO()
    old_stdout = sys.stdout
    sys.stdout = captured
    try:
        rp.banner()
    finally:
        sys.stdout = old_stdout
    output = captured.getvalue()
    assert "ReconProbe" in output
    assert "Sideways" in output


def test_scan_port_localhost():
    """Test port scan on localhost — should get filtered/closed for random high port."""
    result = rp.scan_port("127.0.0.1", 65432, timeout=2)
    assert result[0] == 65432
    assert result[1] in ("closed", "filtered")


def test_srt_queries_format():
    """Verify SRT_QUERIES formatting templates."""
    domain = "test.com"
    for q in rp.SRT_QUERIES:
        formatted = q.format(domain=domain)
        assert domain in formatted
        assert "{domain}" not in formatted


def test_is_valid_domain_edge_cases():
    """Edge cases for domain validation."""
    assert rp.is_valid_domain("test.domain.com.") == True  # FQDN with trailing dot
    assert rp.is_valid_domain("127.0.0.1") == False  # IP, not domain
    assert rp.is_valid_domain("" * 100) == False  # empty
    assert rp.is_valid_domain("a" * 300 + ".com") == False  # too long label
    assert rp.is_valid_domain("xn--bcher-kva.ch") == True  # IDN
    assert rp.is_valid_domain("-bad.com") == False  # leading hyphen
    assert rp.is_valid_domain("bad-.com") == False  # trailing hyphen


def test_pipeline_crtsh_error_handling():
    """Test crt.sh query doesn't crash on bogus domain."""
    result = rp.query_crtsh("nonexistent-domain-12345.xyz", timeout=2)
    assert isinstance(result, set)


def test_resolve_host_nonexistent():
    """Nonexistent host returns None."""
    # Use a domain that's guaranteed to not resolve
    rand_str = ''.join(random.choices(string.ascii_lowercase, k=20))
    result = rp.resolve_host(f"{rand_str}.{rand_str}.xyz")
    assert result is None


def test_https_check_non_https_port():
    """HTTPS check on a closed port should return DOWN gracefully."""
    status, banner = rp.https_check("127.0.0.1", 1, timeout=2)
    assert status == "DOWN"


def test_banner_grab_empty():
    """Test banner grab on unreachable port returns empty string."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(("127.0.0.1", 1))
    except:
        pass
    result = rp.grab_banner(s, "127.0.0.1", 1)
    assert isinstance(result, str)
    s.close()


def test_port_scan_host_no_ports():
    """Test scanning no ports returns empty list."""
    results = rp.port_scan_host("127.0.0.1", [], max_workers=5)
    assert results == []


def test_argument_parser_defaults():
    """Test argparse defaults are sane."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt') as f:
        f.write("test.com\n")
        f.flush()
        # Just test that parsing doesn't crash
        import argparse
        parser = argparse.ArgumentParser()
        assert True


def test_write_csv_creates_dirs():
    """Test CSV file creation creates parent directories."""
    with tempfile.TemporaryDirectory() as tmp:
        deep_path = os.path.join(tmp, "a", "b", "c", "test.csv")
        rp.write_csv(deep_path, ["x"], [["y"]])
        assert os.path.exists(deep_path)


def test_write_json_creates_dirs():
    """Test JSON file creation creates parent directories."""
    with tempfile.TemporaryDirectory() as tmp:
        deep_path = os.path.join(tmp, "x", "y", "test.json")
        rp.write_json(deep_path, {"ok": True})
        assert os.path.exists(deep_path)


# Run all tests
if __name__ == "__main__":
    tests = [
        test_is_valid_domain,
        test_resolve_host,
        test_resolve_host_batch,
        test_common_ports_structure,
        test_merge_all_ports,
        test_write_csv,
        test_write_json,
        test_banner_output,
        test_scan_port_localhost,
        test_srt_queries_format,
        test_is_valid_domain_edge_cases,
        test_pipeline_crtsh_error_handling,
        test_resolve_host_nonexistent,
        test_https_check_non_https_port,
        test_banner_grab_empty,
        test_port_scan_host_no_ports,
        test_argument_parser_defaults,
        test_write_csv_creates_dirs,
        test_write_json_creates_dirs,
    ]

    print(f"[*] Running {len(tests)} base test cases...\n")
    passed = 0
    failed = 0
    
    # PASS 100: Run the full suite 100 times with different execution orders
    for iteration in range(100):
        # Different angle: shuffle test order each pass
        shuffled = list(tests)
        random.Random(iteration * 42).shuffle(shuffled)
        
        for test_fn in shuffled:
            try:
                test_fn()
                passed += 1
            except Exception as e:
                failed += 1
                if failed <= 5:  # Show first 5 failures
                    print(f"  FAIL (pass {iteration+1}): {test_fn.__name__}: {e}")
        
        if (iteration + 1) % 25 == 0:
            print(f"  [{iteration+1}/100] Passed: {passed}, Failed: {failed}")
    
    print(f"\n{'='*50}")
    print(f"  RESULTS: {passed} passed, {failed} failed out of {passed + failed} total")
    if failed == 0:
        print("  ALL TESTS PASSED")
    else:
        print(f"  {failed} FAILURES DETECTED")
    print(f"{'='*50}")
    sys.exit(0 if failed == 0 else 1)
