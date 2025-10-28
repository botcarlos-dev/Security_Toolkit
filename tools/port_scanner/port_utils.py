
"""
port_utils.py


Robust and well-documented utilities for parsing network port specifications
and normalizing host targets. Supports IPv4, IPv6, and domain names.

Author: Carlos Ramos
License: MIT
Date: 2025-10-28

References:
- RFC 3986 (IPv6 validation): https://datatracker.ietf.org/doc/html/rfc3986
- RFC 952 / RFC 1123 (hostname rules): https://datatracker.ietf.org/doc/html/rfc1123
- TCP/UDP port numbers (IANA): https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
- Python regex documentation: https://docs.python.org/3/library/re.html
- PEP 8 (Style Guide): https://peps.python.org/pep-0008/
- PEP 484 (Type Hints): https://peps.python.org/pep-0484/
- Pseudocode Validator: https://chatgpt.com/
- Specific Python error-handling discussion and implementation: https://stackoverflow.com/
"""

import os
import re
from typing import List



# Helper function to remove duplicates while preserving original order

def unique_preserve_order(seq: List[str]) -> List[str]:
    """
    Removes duplicate entries from a sequence while preserving order.

    Args:
        seq (List[str]): Sequence of strings to process.

    Returns:
        List[str]: A list with duplicates removed in their original order.
    """
    seen = set()
    result = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result



# parse_ports(port_spec: str) -> List[int]

def parse_ports(port_spec: str | None) -> List[int]:
    """
    Parses a string representing network ports into a sorted list of unique integers.

    Supports single ports, comma-separated lists, and inclusive ranges (e.g. "20-80").

    Example inputs:
        - "22"
        - "22,80,443"
        - "20-1024"
        - "22,80,1000-1010"

    Example output:
        [22, 80, 443]
        [20, 21, 22, ..., 1024]

    Args:
        port_spec (str | None): Port specification string.
            If None or empty, a default list of common ports is returned.

    Returns:
        List[int]: Sorted list of unique valid port numbers.

    Raises:
        ValueError: If the format is invalid or any port is out of range (1–65535).

    References:
        - IANA Service Names and Port Numbers:
          https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
    """
    if not port_spec:
        # Default common ports
        return [21, 22, 23, 25, 53, 80, 443]

    split_by_comma = [x.strip() for x in port_spec.split(',')]
    final_ports = set()

    for token in split_by_comma:
        if "-" in token:
            # Handle port range (inclusive)
            parts = token.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid range format: '{token}'")
            try:
                start, end = map(int, parts)
            except ValueError:
                raise ValueError(f"Non-numeric range in: '{token}'")
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Port range out of bounds: '{token}'")
            final_ports.update(range(start, end + 1))
        else:
            # Handle single port
            try:
                p = int(token)
            except ValueError:
                raise ValueError(f"Invalid port: '{token}'")
            if p < 1 or p > 65535:
                raise ValueError(f"Port number out of range: {p}")
            final_ports.add(p)

    return sorted(final_ports)



# normalize_targets(target_spec: str | file path) -> List[str]

def normalize_targets(target_spec: str, file_mode: bool = False) -> List[str]:
    """
    Normalizes and validates a list of network targets (hosts or IP addresses).

    This function accepts:
        - A single string with comma-separated targets.
        - A file path containing one target per line.

    Supports:
        - IPv4 (RFC 791)
        - IPv6 (RFC 3986)
        - Hostnames (RFC 952 / RFC 1123)
        - Ignores comments (lines starting with '#') and empty lines.

    Args:
        target_spec (str): Either a comma-separated string or path to a file.
        file_mode (bool, optional): If True, force reading from a file.
            Defaults to False (auto-detect).

    Returns:
        List[str]: List of unique, validated targets (hostnames or IPs).

    Raises:
        ValueError: If no valid targets are found or if the file cannot be read.

    References:
        - RFC 3986 (IPv6 validation): https://datatracker.ietf.org/doc/html/rfc3986
        - RFC 1123 (hostname validation): https://datatracker.ietf.org/doc/html/rfc1123
    """
    targets = []

    # --- Regular expressions for validation ---

    # IPv4 regex (validates 0.0.0.0–255.255.255.255)
    ipv4_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )

    # IPv6 regex (RFC 3986-compliant)
    ipv6_pattern = re.compile(
        r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
        r"([0-9a-fA-F]{1,4}:){1,7}:|"
        r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
        r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
        r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
        r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
        r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
        r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
        r":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
        r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
        r"::(ffff(:0{1,4}){0,1}:){0,1}"
        r"((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}"
        r"(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])|"
        r"([0-9a-fA-F]{1,4}:){1,4}:"
        r"((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}"
        r"(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9]))$"
    )

    # Hostname regex (RFC 952 + RFC 1123)
    hostname_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
    )

    def is_valid_target(t: str) -> bool:
        """Check if a target is a valid IPv4, IPv6, or hostname."""
        return (
            ipv4_pattern.match(t)
            or ipv6_pattern.match(t)
            or hostname_pattern.match(t)
        )

    # --- Read from file or direct input ---
    if file_mode or os.path.isfile(target_spec):
        try:
            with open(target_spec, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if is_valid_target(line):
                        targets.append(line)
        except OSError as e:
            raise ValueError(f"Error reading file '{target_spec}': {e}")
    else:
        for token in target_spec.split(","):
            token = token.strip()
            if not token or token.startswith("#"):
                continue
            if is_valid_target(token):
                targets.append(token)

    if not targets:
        raise ValueError("No valid targets found")

    return unique_preserve_order(targets)
