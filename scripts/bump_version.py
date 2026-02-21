#!/usr/bin/env python3
"""
Automatically bump the version in pyproject.toml.

Usage:
  python scripts/bump_version.py [patch|minor|major]
"""

import argparse
import re
import sys
from pathlib import Path


def bump_version(current_version: str, bump_type: str) -> str:
    """Increment the version string."""
    parts = current_version.split(".")

    if len(parts) != 3:
        raise ValueError(f"Version string '{current_version}' is not in expected format x.y.z")

    try:
        major, minor, patch = map(int, parts)
    except ValueError as e:
        raise ValueError(f"Version components in '{current_version}' must be integers") from e

    if bump_type == "major":
        major += 1
        minor = 0
        patch = 0
    elif bump_type == "minor":
        minor += 1
        patch = 0
    elif bump_type == "patch":
        patch += 1
    else:
        raise ValueError(f"Unknown bump type: {bump_type}")

    return f"{major}.{minor}.{patch}"


def main():
    parser = argparse.ArgumentParser(description="Bump version in pyproject.toml")
    parser.add_argument(
        "type",
        choices=["major", "minor", "patch"],
        default="patch",
        nargs="?",
        help="Type of version bump (default: patch)",
    )
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    pyproject_path = project_root / "pyproject.toml"

    if not pyproject_path.exists():
        print(f"Error: Could not find {pyproject_path}", file=sys.stderr)
        sys.exit(1)

    content = pyproject_path.read_text(encoding="utf-8")

    # regex to find version = "x.y.z"
    version_pattern = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
    match = version_pattern.search(content)

    if not match:
        print("Error: Could not find version string in pyproject.toml", file=sys.stderr)
        sys.exit(1)

    current_version = match.group(1)

    try:
        new_version = bump_version(current_version, args.type)
    except ValueError as e:
        print(f"Error bumping version: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Bumping version from {current_version} to {new_version}")

    new_content = content[: match.start(1)] + new_version + content[match.end(1) :]
    pyproject_path.write_text(new_content, encoding="utf-8")


if __name__ == "__main__":
    main()
