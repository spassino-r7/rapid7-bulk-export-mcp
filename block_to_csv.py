#!/usr/bin/env python3
"""
block_to_csv.py — Convert block-formatted ticket data to CSV.

Each block has a fixed number of lines per record, starting with a SESE- ticket number.

Usage:
  python3 block_to_csv.py input.txt output.csv
"""

import csv
import sys


# Column headers matching the block field order
HEADERS = [
    "Ticket",
    "Owner",
    "SE",
    "Date Opened",
    "Status",
    "Segment",
    "Customer",
    "Description",
    "Region",
    "Product",
    "Type",
    "Amount",
    "Renewal Date",
    "Lines",
]

FIELDS_PER_RECORD = len(HEADERS)


def parse_blocks(input_file):
    """Read the file and split into records based on field count."""
    with open(input_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    records = []
    for i in range(0, len(lines), FIELDS_PER_RECORD):
        block = lines[i:i + FIELDS_PER_RECORD]
        if len(block) == FIELDS_PER_RECORD and block[0].startswith("SESE-"):
            records.append(block)
        elif len(block) > 0 and block[0].startswith("SESE-"):
            # Partial block at end — pad with empty strings
            block.extend([""] * (FIELDS_PER_RECORD - len(block)))
            records.append(block)

    return records


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} input.txt [output.csv]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file.rsplit(".", 1)[0] + ".csv"

    records = parse_blocks(input_file)

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        writer.writerows(records)

    print(f"Converted {len(records)} records → {output_file}")


if __name__ == "__main__":
    main()
