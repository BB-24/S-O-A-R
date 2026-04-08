#!/usr/bin/env python3
import json

# Check hack1 report
print("=== HACK1.EXE Report ===")
r1 = json.load(open('artifacts/hack1_report.json'))
iocs1 = r1.get('indicators_of_compromise', [])
print(f"IOCs: {len(iocs1)}")
for i in iocs1[:6]:
    print(f"  {i.get('ioc_type', '')}: {i.get('value', '')}")

# Check reverse_shell report
print("\n=== REVERSE_SHELL.EXE Report ===")
r2 = json.load(open('artifacts/reverse_shell_report.json'))
iocs2 = r2.get('indicators_of_compromise', [])
print(f"IOCs: {len(iocs2)}")
for i in iocs2[:8]:
    print(f"  {i.get('ioc_type', '')}: {i.get('value', '')}")
