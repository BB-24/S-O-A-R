#!/usr/bin/env python3
import json

report = json.load(open('artifacts/hack1_report.json'))
iocs = report.get('indicators_of_compromise', [])
print('IOCs found:', len(iocs))
for ioc in iocs[:10]:
    print(f"  - {ioc.get('ioc_type', '')}: {ioc.get('value', '')}")
