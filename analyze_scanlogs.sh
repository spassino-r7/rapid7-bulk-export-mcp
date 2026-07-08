#!/bin/bash
LOG_DIR="$HOME/.kiro/scanlogs"
OUTPUT="$HOME/.kiro/scanlogs/scan_analysis_report.txt"

echo "InsightVM Scan Log Analysis Report" > "$OUTPUT"
echo "Generated: $(date)" >> "$OUTPUT"
echo "============================================================" >> "$OUTPUT"
echo "" >> "$OUTPUT"

for logfile in "$LOG_DIR"/*.log; do
    filename=$(basename "$logfile")
    echo "------------------------------------------------------------" >> "$OUTPUT"
    echo "LOG FILE: $filename" >> "$OUTPUT"
    echo "------------------------------------------------------------" >> "$OUTPUT"

    site=$(grep -m1 "\[Site:" "$logfile" 2>/dev/null | grep -oE '\[Site: [^]]+\]' | head -1 | sed 's/\[Site: //;s/\]//')
    echo "Site: ${site:-Unknown}" >> "$OUTPUT"

    start=$(grep -m1 "Logging initialized" "$logfile" 2>/dev/null | awk '{print $1}')
    echo "Scan Start: ${start:-Unknown}" >> "$OUTPUT"

    engine=$(grep -m1 "NSC @" "$logfile" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo "Engine IP: ${engine:-Unknown}" >> "$OUTPUT"
    echo "" >> "$OUTPUT"

    alive=$(grep -c " ALIVE " "$logfile" 2>/dev/null || echo 0)
    dead=$(grep -c " DEAD " "$logfile" 2>/dev/null || echo 0)
    filtered=$(grep -c "filtered" "$logfile" 2>/dev/null || echo 0)
    echo "--- Discovery ---" >> "$OUTPUT"
    echo "  ALIVE hosts:    $alive" >> "$OUTPUT"
    echo "  DEAD hosts:     $dead" >> "$OUTPUT"
    echo "  FILTERED:       $filtered" >> "$OUTPUT"
    echo "" >> "$OUTPUT"

    mrc=$(grep -c "cannot perform Metasploit" "$logfile" 2>/dev/null); mrc=${mrc//[^0-9]/}; mrc=${mrc:-0}
    echo "--- Scan Engine ---" >> "$OUTPUT"
    if [ "$mrc" -gt 0 ]; then
        echo "  WARNING: Metasploit MRC NOT ENABLED" >> "$OUTPUT"
    else
        echo "  Metasploit MRC: OK" >> "$OUTPUT"
    fi
    echo "" >> "$OUTPUT"

    echo "--- Credential Issues ---" >> "$OUTPUT"
    snmp=$(grep -c "SNMPAuthenticator" "$logfile" 2>/dev/null || echo 0)
    echo "  SNMP auth stack traces: $snmp" >> "$OUTPUT"
    bearer=$(grep -c "No matching fingerprint found for banner: Bearer" "$logfile" 2>/dev/null || echo 0)
    echo "  Bearer token unauthenticated: $bearer" >> "$OUTPUT"
    echo "" >> "$OUTPUT"

    echo "--- Notable Findings ---" >> "$OUTPUT"
    exploited=$(grep -c "vulnerability-test-exploited" "$logfile" 2>/dev/null); exploited=${exploited//[^0-9]/}; exploited=${exploited:-0}
    if [ "$exploited" -gt 0 ]; then
        echo "  *** EXPLOITED checks fired: $exploited ***" >> "$OUTPUT"
    else
        echo "  No exploited checks" >> "$OUTPUT"
    fi

    ecr=$(grep -c "ecr.amazonaws.com" "$logfile" 2>/dev/null); ecr=${ecr//[^0-9]/}; ecr=${ecr:-0}
    [ "$ecr" -gt 0 ] && echo "  ECR endpoints (unauthenticated): $ecr" >> "$OUTPUT"

    echo "" >> "$OUTPUT"
    echo "--- Top 5 DEAD Subnets ---" >> "$OUTPUT"
    grep " DEAD " "$logfile" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn | head -5 | while read count subnet; do
        echo "  $subnet.x  ($count)" >> "$OUTPUT"
    done

    echo "" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
done

total=$(ls "$LOG_DIR"/*.log 2>/dev/null | wc -l | tr -d ' ')
echo "============================================================" >> "$OUTPUT"
echo "Total files analyzed: $total" >> "$OUTPUT"
echo "Done. Report: $OUTPUT"
