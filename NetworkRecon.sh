#!/usr/bin/env bash
# Requirements: nmap (required). Optional: nc (netcat), pv (for netcat progress)
# Example: ./NetworkRecon.sh -t 10.10.11.143 -s -v -o quick_report.txt
# NOTE: Only scan systems you are authorized to test.

# Exit script on any error & avoid splitting on spaces
set -euo pipefail
IFS=$'\n\t'

# Set program name for errors & set timestamp for filenames
PROGNAME=$(basename "$0")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Flags/defaults
TARGET=""            # required
SERVICE_DETECT=0     # -s : use -sV
VULN_CHECK=0         # -v : run --script vuln
NETCAT_TEST=0        # -n : netcat throughput test (client)
NC_PEER=""           # ip:port for netcat send test
OUTPUT=""            # -o output file (single file)
FAST_SCAN=1          # default to -F fast scan
PORTS=""             # -p custom ports (comma separated)
SUSPICIOUS=(21 22 23 69 161 445 3389 5900 5060)  # ports to alert on, can be changed depending on purpose

# Parse args
while getopts ":t:svp:n:o:h" opt; do
  case "$opt" in
    t) TARGET=$OPTARG ;;
    s) SERVICE_DETECT=1 ;;
    v) VULN_CHECK=1 ;;
    p) PORTS=$OPTARG; FAST_SCAN=0 ;;
    n) NETCAT_TEST=1; NC_PEER=$OPTARG ;;
    o) OUTPUT=$OPTARG ;;
    h)
      echo "Usage: $PROGNAME -t <target> [-s] [-v] [-p <ports>] [-n <ip:port>] [-o <outfile>]"
      exit 0
      ;;
    \?) echo "ERROR: Invalid option -$OPTARG" >&2; exit 2 ;;
    :) echo "ERROR: Option -$OPTARG requires an argument." >&2; exit 2 ;;
  esac
done

# Require target or fail
if [[ -z "$TARGET" ]]; then
  echo "ERROR: target required. Example: $PROGNAME -t 192.168.1.5" >&2
  exit 2
fi

# Single output file default
if [[ -z "$OUTPUT" ]]; then
  safe_target=$(echo "$TARGET" | sed 's/[^A-Za-z0-9._-]/_/g')
  OUTPUT="report_${safe_target}_${TIMESTAMP}.txt"
fi

# Helper
log() { printf '[%s] %s\n' "$(date +'%F %T')" "$*"; }

# Initialize report (single file)
{
  echo "NetworkRecon Report"
  echo "Target: $TARGET"
  echo "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%SZ")"
  echo ""
} > "$OUTPUT"

log "Starting quick reconnaissance for $TARGET" | tee -a "$OUTPUT"

# 1) Reachability (ping) — continue even if ping fails
log "Checking reachability (ICMP ping)..." | tee -a "$OUTPUT"
if ping -c 2 -W 2 "$TARGET" &>/dev/null; then
  echo "Reachable: yes (ping responded)" | tee -a "$OUTPUT"
else
  echo "Reachable: no (ICMP blocked or host down). Continuing with TCP scans." | tee -a "$OUTPUT"
fi
echo "" >> "$OUTPUT"

# 2) Build nmap command(s)
NMAP_BASE="nmap -n -Pn -sT"  # TCP connect, no ping required
NMAP_PORTS_ARG="-F"
if [[ $FAST_SCAN -eq 0 ]]; then
  NMAP_PORTS_ARG="-p ${PORTS}"
fi

if [[ $SERVICE_DETECT -eq 1 ]]; then
  NMAP_BASE="$NMAP_BASE -sV --version-intensity 2"
fi

if [[ $VULN_CHECK -eq 1 ]]; then
  NMAP_SCRIPTS="--script vuln"
else
  NMAP_SCRIPTS=""
fi

# 2a) Nmap summary (greppable)
NMAP_SUMMARY_CMD="$NMAP_BASE $NMAP_PORTS_ARG $NMAP_SCRIPTS $TARGET -oG - --open"

log "Running nmap summary (greppable)..." | tee -a "$OUTPUT"
log "Command: $NMAP_SUMMARY_CMD" | tee -a "$OUTPUT"
echo "" >> "$OUTPUT"
echo "=== Nmap Summary (open ports/services) ===" >> "$OUTPUT"
# run summary and append (don't exit on nmap non-zero)
if eval "$NMAP_SUMMARY_CMD" 2>/dev/null | tee -a "$OUTPUT" | awk '/Ports:/{print}' >> "$OUTPUT" 2>/dev/null; then
  true
else
  echo "(nmap summary finished; host filtered or no open ports visible.)" >> "$OUTPUT"
fi
echo "" >> "$OUTPUT"

# 2b) Full nmap output appended to the same single report file
echo "=== Full nmap output ===" >> "$OUTPUT"
log "Appending full nmap output to single report..." | tee -a "$OUTPUT"
# run full nmap and append; allow failure but continue
if ! eval "$NMAP_BASE $NMAP_PORTS_ARG $NMAP_SCRIPTS $TARGET -oN - 2>/dev/null" | sed 's/$/\n/' >> "$OUTPUT"; then
  echo "(Warning: full nmap run failed or nmap not present.)" >> "$OUTPUT"
fi
echo "" >> "$OUTPUT"

# 3) Parse open ports from the appended nmap output (search inside OUTPUT)
echo "=== Parsed Open Ports ===" >> "$OUTPUT"
# try to extract lines like "22/tcp open ssh ..."
grep -E '^[0-9]+/tcp' "$OUTPUT" | sed 's/\/tcp//g' | awk '{print $1 " -> " substr($0, index($0,$2))}' >> "$OUTPUT" || echo "(no parsed open ports found)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# 4) Suspicious port alerts (based on parsed lines above)
echo "=== Suspicious Port Alerts ===" >> "$OUTPUT"
alerted=0
while IFS= read -r line; do
  port=$(echo "$line" | awk '{print $1}' | sed 's/\/tcp//g' || true)
  for sp in "${SUSPICIOUS[@]}"; do
    if [[ "$port" == "$sp" ]]; then
      echo "ALERT: suspicious/insecure port $port open on $TARGET -> $line" >> "$OUTPUT"
      alerted=1
    fi
  done
done < <(grep -E '^[0-9]+/tcp' "$OUTPUT" || true)
if [[ $alerted -eq 0 ]]; then
  echo "No suspicious ports from the default alert list detected." >> "$OUTPUT"
fi
echo "" >> "$OUTPUT"

# 5) Optional netcat throughput test appended to single report
if [[ $NETCAT_TEST -eq 1 ]]; then
  echo "=== Netcat Throughput Test ===" >> "$OUTPUT"
  if [[ -z "$NC_PEER" ]]; then
    echo "Netcat peer not specified. Use -n ip:port" >> "$OUTPUT"
  else
    ip=${NC_PEER%%:*}
    port=${NC_PEER##*:}
    if command -v pv >/dev/null 2>&1; then
      echo "Sending 5MB to $NC_PEER (pv used for progress) ..." >> "$OUTPUT"
      (dd if=/dev/zero bs=1M count=5 2>/dev/null | pv -s 5M) | nc "$ip" "$port" 2>>"$OUTPUT" || echo "nc client finished or failed" >> "$OUTPUT"
    else
      echo "pv not installed; doing basic 5MB nc transfer to $NC_PEER" >> "$OUTPUT"
      dd if=/dev/zero bs=1M count=5 2>/dev/null | nc "$ip" "$port" 2>>"$OUTPUT" || echo "nc client finished or failed" >> "$OUTPUT"
    fi
  fi
  echo "" >> "$OUTPUT"
fi

# 6) Final notes
{
  echo "=== Notes & Next Steps ==="
  echo "- This single-file report contains summary + full nmap output + parsed sections."
  echo "- For deeper checks, consider nmap -sV -O -p- or a dedicated vulnerability scanner."
  echo "- If -v was used (vuln scripts) results may require manual verification."
  echo "- Always have authorization before scanning networks you do not own."
} >> "$OUTPUT"

log "Report written to: $OUTPUT"
echo ""
# print the report to stdout
cat "$OUTPUT"
