> NetworkRecon - Lightweight Network Reconnaissance Tool

> Video Demonstration

> Overview

NetworkRecon is a compact Bash script for quick, targeted reconnaissance of a single host.  
It performs a lightweight reachability check, TCP port scanning via nmap, optional service/version detection and light NSE vulnerability checks, optional netcat throughput testing, and writes everything to a single text report file.

NOTE: Always scan only systems you own or have explicit authorization to test.

> Key Features

- Single-host, low-impact reconnaissance (fast default scan using nmap -F).
- Optional service/version detection (-s) and light vulnerability scripts (-v).
- Suspicious-port alerting using a configurable default list.
- Single consolidated text report.
- Optional basic netcat throughput test (-n), if nc/pv are available.

> Dependencies
Ens

instructions for install
usage guide with examples
