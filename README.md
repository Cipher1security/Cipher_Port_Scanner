# Cipher_Port_Scanner
Cipher Port Scanner

A fast and flexible multi-port TCP scanner
It supports scanning IPs, hostnames, CIDR ranges, or manual input, with concurrent threads and colored output

---

## Features

- Scan single IPs, hostnames, ranges (`192.168.1.1-192.168.1.10`) or CIDR (`192.168.1.0/24`)
- Scan single or multiple ports (e.g., `22,80,443` or `20-25`)
- Concurrent scanning using threads for speed
- Color-coded console output
- Save results to CSV, JSON, or list only open ports
- Interactive input mode or via command-line arguments

---

## Usage

```bash
git clone https://github.com/Cipher1security/Cipher_Port_Scanner.git

cd Cipher_Port_Scanner

python3 cipher_port_scanner.py
```
#### Help

```bash
python3 cipher_port_scanner.py -h
```
Install dependencies:

```bash
pip install -r requirements.txt
```
