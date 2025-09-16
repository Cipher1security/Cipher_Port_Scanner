import argparse
import socket
import time
import csv
import json
import ipaddress
import errno
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S"
)


def parse_line_to_ips(line, include_network=False):
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    try:
        if "/" in line:
            net = ipaddress.ip_network(line, strict=False)
            return [str(ip) for ip in (net if include_network else net.hosts())] or [str(net.network_address)]
        if "-" in line:
            left, right = [p.strip() for p in line.split("-", 1)]
            left_ip = ipaddress.ip_address(left)
            try:
                right_ip = ipaddress.ip_address(right)
                return [str(ipaddress.ip_address(i)) for i in range(int(left_ip), int(right_ip)+1)]
            except ValueError:
                parts = left.split(".")
                if len(parts) == 4 and right.isdigit():
                    start, end = int(parts[3]), int(right)
                    if 0 <= start <= end <= 255:
                        return [f"{'.'.join(parts[:3])}.{i}" for i in range(start, end+1)]
        else:
            return [str(ipaddress.ip_address(line))]
    except ValueError:
        try:
            infos = socket.getaddrinfo(line, None)
            return list({info[4][0] for info in infos})
        except Exception:
            return []
    return []

def parse_ports(ports_str):
    ports = set()
    for part in ports_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end+1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def check_port(ip, port, timeout):
    start = time.time()
    sock = None
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((ip, port))
        elapsed = round((time.time() - start) * 1000.0, 1)

        if err == 0:
            status, reason, color = "open", "connected", Fore.GREEN
        elif err == errno.ECONNREFUSED:
            status, reason, color = "closed", "connection_refused", Fore.RED
        else:
            status, reason, color = "filtered", f"err_{err}", Fore.YELLOW

        return dict(ip=ip, port=port, status=status, reason=reason, elapsed_ms=elapsed, color=color)

    except socket.timeout:
        return dict(ip=ip, port=port, status="filtered", reason="timeout",
                    elapsed_ms=round((time.time()-start)*1000, 1), color=Fore.YELLOW)
    except Exception as e:
        return dict(ip=ip, port=port, status="error", reason=repr(e),
                    elapsed_ms=round((time.time()-start)*1000, 1), color=Fore.BLUE)
    finally:
        if sock:
            sock.close()


def get_interactive_input():
    logo = r"""
  ______      __             ___           __    ____                          
 / ___(_)__  / /  ___ ____  / _ \___  ____/ /_  / __/______ ____  ___  ___ ____
/ /__/ / _ \/ _ \/ -_) __/ / ___/ _ \/ __/ __/ _\ \/ __/ _ `/ _ \/ _ \/ -_) __/
\___/_/ .__/_//_/\__/_/   /_/   \___/_/  \__/ /___/\__/\_,_/_//_/_//_/\__/_/   
     /_/                                                                       

            Cipher TCP Port Scanner - v1.0.0
    """
    github = "github: Cipher1security"

    print(Fore.CYAN + logo + Style.RESET_ALL + "\n" + Fore.GREEN + github + Style.RESET_ALL + "\n")

    input_file = input("Enter input file path (leave blank to enter IPs manually): ").strip()
    ips = []
    if input_file:
        try:
            with open(input_file, "r", encoding="utf-8") as f:
                for raw in f:
                    ips.extend(parse_line_to_ips(raw))
        except FileNotFoundError:
            print(f"File not found: {input_file}")
            return None
    else:
        while True:
            ip = input("Enter IP / hostname (or leave blank to finish): ").strip()
            if not ip:
                break
            ips.extend(parse_line_to_ips(ip))

    ips = list(dict.fromkeys(ips))
    print(f"\nTotal IPs: {len(ips)}\n")

    ports = input("Enter port(s) to scan (e.g., 22,80,443 or 20-25): ").strip()
    timeout = input("Enter connection timeout in seconds [default 3.0]: ").strip()
    timeout = float(timeout) if timeout else 3.0
    workers = input("Enter number of concurrent workers [default 200]: ").strip()
    workers = int(workers) if workers else 200
    output = input("Enter CSV output file name [default results.csv]: ").strip() or "results.csv"

    save_json = input("Save results as JSON? (y/n) [default n]: ").strip().lower() == 'y'
    json_file = ""
    if save_json:
        json_file = input("Enter JSON output file name [default results.json]: ").strip() or "results.json"

    save_open = input("Save only open ports? (y/n) [default n]: ").strip().lower() == 'y'
    open_file = ""
    if save_open:
        open_file = input("Enter open ports output file (CSV or TXT) [default open_ports.txt]: ").strip() or "open_ports.txt"

    return argparse.Namespace(
        input=None,
        ips=ips,
        port=ports,
        timeout=timeout,
        workers=workers,
        output=output,
        json=json_file if save_json else None,
        open=open_file if save_open else None
    )

def main(args):
    if hasattr(args, "ips"):
        ips = args.ips
    else:
        ips = []
        with open(args.input, "r", encoding="utf-8") as f:
            for raw in f:
                ips.extend(parse_line_to_ips(raw))
    ips = list(dict.fromkeys(ips))
    logging.info(f"Parsed {len(ips)} unique IPs")

    ports = parse_ports(args.port)
    logging.info(f"Ports to scan: {ports}")

    results = []
    open_results = []
    total = len(ips) * len(ports)
    workers = min(args.workers, max(4, total))
    logging.info(f"Scanning {total} targets with timeout {args.timeout}s using {workers} workers")

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(check_port, ip, port, args.timeout): (ip, port) for ip in ips for port in ports}
        for i, fut in enumerate(as_completed(futures), 1):
            res = fut.result()
            results.append(res)
            if res['status'] == 'open':
                open_results.append(res)
            color = res.pop("color")
            print(f"{color}[{i}/{total}] {res['ip']}:{res['port']} -> {res['status']} ({res['reason']}) {res['elapsed_ms']}ms{Style.RESET_ALL}")

    results.sort(key=lambda r: (r["ip"], r["port"]))
    open_results.sort(key=lambda r: (r["ip"], r["port"]))

    with open(args.output, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=["ip", "port", "status", "reason", "elapsed_ms"])
        writer.writeheader()
        writer.writerows(results)
    logging.info(f"All results saved to {args.output}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(results, jf, indent=2)
        logging.info(f"All results also saved to {args.json}")

    if args.open:
        ext = os.path.splitext(args.open)[1].lower()
        if ext == ".csv":
            with open(args.open, "w", newline="", encoding="utf-8") as csvf:
                writer = csv.DictWriter(csvf, fieldnames=["ip", "port"])
                writer.writeheader()
                for r in open_results:
                    writer.writerow({"ip": r["ip"], "port": r["port"]})
            logging.info(f"Open ports saved to CSV {args.open}")
        else:
            with open(args.open, "w", encoding="utf-8") as f:
                for r in open_results:
                    f.write(f"{r['ip']}:{r['port']}\n")
            logging.info(f"Open ports saved to TXT {args.open}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Cipher Port Scanner - v1.0.0: fast TCP port scanning for IPs / ranges / CIDR / hostnames from a file",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-i", "--input", help="Input file (IP / hostname / range / CIDR, one per line)")
    parser.add_argument("-p", "--port", help="Port(s) to test, e.g., 22, 80, 443 or 20-25")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Connection timeout in seconds (default 3.0)")
    parser.add_argument("-w", "--workers", type=int, default=200, help="Number of concurrent workers (default 200)")
    parser.add_argument("-o", "--output", default="results.csv", help="CSV output file (default results.csv)")
    parser.add_argument("--json", help="Optional: save results as JSON")
    parser.add_argument("--open", help="Optional: save only open ports to TXT or CSV file")

    args = parser.parse_args()

    if not args.input or not args.port:
        args = get_interactive_input()

    main(args)
