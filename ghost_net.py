import os
import sys
from scapy.all import sniff, IP, TCP
from datetime import datetime

# --- KONFIGURACE ---
REPORT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.txt")
threat_actors = {}
live_log = []
total_packets = 0

class B:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def draw_header():
    print(f"{B.CYAN}╔" + "═"*73 + "╗")
    print(f"║{B.END} {B.BOLD}👻  GHOST-NET CYBER-SECURITY - PROACTIVE THREAT DETECTION{B.END}       {B.CYAN}║")
    print(f"╚" + "═"*73 + "╝{B.END}")

def update_dashboard():
    os.system('clear')
    draw_header()

    uptime = str(datetime.now() - start_time).split(".")[0]
    print(f" {B.BOLD}SYSTEM STATUS:{B.END} {B.GREEN}ACTIVE{B.END}  │  {B.BOLD}UPTIME:{B.END} {uptime}  │  {B.BOLD}TOTAL ALERTS:{B.END} {total_packets}")
    print(f"{B.CYAN}╟" + "─"*73 + "╢{B.END}")

    print(f" {B.BOLD}{'SOURCE IP':<18} │ {'ATTEMPTS':<10} │ {'LAST PORT':<10} │ {'RISK LEVEL'}{B.END}")
    print(f" " + "─"*71)

    for ip, data in threat_actors.items():
        if data['count'] > 50:
            lvl, col = "!! CRITICAL !!", B.RED
        elif data['count'] > 10:
            lvl, col = "WARNING", B.YELLOW
        else:
            lvl, col = "STABLE", B.GREEN

        print(f" {col}{ip:<18}{B.END} │ {data['count']:<10} │ {data['port']:<10} │ {col}{lvl}{B.END}")

    print(f"{B.CYAN}╟" + "─"*73 + "╢{B.END}")
    print(f" {B.BOLD}RECENT ACTIVITY LOG:{B.END}")

    for entry in live_log[-4:]:
        print(f"  {B.CYAN}→{B.END} {entry}")

    print(f"{B.CYAN}╚" + "═"*73 + "╝{B.END}")
    print(f" {B.YELLOW}COMMANDS:{B.END} [Ctrl+C] Save & Exit  │  [F] Flush Logs")
    sys.stdout.flush()

def generate_report():
    try:
        with open(REPORT_FILE, "w") as f:
            f.write("=" * 60 + "\n")
            f.write("👻  GHOST-NET CYBER-SECURITY INCIDENT REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"End:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 60 + "\n")
            f.write(f"{'SOURCE IP':<15} | {'ATTEMPTS':<10} | {'LAST PORT'}\n")
            f.write("-" * 60 + "\n")
            for ip, data in threat_actors.items():
                f.write(f"{ip:<15} | {data['count']:<10} | {data['port']}\n")
            f.write("=" * 60 + "\n")
        os.chmod(REPORT_FILE, 0o666)
        print(f"\n {B.GREEN}[+] Ghost-Net offline. Report saved to: {REPORT_FILE}{B.END}")
    except Exception as e:
        print(f"\n {B.RED}[!] Failed to save report: {e}{B.END}")

def monitor_callback(pkt):
    global total_packets
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        total_packets += 1
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport

        if src_ip not in threat_actors:
            threat_actors[src_ip] = {'count': 0, 'port': 0}
        threat_actors[src_ip]['count'] += 1
        threat_actors[src_ip]['port'] = dst_port

        msg = f"{datetime.now().strftime('%H:%M:%S')} - Alert: SYN on port {dst_port} from {src_ip}"
        live_log.append(msg)
        update_dashboard()

if __name__ == "__main__":
    start_time = datetime.now()
    try:
        os.system('clear')
        draw_header()
        print(f"\n {B.YELLOW}[*] Booting Ghost-Net Engine...{B.END}")
        print(f" {B.YELLOW}[*] Binding to local interface...{B.END}")
        sniff(prn=monitor_callback, store=0, iface="lo")
    except KeyboardInterrupt:
        generate_report()
        sys.exit(0)
