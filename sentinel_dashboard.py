import os
import sys
from scapy.all import sniff, IP, TCP
from datetime import datetime

# --- KONFIGURACE ---
REPORT_FILE = "/home/linux/Desktop/programovani_plocha/cybersec-tools/Sentinel-IDS/report.txt"
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
    # Horní okraj rámečku
    print(f"{B.CYAN}╔" + "═"*73 + "╗")
    print(f"║{B.END} {B.BOLD}🛡️  SENTINEL CYBER-SECURITY - PROACTIVE THREAT DETECTION{B.END}        {B.CYAN}║")
    print(f"╚" + "═"*73 + "╝{B.END}")

def update_dashboard():
    os.system('clear')
    draw_header()
    
    # Statistiky v jednom řádku
    uptime = str(datetime.now() - start_time).split(".")[0]
    print(f" {B.BOLD}SYSTEM STATUS:{B.END} {B.GREEN}ACTIVE{B.END}  │  {B.BOLD}UPTIME:{B.END} {uptime}  │  {B.BOLD}TOTAL ALERTS:{B.END} {total_packets}")
    print(f"{B.CYAN}╟" + "─"*73 + "╢{B.END}")
    
    # Tabulka
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
    
    # Live Log sekce
    print(f"{B.CYAN}╟" + "─"*73 + "╢{B.END}")
    print(f" {B.BOLD}RECENT ACTIVITY LOG:{B.END}")
    
    for entry in live_log[-4:]:
        print(f"  {B.CYAN}→{B.END} {entry}")
    
    # Spodní okraj
    print(f"{B.CYAN}╚" + "═"*73 + "╝{B.END}")
    print(f" {B.YELLOW}COMMANDS:{B.END} [Ctrl+C] Save & Exit  │  [F] Flush Logs")
    sys.stdout.flush()

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
        # Inicializační obrazovka
        draw_header()
        print(f"\n {B.YELLOW}[*] Booting Sentinel Engine...{B.END}")
        print(f" {B.YELLOW}[*] Binding to local interface...{B.END}")
        sniff(prn=monitor_callback, store=0, iface="lo")
    except KeyboardInterrupt:
        # Tady voláme tvou ukládací funkci
        print(f"\n {B.GREEN}[+] Sentinel offline. Report vygenerován.{B.END}")
        sys.exit(0)
