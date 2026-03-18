import sys
import time
from scapy.all import IP, TCP, send

# Cilime na localhost (sami na sebe)
target_ip = "127.0.0.1" 

print(f"[*] SPUSTENO: Simulace utoku na {target_ip}")
print("[*] Posilam TCP SYN pakety na porty 1-100...")

try:
    for port in range(1, 101):
        # Vytvorime paket (IP vrstva + TCP SYN priznak)
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        
        # Odeslani (verbose=False skryje systemove vypisy Scapy)
        send(pkt, verbose=False)
        
        if port % 20 == 0:
            print(f"[>] Proskenovano {port} portu...")
        
        # Krátká pauza pro plynulost Dashboardu
        time.sleep(0.1)

    print("\n[+] Simulace dokoncena. Zkontroluj Sentinel Dashboard!")

except PermissionError:
    print("\n[!] CHYBA: Musis spustit jako SUDO!")
except Exception as e:
    print(f"\n[!] Neocekavana chyba: {e}")
