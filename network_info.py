"""
Network Info Tool - Windows 11
Reliable LLDP + CDP capture using raw Scapy with explicit interface selection.
Run as Administrator.
"""

import tkinter as tk
from tkinter import ttk
import threading
import subprocess
import re
import time
import ctypes
import struct

try:
    import scapy.all as scapy
    from scapy.all import conf, get_if_list, Ether, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


BG      = "#0f172a"
CARD    = "#1e293b"
ACCENT  = "#38bdf8"
ACCENT2 = "#818cf8"
GREEN   = "#4ade80"
YELLOW  = "#facc15"
RED     = "#f87171"
TEXT    = "#f1f5f9"
SUBTEXT = "#94a3b8"


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def get_ip_info():
    result = {"ip": "—", "subnet": "—", "gateway": "—",
              "dns": "—", "interface": "—", "mac": "—", "ipv6": "—"}
    try:
        out = subprocess.check_output("ipconfig /all", shell=True,
                                      encoding='utf-8', errors='replace')
        sections = re.split(r'\r?\n(?=\S)', out)
        for section in sections:
            if re.search(r'Ethernet adapter', section, re.IGNORECASE) and \
               not re.search(r'vEthernet|Loopback|Bluetooth', section, re.IGNORECASE):
                m = re.search(r'Ethernet adapter (.+?):', section)
                if m: result["interface"] = m.group(1).strip()
                m = re.search(r'Physical Address[.\s]+:\s*([\w-]+)', section)
                if m: result["mac"] = m.group(1).strip()
                m = re.search(r'IPv4 Address[.\s]+:\s*([\d.]+)', section)
                if m: result["ip"] = m.group(1).replace('(Preferred)', '').strip()
                m = re.search(r'Subnet Mask[.\s]+:\s*([\d.]+)', section)
                if m: result["subnet"] = m.group(1).strip()
                m = re.search(r'Default Gateway[.\s]+:\s*([\d.]+)', section)
                if m: result["gateway"] = m.group(1).strip()
                m = re.findall(r'DNS Servers[.\s]+:\s*([\d.a-fA-F:]+)', section)
                if m: result["dns"] = m[0].strip()
                m = re.search(r'IPv6 Address[.\s]+:\s*([a-fA-F0-9:]+)', section)
                if m: result["ipv6"] = m.group(1).strip()
                if result["ip"] != "—":
                    break
    except Exception as e:
        result["error"] = str(e)
    return result


def get_all_interfaces():
    ifaces = []
    try:
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            name = iface.get('name', '')
            desc = iface.get('description', '') or iface.get('friendlyname', '') or name
            ifaces.append((name, desc))
    except Exception:
        try:
            for name in get_if_list():
                ifaces.append((name, name))
        except:
            pass
    return ifaces


def get_ethernet_interfaces():
    all_ifaces = get_all_interfaces()
    eth = []
    for name, desc in all_ifaces:
        combined = (name + desc).lower()
        if any(k in combined for k in ['ethernet', 'realtek', 'intel', 'aquantia',
                                        'usb', 'asix', 'ax88', 'gigabit', 'lan']):
            if not any(k in combined for k in ['wifi', 'wireless', 'wi-fi',
                                                'bluetooth', 'loopback', 'tunnel',
                                                'vpn', 'virtual', 'hyper-v']):
                eth.append((name, desc))
    return eth if eth else [(n, d) for n, d in all_ifaces
                             if not any(k in (n+d).lower()
                                        for k in ['wifi','wireless','loopback','bluetooth'])]


def parse_lldp(raw_bytes):
    info = {"protocol": "LLDP", "switch_name": None, "switch_port": None,
            "vlan_id": None, "system_desc": None}
    try:
        pos = 0
        while pos + 2 <= len(raw_bytes):
            word = struct.unpack('!H', raw_bytes[pos:pos+2])[0]
            tlv_type = (word >> 9) & 0x7F
            tlv_len  = word & 0x1FF
            pos += 2
            if pos + tlv_len > len(raw_bytes):
                break
            value = raw_bytes[pos:pos + tlv_len]
            pos += tlv_len
            if tlv_type == 0:
                break
            elif tlv_type == 2 and len(value) > 1:
                info["switch_port"] = value[1:].decode('utf-8', errors='replace').strip('\x00').strip()
            elif tlv_type == 5:
                info["switch_name"] = value.decode('utf-8', errors='replace').strip('\x00').strip()
            elif tlv_type == 6:
                info["system_desc"] = value.decode('utf-8', errors='replace').strip('\x00').strip()[:100]
            elif tlv_type == 127 and len(value) >= 4:
                oui = value[:3]
                sub = value[3]
                if oui == b'\x00\x80\xc2' and sub == 0x01 and len(value) >= 6:
                    info["vlan_id"] = struct.unpack('!H', value[4:6])[0]
                elif oui == b'\x00\x00\x0c' and len(value) >= 6:
                    info["vlan_id"] = struct.unpack('!H', value[4:6])[0]
    except Exception as e:
        info["parse_error"] = str(e)
    return info


def parse_cdp(raw_bytes):
    info = {"protocol": "CDP", "switch_name": None, "switch_port": None,
            "vlan_id": None, "system_desc": None}
    try:
        pos = 4  # skip version(1) + ttl(1) + checksum(2)
        while pos + 4 <= len(raw_bytes):
            typ = struct.unpack('!H', raw_bytes[pos:pos+2])[0]
            lng = struct.unpack('!H', raw_bytes[pos+2:pos+4])[0]
            if lng < 4:
                break
            value = raw_bytes[pos+4:pos+lng]
            pos += lng
            if typ == 0x0001:
                info["switch_name"] = value.decode('utf-8', errors='replace').strip('\x00').strip()
            elif typ == 0x0003:
                info["switch_port"] = value.decode('utf-8', errors='replace').strip('\x00').strip()
            elif typ == 0x0005:
                info["system_desc"] = value.decode('utf-8', errors='replace').strip('\x00').strip()[:100]
            elif typ == 0x000A and len(value) >= 2:
                info["vlan_id"] = struct.unpack('!H', value[:2])[0]
    except Exception as e:
        info["parse_error"] = str(e)
    return info


class Sniffer:
    def __init__(self, iface, timeout, callback):
        self.iface    = iface
        self.timeout  = timeout
        self.callback = callback
        self.found    = False

    def _handle(self, pkt):
        if self.found:
            return
        try:
            raw_pkt = bytes(pkt)

            # ── LLDP: EtherType 0x88cc at bytes 12-13 ──
            if len(raw_pkt) >= 14:
                ethertype = struct.unpack('!H', raw_pkt[12:14])[0]
                if ethertype == 0x88CC:
                    info = parse_lldp(raw_pkt[14:])
                    self.found = True
                    self.callback(info, None)
                    return

            # ── CDP: 802.3 frame with SNAP LLC ──
            # Dst MAC 01:00:0c:cc:cc:cc
            if raw_pkt[:6] == b'\x01\x00\x0c\xcc\xcc\xcc':
                # Find SNAP OUI 00:00:0c + PID 0x2000 (CDP)
                snap_idx = raw_pkt.find(b'\xaa\xaa\x03\x00\x00\x0c\x20\x00')
                if snap_idx != -1:
                    cdp_data = raw_pkt[snap_idx + 8:]
                    info = parse_cdp(cdp_data)
                    self.found = True
                    self.callback(info, None)
                    return
        except Exception:
            pass

    def _stop(self, pkt):
        return self.found

    def run(self):
        try:
            # No BPF filter — capture ALL frames and filter in Python
            # This is the most reliable method on Windows/Npcap
            sniff(
                iface=self.iface,
                prn=self._handle,
                stop_filter=self._stop,
                timeout=self.timeout,
                store=False,
                monitor=False
            )
            if not self.found:
                self.callback(None,
                    "No LLDP/CDP frames received.\n"
                    "   • Make sure the correct interface is selected\n"
                    "   • Ensure switch has LLDP enabled\n"
                    "   • Wait — switches send LLDP every 30s")
        except Exception as e:
            self.callback(None, f"Capture error: {e}")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Info  •  LLDP / CDP Scanner")
        self.geometry("740x820")
        self.resizable(True, True)
        self.configure(bg=BG)
        self.scanning = False
        self.selected_iface = tk.StringVar()
        self._iface_map = {}
        self._build_ui()
        self._refresh_ip()
        self._load_interfaces()
        self._tick()

    def _build_ui(self):
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill='x', padx=20, pady=(16, 0))
        tk.Label(hdr, text="🌐  Network Info", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 22, "bold")).pack(side='left')
        self.lbl_time = tk.Label(hdr, text="", bg=BG, fg=SUBTEXT,
                                  font=("Segoe UI", 10))
        self.lbl_time.pack(side='right')

        if not is_admin():
            bar = tk.Frame(self, bg="#7c2d12", pady=5)
            bar.pack(fill='x', padx=20, pady=(8, 0))
            tk.Label(bar,
                     text="⚠  Run as Administrator for LLDP/CDP capture  —  "
                          "Right-click EXE → Run as administrator",
                     bg="#7c2d12", fg=YELLOW,
                     font=("Segoe UI", 9, "bold")).pack()

        if not SCAPY_AVAILABLE:
            bar2 = tk.Frame(self, bg="#1e1e40", pady=5)
            bar2.pack(fill='x', padx=20, pady=(6, 0))
            tk.Label(bar2, text="❌  Scapy not installed — run BUILD.bat first",
                     bg="#1e1e40", fg=RED, font=("Segoe UI", 9, "bold")).pack()

        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill='both', expand=True, padx=20, pady=10)
        canvas = tk.Canvas(wrap, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(wrap, orient='vertical', command=canvas.yview)
        self.inner = tk.Frame(canvas, bg=BG)
        self.inner.bind('<Configure>',
            lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0, 0), window=self.inner, anchor='nw')
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')
        canvas.bind_all("<MouseWheel>",
            lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        # IP Card
        c = self._card("🖥  IP Address", ACCENT)
        self.row_ip    = self._row(c, "IPv4 Address")
        self.row_ipv6  = self._row(c, "IPv6 Address")
        self.row_mac   = self._row(c, "MAC Address")
        self.row_iface = self._row(c, "Interface")

        # Interface picker card
        cp = self._card("🔍  Capture Interface", YELLOW)
        tk.Label(cp,
                 text="Select the interface Wireshark uses to see LLDP/CDP:",
                 bg=CARD, fg=SUBTEXT, font=("Segoe UI", 9)).pack(
                     anchor='w', padx=16, pady=(0, 4))
        self.combo_iface = ttk.Combobox(cp, textvariable=self.selected_iface,
                                         state='readonly', width=72,
                                         font=("Consolas", 9))
        self.combo_iface.pack(anchor='w', padx=16, pady=(0, 4))
        self.lbl_iface_count = tk.Label(cp, text="Loading interfaces…",
                                         bg=CARD, fg=SUBTEXT,
                                         font=("Segoe UI", 8))
        self.lbl_iface_count.pack(anchor='w', padx=16, pady=(0, 10))

        # Switch card
        cs = self._card("🔌  Switch Info  (LLDP / CDP)", ACCENT2)
        self.row_proto  = self._row(cs, "Protocol")
        self.row_switch = self._row(cs, "Switch Name")
        self.row_port   = self._row(cs, "Switch Port")
        self.row_vlan   = self._row(cs, "VLAN ID")
        self.row_desc   = self._row(cs, "System Desc")
        self.lbl_status = tk.Label(cs, text="Not scanned yet",
                                    bg=CARD, fg=SUBTEXT,
                                    font=("Segoe UI", 9), justify='left')
        self.lbl_status.pack(anchor='w', padx=16, pady=(6, 2))
        self.btn_scan = tk.Button(cs,
                                   text="▶  Start LLDP/CDP Scan  (90s)",
                                   bg=ACCENT2, fg="white", relief='flat',
                                   font=("Segoe UI", 10, "bold"),
                                   padx=14, pady=7, cursor='hand2',
                                   command=self._start_scan)
        self.btn_scan.pack(anchor='w', padx=16, pady=(4, 14))

        # Network details card
        cn = self._card("⚙  Network Details", GREEN)
        self.row_subnet = self._row(cn, "Subnet Mask")
        self.row_gw     = self._row(cn, "Gateway")
        self.row_dns    = self._row(cn, "DNS Server")

        bf = tk.Frame(self, bg=BG)
        bf.pack(pady=(0, 16))
        tk.Button(bf, text="🔄  Refresh IP",
                  bg=ACCENT, fg=BG, relief='flat',
                  font=("Segoe UI", 11, "bold"),
                  padx=18, pady=7, cursor='hand2',
                  command=self._refresh_ip).pack(side='left', padx=6)
        tk.Button(bf, text="📋  Copy All",
                  bg=CARD, fg=TEXT, relief='flat',
                  font=("Segoe UI", 11),
                  padx=18, pady=7, cursor='hand2',
                  command=self._copy_all).pack(side='left', padx=6)

    def _card(self, title, color):
        f = tk.Frame(self.inner, bg=CARD)
        f.pack(fill='x', pady=7)
        tk.Frame(f, bg=color, height=3).pack(fill='x')
        tk.Label(f, text=title, bg=CARD, fg=color,
                 font=("Segoe UI", 12, "bold")).pack(
                     anchor='w', padx=16, pady=(10, 4))
        tk.Frame(f, bg="#334155", height=1).pack(fill='x', padx=16, pady=(0, 8))
        return f

    def _row(self, parent, label):
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill='x', padx=16, pady=3)
        tk.Label(row, text=label, bg=CARD, fg=SUBTEXT,
                 font=("Segoe UI", 9), width=14, anchor='w').pack(side='left')
        val = tk.Label(row, text="—", bg=CARD, fg=TEXT,
                       font=("Consolas", 10, "bold"), anchor='w',
                       wraplength=520, justify='left')
        val.pack(side='left', fill='x', expand=True)
        val.bind("<Button-1>", lambda e, v=val: self._copy(v.cget("text")))
        val.config(cursor='hand2')
        return val

    def _tick(self):
        self.lbl_time.config(text=time.strftime("%H:%M:%S  %d %b %Y"))
        self.after(1000, self._tick)

    def _load_interfaces(self):
        if not SCAPY_AVAILABLE:
            self.lbl_iface_count.config(text="Scapy not available")
            return
        def worker():
            eth = get_ethernet_interfaces()
            all_ifaces = get_all_interfaces()
            self.after(0, lambda: self._set_ifaces(eth, all_ifaces))
        threading.Thread(target=worker, daemon=True).start()

    def _set_ifaces(self, eth_ifaces, all_ifaces):
        if eth_ifaces:
            iface_list = eth_ifaces
            note = f"{len(eth_ifaces)} Ethernet interface(s) found  (all shown below)"
        else:
            iface_list = all_ifaces
            note = f"No Ethernet filter matched — showing all {len(all_ifaces)} interface(s)"
        items = [f"{desc}  |  {name}" for name, desc in iface_list]
        self._iface_map = {f"{desc}  |  {name}": name for name, desc in iface_list}
        self.combo_iface['values'] = items
        if items:
            self.combo_iface.current(0)
        self.lbl_iface_count.config(text=note)

    def _refresh_ip(self):
        threading.Thread(
            target=lambda: self.after(0, self._update_ip, get_ip_info()),
            daemon=True).start()

    def _update_ip(self, info):
        self.row_ip.config(text=info.get("ip", "—"),
                           fg=GREEN if info.get("ip", "—") != "—" else RED)
        self.row_ipv6.config(text=info.get("ipv6", "—"))
        self.row_mac.config(text=info.get("mac", "—"))
        self.row_iface.config(text=info.get("interface", "—"))
        self.row_subnet.config(text=info.get("subnet", "—"))
        self.row_gw.config(text=info.get("gateway", "—"))
        self.row_dns.config(text=info.get("dns", "—"))

    def _start_scan(self):
        if self.scanning:
            return
        if not SCAPY_AVAILABLE:
            self.lbl_status.config(text="❌  Scapy not installed.", fg=RED)
            return
        if not is_admin():
            self.lbl_status.config(
                text="❌  Administrator rights required.\n"
                     "   Right-click the EXE → Run as administrator", fg=RED)
            return
        sel = self.selected_iface.get()
        iface_name = self._iface_map.get(sel)
        if not iface_name:
            self.lbl_status.config(text="❌  Select an interface first.", fg=RED)
            return

        self.scanning = True
        self.btn_scan.config(text="⏳  Scanning…", state='disabled', bg="#4b5563")
        short = sel[:55] + "…" if len(sel) > 55 else sel
        self.lbl_status.config(
            text=f"🔄  Listening on:\n    {short}\n    Waiting for LLDP/CDP… (up to 90s)",
            fg=YELLOW)
        for row in [self.row_proto, self.row_switch, self.row_port,
                    self.row_vlan, self.row_desc]:
            row.config(text="—", fg=TEXT)

        threading.Thread(target=self._scan_worker,
                         args=(iface_name,), daemon=True).start()

    def _scan_worker(self, iface):
        Sniffer(iface, 90, self._on_result).run()

    def _on_result(self, info, error):
        self.after(0, self._update_switch, info, error)

    def _update_switch(self, info, error):
        self.scanning = False
        self.btn_scan.config(text="▶  Start LLDP/CDP Scan  (90s)",
                              state='normal', bg=ACCENT2)
        if error or not info:
            self.lbl_status.config(text=f"⚠  {error or 'No frames captured.'}", fg=YELLOW)
            return
        self.lbl_status.config(text=f"✅  {info['protocol']} frame captured!", fg=GREEN)
        self.row_proto.config(text=info.get("protocol", "—"),
                               fg=ACCENT if info.get("protocol") == "LLDP" else YELLOW)
        self.row_switch.config(text=info.get("switch_name") or "—",
                                fg=GREEN if info.get("switch_name") else SUBTEXT)
        self.row_port.config(text=info.get("switch_port") or "—",
                              fg=GREEN if info.get("switch_port") else SUBTEXT)
        vlan = info.get("vlan_id")
        self.row_vlan.config(text=str(vlan) if vlan else "—",
                              fg=ACCENT if vlan else SUBTEXT)
        self.row_desc.config(text=info.get("system_desc") or "—", fg=SUBTEXT)

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _copy_all(self):
        lines = [
            f"Protocol:    {self.row_proto.cget('text')}",
            f"IPv4:        {self.row_ip.cget('text')}",
            f"IPv6:        {self.row_ipv6.cget('text')}",
            f"MAC:         {self.row_mac.cget('text')}",
            f"Interface:   {self.row_iface.cget('text')}",
            f"Switch Name: {self.row_switch.cget('text')}",
            f"Switch Port: {self.row_port.cget('text')}",
            f"VLAN ID:     {self.row_vlan.cget('text')}",
            f"Sys Desc:    {self.row_desc.cget('text')}",
            f"Subnet:      {self.row_subnet.cget('text')}",
            f"Gateway:     {self.row_gw.cget('text')}",
            f"DNS:         {self.row_dns.cget('text')}",
        ]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.lbl_status.config(text="📋  Copied to clipboard!", fg=GREEN)


if __name__ == "__main__":
    app = App()
    app.mainloop()
