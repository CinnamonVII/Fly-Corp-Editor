#!/usr/bin/env python3
import gzip
import json
import os
import sys
import time
import argparse
import struct
import re
import subprocess
import threading
import ctypes
from collections import Counter, deque
IN_CLOSE_WRITE = 8
IN_MOVED_TO = 128
OFF_MONEY = 0
OFF_SPENT = 848
OFF_DELIVERED = 812
OFF_ROUTES = 844

class FlyCorpAdvisor:

    def __init__(self, file_path, mock=False, money_offset=-336, scan_range=512):
        self.file_path = file_path
        self.mock = mock
        self.money_offset = money_offset
        self.scan_range = scan_range
        self.pid = None
        self.money_addr = None
        self.money_type = 'int'
        self.last_mtime = 0
        self.data = {}
        self.last_update_str = 'Never'
        self.live_data = {}
        self.is_scanning = False
        self.money_history = deque(maxlen=60)
        self.income_per_sec = 0
        self.extracted_data = {}
        self.optimizations = []
        self.last_scan_attempt = 0
        self.ptrace_ok = None
        self.scan_range = 512
        self.offsets = {'money': OFF_MONEY, 'spent': OFF_SPENT, 'delivered': OFF_DELIVERED, 'routes': OFF_ROUTES}
        self.money_type = 'double'
        self.activity_map = {}
        self.global_activity = {}
        self.last_global_scan = 0
        self.HIGH_WEIGHT = ['USA', 'China', 'India', 'Germany', 'France', 'United Kingdom', 'Japan']
        self.UNLOCK_COSTS = {'USA': 15000, 'China': 18000, 'India': 12000, 'Germany': 10000, 'France': 8000, 'United Kingdom': 9000, 'Japan': 14000}

    def find_pid(self):
        candidates = []
        try:
            for pid_str in os.listdir('/proc'):
                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)
                try:
                    with open(f'/proc/{pid}/comm', 'r') as f:
                        comm = f.read().strip()
                    with open(f'/proc/{pid}/cmdline', 'r') as f:
                        cmdline = f.read().replace('\\0', ' ').strip()
                    if 'Fly Corp' in cmdline or 'Fly.Corp' in cmdline or 'KishMish' in cmdline or ('Fly Corp' in comm):
                        with open(f'/proc/{pid}/statm', 'r') as f:
                            rss = int(f.read().split()[1])
                        candidates.append((pid, rss))
                except Exception:
                    continue
        except Exception:
            pass
        if candidates:
            return sorted(candidates, key=lambda x: x[1], reverse=True)[0][0]
        return None

    def check_ptrace(self):
        if self.ptrace_ok is not None:
            return self.ptrace_ok
        try:
            with open('/proc/sys/kernel/yama/ptrace_scope', 'r') as f:
                scope = int(f.read().strip())
            if scope >= 1:
                print('  ⚠️  WARNING: ptrace_scope is set to 1 (restricted).')
                print('     Live memory reading may fail. To fix:')
                print('     echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope')
                self.ptrace_ok = False
                return False
            self.ptrace_ok = True
            return True
        except Exception:
            self.ptrace_ok = True
            return True

    def _do_scan(self):
        self.is_scanning = True
        gs = self.data.get('GameState', {})
        save_money = float(gs.get('Money', 0))
        save_spent = int(gs.get('TotalInfrastructureSpent', -1))
        save_delivered = int(gs.get('TotalPackagesDelivered', -1))
        if save_spent <= 0 and save_delivered <= 0:
            print(f'  [Scan skipped: Need at least >0 spent to form a unique memory signature.]')
            self.is_scanning = False
            return
        print(f'  [Scanning for struct anchors (Spent: {save_spent}, Money: {save_money})...]')
        t_spent = struct.pack('<i', save_spent)
        valid = []
        try:
            with open(f'/proc/{self.pid}/maps', 'r') as maps:
                with open(f'/proc/{self.pid}/mem', 'rb') as mem_f:
                    for line in maps:
                        if 'rw-p' not in line:
                            continue
                        parts = line.split()
                        addr_range = parts[0].split('-')
                        start, end = (int(addr_range[0], 16), int(addr_range[1], 16))
                        chunk_size = 16 * 1024 * 1024
                        overlap = 2048
                        current_addr = start
                        while current_addr < end:
                            try:
                                read_size = min(chunk_size, end - current_addr)
                                mem_f.seek(current_addr)
                                chunk = mem_f.read(read_size)
                                idx = 0
                                while True:
                                    idx = chunk.find(t_spent, idx)
                                    if idx == -1:
                                        break
                                    if idx >= OFF_SPENT and idx - OFF_SPENT + 8 <= len(chunk):
                                        m_idx = idx - OFF_SPENT
                                        test_money = struct.unpack('<d', chunk[m_idx:m_idx + 8])[0]
                                        if save_money * 0.1 <= test_money <= save_money * 10.0 or (save_money == 0 and test_money < 100000):
                                            valid.append((current_addr + m_idx, 'double'))
                                    idx += 4
                                if read_size == chunk_size and end - current_addr > chunk_size:
                                    current_addr += chunk_size - overlap
                                else:
                                    current_addr += read_size
                            except Exception:
                                break
        except Exception as e:
            print(f'  [Scan Error: {e}]')
        if valid:
            self.money_addr, self.money_type = sorted(valid)[-1]
            print(f'  [Live Link Established: {hex(self.money_addr)}]')
        else:
            print(f'  [WARNING: No valid live links found.]')
        self.is_scanning = False

    def auto_scan_money(self):
        if self.mock:
            return
        self.pid = self.find_pid()
        if not self.pid:
            return
        print(f'  [Auto-Scan: Found PID {self.pid}]')
        self.check_ptrace()
        self.last_scan_attempt = time.time()
        t = threading.Thread(target=self._do_scan, daemon=True)
        t.start()

    def read_live_data(self):
        if self.mock or not self.pid or (not self.money_addr):
            return {'money': self.data.get('GameState', {}).get('Money', 0), 'spent': self.data.get('GameState', {}).get('TotalInfrastructureSpent', 0), 'delivered': self.data.get('GameState', {}).get('TotalPackagesDelivered', 0)}
        out = {}
        try:
            with open(f'/proc/{self.pid}/mem', 'rb', 0) as mem:
                mem.seek(self.money_addr + self.offsets['money'])
                if self.money_type == 'double':
                    out['money'] = int(struct.unpack('<d', mem.read(8))[0])
                else:
                    out['money'] = int(struct.unpack('<f', mem.read(4))[0])
                mem.seek(self.money_addr + self.offsets['spent'])
                out['spent'] = struct.unpack('<i', mem.read(4))[0]
                mem.seek(self.money_addr + self.offsets['delivered'])
                out['delivered'] = struct.unpack('<i', mem.read(4))[0]
                mem.seek(self.money_addr + self.offsets['routes'])
                out['routes'] = struct.unpack('<i', mem.read(4))[0]
        except Exception:
            self.money_addr = None
            return {'money': self.data.get('GameState', {}).get('Money', 0), 'spent': self.data.get('GameState', {}).get('TotalInfrastructureSpent', 0), 'delivered': self.data.get('GameState', {}).get('TotalPackagesDelivered', 0)}
        return out

    def auto_tune_offsets(self):
        if not self.money_addr or not self.pid:
            return
        gs = self.data.get('GameState', {})
        targets = {'money': (float(gs.get('Money', 0)), 'd', 8), 'spent': (int(gs.get('TotalInfrastructureSpent', 0)), 'i', 4), 'delivered': (int(gs.get('TotalPackagesDelivered', 0)), 'i', 4)}
        print(f'  [Auto-Tune: Searching for live targets near {hex(self.money_addr)}...]')
        try:
            with open(f'/proc/{self.pid}/mem', 'rb', 0) as mem:
                search_start = self.money_addr - 4096
                mem.seek(search_start)
                chunk = mem.read(8192)
                for field, (val, fmt, size) in targets.items():
                    pat = struct.pack(f'<{fmt}', val)
                    for m in re.finditer(re.escape(pat), chunk):
                        new_off = search_start + m.start() - self.money_addr
                        if new_off != self.offsets[field]:
                            print(f'  [Auto-Tune: Found {field} at new offset {new_off} (was {self.offsets[field]})]')
                            self.offsets[field] = new_off
                            break
        except Exception:
            pass

    def hunt_live_fields(self):
        if not self.money_addr or not self.pid or self.mock:
            return
        try:
            with open(f'/proc/{self.pid}/mem', 'rb', 0) as mem:
                search_start = self.money_addr - 4096
                mem.seek(search_start)
                chunk = mem.read(8192)
                for i in range(0, len(chunk) - 8, 4):
                    val_d = struct.unpack('<d', chunk[i:i + 8])[0]
                    val_f = struct.unpack('<f', chunk[i:i + 4])[0]
                    off = search_start + i - self.money_addr
                    for val, size, tag in [(val_d, 8, 'double'), (val_f, 4, 'float')]:
                        if not 0.1 < val < 1000000000:
                            continue
                        key = (off, size)
                        if key not in self.activity_map:
                            self.activity_map[key] = [val, 0]
                        else:
                            last_val, count = self.activity_map[key]
                            if abs(val - last_val) > 0.01:
                                self.activity_map[key] = [val, count + 1]
                                if count + 1 > 3:
                                    if abs(off - self.offsets['money']) < 512:
                                        if off != self.offsets['money'] or tag != self.money_type:
                                            print(f'  [Hunter: Pivoting Money to {tag} at offset {off} (Value: {val:,.0f})]')
                                            self.offsets['money'] = off
                                            self.money_type = tag
                                            break
        except:
            pass

    def find_live_counterpart(self):
        if not self.pid or self.mock:
            return
        gs = self.data.get('GameState', {})
        save_money = float(gs.get('Money', 0))
        save_spent = int(gs.get('TotalInfrastructureSpent', -1))
        save_delivered = int(gs.get('TotalPackagesDelivered', -1))
        if save_spent <= 0 and save_delivered <= 0:
            return
        t_spent = struct.pack('<i', save_spent)
        print(f'  [DuoScan: Hunting for save buffer using Spent ({save_spent})...]')
        anchors = []
        try:
            with open(f'/proc/{self.pid}/maps', 'r') as maps:
                with open(f'/proc/{self.pid}/mem', 'rb') as mem_f:
                    for line in maps:
                        if 'rw-p' not in line:
                            continue
                        if '/' in line and '/dev/' in line:
                            continue
                        parts = line.split()
                        addr_range = parts[0].split('-')
                        start, end = (int(addr_range[0], 16), int(addr_range[1], 16))
                        chunk_size = 16 * 1024 * 1024
                        current_addr = start
                        while current_addr < end:
                            try:
                                read_size = min(chunk_size, end - current_addr)
                                mem_f.seek(current_addr)
                                chunk = mem_f.read(read_size)
                                idx = 0
                                while True:
                                    idx = chunk.find(t_spent, idx)
                                    if idx == -1:
                                        break
                                    anchors.append(current_addr + idx)
                                    idx += 4
                                if read_size == chunk_size and end - current_addr > chunk_size:
                                    current_addr += chunk_size - 4
                                else:
                                    current_addr += read_size
                            except Exception:
                                break
                    if not anchors:
                        return
                    for anchor in anchors:
                        search_start = max(0, anchor - 65536)
                        mem_f.seek(search_start)
                        neighborhood = mem_f.read(131072)
                        idx = 0
                        while True:
                            idx = neighborhood.find(t_spent, idx)
                            if idx == -1:
                                break
                            s_addr = search_start + idx
                            m_addr = s_addr - OFF_SPENT
                            idx += 4
                            if search_start <= m_addr < search_start + 131072 - 8:
                                test_money = struct.unpack('<d', neighborhood[m_addr - search_start:m_addr - search_start + 8])[0]
                                if save_money * 0.1 <= test_money <= save_money * 10.0 or (save_money == 0 and test_money < 100000):
                                    print(f'  [DuoScan: CONFIRMED live shadow struct via Spent anchor!]')
                                    self.money_addr = m_addr
                                    self.offsets['money'] = 0
                                    return
        except:
            pass

    def load_data(self):
        if self.mock:
            self.data = {'GameState': {'Money': 5000}, 'OpenedCountries': [], 'Warehouses': [], 'Routes': [], 'Packages': [], 'Planes': []}
            return True
        if not os.path.exists(self.file_path):
            return False
        try:
            mtime = os.path.getmtime(self.file_path)
            if mtime <= self.last_mtime:
                return False
            with gzip.open(self.file_path, 'rb') as f:
                self.data = json.load(f)
            self.last_mtime = mtime
            self.last_update_str = time.strftime('%H:%M:%S')
            self.analyze_flow_data()
            self.auto_tune_offsets()
            threading.Thread(target=self.find_live_counterpart, daemon=True).start()
            return True
        except Exception:
            return False

    def _watch_save(self):
        libc = ctypes.CDLL('libc.so.6')
        inotify_fd = libc.inotify_init()
        if inotify_fd < 0:
            return
        dir_path = os.path.dirname(self.file_path)
        watch_fd = libc.inotify_add_watch(inotify_fd, dir_path.encode(), IN_CLOSE_WRITE | IN_MOVED_TO)
        if watch_fd < 0:
            return
        buf_size = 1024
        buf = ctypes.create_string_buffer(buf_size)
        while True:
            n = libc.read(inotify_fd, buf, buf_size)
            if n <= 0:
                continue
            self.load_data()
            if not self.money_addr:
                self.auto_scan_money()

    def analyze_flow_data(self):
        raw_warehouses = self.data.get('Warehouses', [])
        raw_routes = self.data.get('Routes', [])
        raw_packages = self.data.get('Packages', [])
        raw_planes = self.data.get('Planes', [])
        warehouses = {w['Id']: {'Name': w.get('Name', f"Hub-{w['Id']}"), 'Country': w.get('AssignedCountryName', '?'), 'Level': w.get('Level', 1), 'Capacity': w.get('Level', 1) * 40, 'Pkgs': len(w.get('PackageIds', [])), 'TotalProcessed': w.get('TotalPackagesProcessed', 0)} for w in raw_warehouses}
        routes = {r['Id']: r for r in raw_routes}
        route_edges = {r['Id']: tuple(sorted((r['OriginWarehouseId'], r['DestinationWarehouseId']))) for r in raw_routes}
        edge_to_routes = {}
        for r_id, edge in route_edges.items():
            if edge not in edge_to_routes:
                edge_to_routes[edge] = []
            edge_to_routes[edge].append(r_id)
        planes = {p['Id']: p for p in raw_planes}
        route_planes = {}
        for p in raw_planes:
            rid = p.get('RouteId')
            if rid not in route_planes:
                route_planes[rid] = []
            route_planes[rid].append(p)
        total_backlog = sum((w['Pkgs'] for w in warehouses.values()))
        dest_counter = Counter()
        for p in raw_packages:
            d = p.get('DestinationWarehouseId')
            if d in warehouses:
                dest_counter[warehouses[d]['Country']] += 1
        self.extracted_data = {'Total Hubs': len(warehouses), 'Total Routes': len(routes), 'Total Planes': len(planes), 'Global Backlog': total_backlog, 'Top Demand': dest_counter.most_common(3)}
        opts = []
        sorted_hubs = sorted([w for w in warehouses.values() if w['Pkgs'] > 0], key=lambda w: w['Pkgs'] / w['Capacity'] if w['Capacity'] else 0, reverse=True)
        for w in sorted_hubs[:3]:
            util = w['Pkgs'] / w['Capacity'] * 100
            if util > 75:
                throughput = w['TotalProcessed']
                opts.append(f"🚨 BOTTLENECK: {w['Name']} ({w['Country']}) at {util:.0f}% ({w['Pkgs']}/{w['Capacity']}), {throughput:,} total processed. Upgrade!")
        route_waitlist = Counter()
        for p in raw_packages:
            path = p.get('DeliveryPathRouteIds', [])
            if path:
                route_waitlist[path[0]] += 1
        direct_edges = set(route_edges.values())
        indirect_traffic = Counter()
        for p in raw_packages:
            path = p.get('DeliveryPathRouteIds', [])
            if len(path) >= 3:
                o, d = (p.get('OriginWarehouseId'), p.get('DestinationWarehouseId'))
                if o and d:
                    edge = tuple(sorted((o, d)))
                    indirect_traffic[edge] += 1
        for (a, b), count in indirect_traffic.most_common(3):
            if count >= 5:
                name_a = warehouses.get(a, {}).get('Name', f'Hub-{a}')
                name_b = warehouses.get(b, {}).get('Name', f'Hub-{b}')
                opts.append(f'🛫 LONG TRANSFER: {name_a} ↔ {name_b} has {count} pkgs taking 3+ hops. Consider a direct route!')
        for edge, route_ids in edge_to_routes.items():
            all_planes = []
            for r_id in route_ids:
                all_planes.extend(route_planes.get(r_id, []))
            total_cap = sum((p.get('Capacity', 10) for p in all_planes))
            waiting = sum((route_waitlist.get(r_id, 0) for r_id in route_ids))
            a, b = edge
            name_a = warehouses.get(a, {}).get('Name', '?')
            name_b = warehouses.get(b, {}).get('Name', '?')
            if waiting > total_cap * 2 and waiting > 20:
                opts.append(f'⚠️ OVERLOADED: {name_a} ↔ {name_b} has {waiting} pkgs but only {len(all_planes)} plane(s) (cap: {total_cap}). Add planes!')
        hub_connections = Counter()
        for r in raw_routes:
            hub_connections[r['OriginWarehouseId']] += 1
            hub_connections[r['DestinationWarehouseId']] += 1
        for hub_id, count in hub_connections.items():
            if count == 1:
                name = warehouses.get(hub_id, {}).get('Name', f'Hub-{hub_id}')
                opts.append(f'🔗 ISOLATED HUB: {name} has only 1 route — single point of failure!')
        idle_planes = []
        for p in raw_planes:
            if not p.get('IsFlying', True) and (not p.get('IsWaiting', False)):
                rid = p.get('RouteId')
                route = routes.get(rid, {})
                o = route.get('OriginWarehouseId')
                d = route.get('DestinationWarehouseId')
                name_o = warehouses.get(o, {}).get('Name', '?')
                name_d = warehouses.get(d, {}).get('Name', '?')
                idle_planes.append(f'{name_o} ↔ {name_d}')
        if idle_planes:
            opts.append(f"💤 IDLE PLANES: {len(idle_planes)} plane(s) sitting idle ({', '.join(idle_planes[:3])})")
        self.optimizations = list(dict.fromkeys(opts))[:12]

    def update_income(self):
        now = time.time()
        money = self.live_data.get('money', 0)
        self.money_history.append((now, money))
        if len(self.money_history) > 1:
            dt = self.money_history[-1][0] - self.money_history[0][0]
            dm = self.money_history[-1][1] - self.money_history[0][1]
            if dt > 0:
                self.income_per_sec = dm / dt
            else:
                self.income_per_sec = 0

    def run(self):
        self.load_data()
        self.auto_scan_money()
        t_watch = threading.Thread(target=self._watch_save, daemon=True)
        t_watch.start()
        try:
            while True:
                now = time.time()
                if now - self.last_mtime > 5:
                    self.load_data()
                if not self.money_addr and time.time() - self.last_scan_attempt > 30:
                    self.auto_scan_money()
                self.live_data = self.read_live_data()
                self.hunt_live_fields()
                self.update_income()
                os.system('clear')
                print('=== Fly Corp Cargo Advisor ===')
                money = self.live_data.get('money', 0)
                spent = self.live_data.get('spent', 0)
                delivered = self.live_data.get('delivered', 0)
                print(f"💰 Money: ${money:,.0f} | 📈 Live Income: {('+$' if self.income_per_sec >= 0 else '-$')}{abs(self.income_per_sec):,.1f}/sec")
                print(f'🏗️  Spent: ${spent:,.0f} | 📦 Delivered: {delivered:,}')
                if self.money_addr:
                    mem_status = hex(self.money_addr)
                elif self.is_scanning:
                    mem_status = 'Scanning...'
                elif self.pid:
                    mem_status = 'Not linked (Save Fallback)'
                else:
                    mem_status = 'Not linked'
                print(f'💾 Last Save: {self.last_update_str} | Memory: {mem_status}')
                print('-' * 60)
                if self.is_scanning:
                    print('  [SYSTEM: Scanning memory for live link...]')
                else:
                    if self.income_per_sec < -1:
                        money = self.live_data.get('money', 0)
                        runway_secs = money / abs(self.income_per_sec)
                        print(f'  🔥 CASH BURN: Losing ${abs(self.income_per_sec):.0f}/sec. Funds run out in {runway_secs / 60:.1f}m if unchanged.')
                    opened = self.data.get('OpenedCountries', [])
                    targets = [c for c in self.HIGH_WEIGHT if c not in opened]
                    money = self.live_data.get('money', 0)
                    if targets and self.income_per_sec > 0:
                        target = targets[0]
                        eth = self.UNLOCK_COSTS.get(target, 10000)
                        if money >= eth:
                            print(f'  🌟 EXPANSION: You can afford {target} (${eth:,})! Unlock now!')
                        elif money < eth:
                            time_left = (eth - money) / self.income_per_sec
                            if time_left < 600:
                                print(f'  ⏳ GOAL ETA: {target} (${eth:,}) in ~{time_left / 60:.1f}m at current income.')
                    print('\n📊 EXTRACTED DATA:')
                    if not self.extracted_data:
                        print('  [Waiting for save file data...]')
                    else:
                        for k, v in self.extracted_data.items():
                            if k == 'Top Demand':
                                top_str = ', '.join([f'{c} ({cnt})' for c, cnt in v])
                                print(f'  * {k}: {top_str}')
                            else:
                                print(f'  * {k}: {v:,}')
                    print('\n🔧 OPTIMIZATIONS:')
                    if not self.optimizations:
                        print('  ✅ Network is running smoothly!')
                    else:
                        for opt in self.optimizations:
                            print(f'  * {opt}')
                h = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'][int(time.time() * 10) % 10]
                print(f'\n[{h}] Live Monitoring... (Ctrl+C to stop)')
                time.sleep(1)
        except KeyboardInterrupt:
            print('\nStopped.')
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--file')
    parser.add_argument('--money-offset', type=int, default=-336, help='Byte offset from anchor to money field')
    parser.add_argument('--scan-range', type=int, default=512, help='Search window around anchor (bytes)')
    args = parser.parse_args()
    default_path = '/home/deck/.local/share/Steam/steamapps/compatdata/1372530/pfx/drive_c/users/steamuser/AppData/LocalLow/KishMish Games/Fly Corp/CargoSaves/save_slot_0.json'
    path = args.file if args.file else default_path
    FlyCorpAdvisor(path, money_offset=args.money_offset, scan_range=args.scan_range).run()