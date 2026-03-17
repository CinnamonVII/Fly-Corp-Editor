#!/usr/bin/env python3
import gzip
import json
import os
import sys
import time
import argparse
import struct
import re
from collections import Counter, deque

class FlyCorpAdvisor:
    def __init__(self, file_path, mock=False):
        self.file_path = file_path
        self.mock = mock
        self.pid = None
        self.money_addr = None
        self.money_type = 'int'
        self.last_mtime = 0
        self.data = {}
        self.last_update_str = "Never"
        self.live_money = 0
        self.is_scanning = False
        self.money_history = deque(maxlen=10)
        self.income_per_sec = 0
        self.extracted_data = {}
        self.optimizations = []
        self.HIGH_WEIGHT = ["USA", "China", "India", "Germany", "France", "United Kingdom", "Japan"]

    def find_pid(self):
        try:
            pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
            for pid in pids:
                try:
                    with open(f'/proc/{pid}/comm', 'r') as f:
                        if 'Fly Corp' in f.read():
                            return int(pid)
                except:
                    continue
        except:
            pass
        return None

    def auto_scan_money(self):
        if self.mock:
            return
        self.pid = self.find_pid()
        if not self.pid:
            return
        self.is_scanning = True
        gs = self.data.get("GameState", {})
        save_money = gs.get("Money", 0)
        spent = gs.get("TotalInfrastructureSpent", -1)
        if save_money < 100 or spent < 10:
            self.is_scanning = False
            return
        print(f"  [Scanning for static struct anchor (Spent: {spent}) in memory...]")
        t_spent = struct.pack('<i', int(spent))
        candidates = []
        try:
            with open(f'/proc/{self.pid}/maps', 'r') as maps:
                mem_f = open(f'/proc/{self.pid}/mem', 'rb')
                for line in maps:
                    if 'rw-p' not in line:
                        continue
                    parts = line.split()
                    addr_range = parts[0].split('-')
                    start, end = int(addr_range[0], 16), int(addr_range[1], 16)
                    size = end - start
                    if size > 120 * 1024 * 1024:
                        continue
                    try:
                        mem_f.seek(start)
                        chunk = mem_f.read(size)
                        for m in re.finditer(re.escape(t_spent), chunk):
                            candidates.append(start + m.start())
                    except:
                        continue
                mem_f.close()
        except:
            pass
        if not candidates:
            self.is_scanning = False
            return
        print(f"  [Validating {len(candidates)} structural anchors...]")
        valid = []
        try:
            with open(f'/proc/{self.pid}/mem', 'rb', 0) as mem:
                for addr in candidates:
                    try:
                        mem.seek(addr - 336)
                        v = struct.unpack('<d', mem.read(8))[0]
                        if v >= save_money and v < save_money + 1000000:
                            valid.append((addr - 336, 'double'))
                    except:
                        continue
        except:
            pass
        if valid:
            self.money_addr, self.money_type = valid[-1]
            print(f"  [Live Link Established (Struct Offset): {hex(self.money_addr)}]")
        self.is_scanning = False

    def read_live_money(self):
        if self.mock or not self.pid or not self.money_addr:
            return self.data.get("GameState", {}).get("Money", 0)
        try:
            with open(f'/proc/{self.pid}/mem', 'rb', 0) as mem:
                mem_file = mem
                mem_file.seek(self.money_addr)
                if self.money_type == 'int':
                    return struct.unpack('<i', mem_file.read(4))[0]
                elif self.money_type == 'float':
                    return int(struct.unpack('<f', mem_file.read(4))[0])
                elif self.money_type == 'double':
                    return int(struct.unpack('<d', mem_file.read(8))[0])
                else:
                    return self.data.get("GameState", {}).get("Money", 0)
        except:
            self.money_addr = None
            return self.data.get("GameState", {}).get("Money", 0)

    def load_data(self):
        if self.mock:
            self.data = {"GameState": {"Money": 5000}, "OpenedCountries": [], "Warehouses": [], "Routes": [], "Packages": [], "Planes": []}
            return True
        if not os.path.exists(self.file_path):
            return False
        try:
            mtime = os.path.getmtime(self.file_path)
            if mtime <= self.last_mtime:
                return False
            self.last_mtime = mtime
            with gzip.open(self.file_path, 'rb') as f:
                self.data = json.load(f)
            self.last_update_str = time.strftime('%H:%M:%S')
            self.analyze_flow_data()
            return True
        except:
            return False

    def analyze_flow_data(self):
        raw_warehouses = self.data.get("Warehouses", [])
        raw_routes = self.data.get("Routes", [])
        raw_packages = self.data.get("Packages", [])
        raw_planes = self.data.get("Planes", [])
        warehouses = {w['Id']: {
            'Name': w.get('Name', f"Hub-{w['Id']}"),
            'Country': w.get('AssignedCountryName', '?'),
            'Level': w.get('Level', 1),
            'Capacity': w.get('Level', 1) * 40,
            'Pkgs': len(w.get('PackageIds', [])),
            'TotalProcessed': w.get('TotalPackagesProcessed', 0)
        } for w in raw_warehouses}
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
        total_backlog = sum(w['Pkgs'] for w in warehouses.values())
        dest_counter = Counter()
        for p in raw_packages:
            d = p.get("DestinationWarehouseId")
            if d in warehouses:
                dest_counter[warehouses[d]['Country']] += 1
        self.extracted_data = {
            "Total Hubs": len(warehouses),
            "Total Routes": len(routes),
            "Total Planes": len(planes),
            "Global Backlog": total_backlog,
            "Top Demand": dest_counter.most_common(3)
        }
        opts = []
        sorted_hubs = sorted(
            [w for w in warehouses.values() if w['Pkgs'] > 0],
            key=lambda w: w['Pkgs'] / w['Capacity'] if w['Capacity'] else 0,
            reverse=True
        )
        for w in sorted_hubs[:2]:
            util = (w['Pkgs'] / w['Capacity']) * 100
            if util > 75:
                opts.append(f"🚨 BOTTLENECK: {w['Name']} ({w['Country']}) is at {util:.0f}% capacity ({w['Pkgs']}/{w['Capacity']}). Upgrade level!")
        route_waitlist = Counter()
        for p in raw_packages:
            path = p.get("DeliveryPathRouteIds", [])
            if path:
                route_waitlist[path[0]] += 1
        direct_edges = set(route_edges.values())
        indirect_traffic = Counter()
        for p in raw_packages:
            o, d = p.get("OriginWarehouseId"), p.get("DestinationWarehouseId")
            if o and d:
                edge = tuple(sorted((o, d)))
                if edge not in direct_edges:
                    indirect_traffic[edge] += 1
        for (a, b), count in indirect_traffic.most_common(2):
            if count >= 10:
                name_a = warehouses.get(a, {}).get('Name', f"Hub-{a}")
                name_b = warehouses.get(b, {}).get('Name', f"Hub-{b}")
                opts.append(f"🛫 MISSING ROUTE: {name_a} ↔ {name_b} has {count} pkgs forced to transfer. Build it!")
        route_stress = []
        for r_id, route in routes.items():
            o, d = route['OriginWarehouseId'], route['DestinationWarehouseId']
            name_o = warehouses.get(o, {}).get('Name', '?')
            name_d = warehouses.get(d, {}).get('Name', '?')
            rt_planes = route_planes.get(r_id, [])
            total_cap = sum(p.get('Capacity', 10) for p in rt_planes)
            waiting = route_waitlist.get(r_id, 0)
            if waiting > total_cap * 2 and waiting > 20:
                route_stress.append((waiting, total_cap, name_o, name_d, len(rt_planes)))
        route_stress.sort(reverse=True)
        for w, cap, no, nd, count in route_stress[:4]:
            opts.append(f"⚠️ UPGRADE ROUTE: {no} ↔ {nd} has {w} pkgs waiting but {count} plane(s) (cap: {cap})!")
        self.optimizations = list(dict.fromkeys(opts))[:10]

    def update_income(self):
        now = time.time()
        self.money_history.append((now, self.live_money))
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
        try:
            while True:
                save_updated = self.load_data()
                if save_updated:
                    self.auto_scan_money()
                new_money = self.read_live_money()
                if abs(new_money - self.data.get("GameState", {}).get("Money", 0)) > 50000:
                    self.auto_scan_money()
                self.live_money = new_money
                self.update_income()
                os.system('clear')
                print("=== Fly Corp Flow Optimizer (V8 - Dynamic State) ===")
                print(f"💰 Money: ${self.live_money:,.0f} | 📈 Live Income: {('+$' if self.income_per_sec >= 0 else '-$')}{abs(self.income_per_sec):,.1f}/sec")
                print(f"💾 Last Save: {self.last_update_str} | Memory: {hex(self.money_addr) if self.money_addr else 'Searching...'}")
                print("-" * 60)
                if self.is_scanning:
                    print("  [SYSTEM: Scanning memory for live link...]")
                else:
                    opened = self.data.get("OpenedCountries", [])
                    targets = [c for c in self.HIGH_WEIGHT if c not in opened]
                    if targets and self.live_money > 2000 and self.income_per_sec > 100:
                        print(f"  🌟 EXPANSION: High income detected! Consider unlocking {targets[0]}.")
                    elif targets and self.income_per_sec > 0:
                        eth = 5000 + (len(opened) * 2000)
                        if self.live_money < eth:
                            time_left = (eth - self.live_money) / self.income_per_sec
                            if time_left < 300:
                                print(f"  ⏳ GOAL ETA: You will afford expansion roughly in {time_left / 60:.1f}m at current income.")
                    print("\n📊 EXTRACTED DATA:")
                    if not self.extracted_data:
                        print("  [Waiting for save file data...]")
                    else:
                        for k, v in self.extracted_data.items():
                            if k == "Top Demand":
                                top_str = ", ".join([f"{c} ({cnt})" for c, cnt in v])
                                print(f"  * {k}: {top_str}")
                            else:
                                print(f"  * {k}: {v:,}")
                    print("\n🔧 OPTIMIZATIONS:")
                    if not self.optimizations:
                        print("  * Network is running smoothly!")
                    else:
                        for opt in self.optimizations:
                            print(f"  * {opt}")
                h = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][int(time.time() * 10) % 10]
                print(f"\n[{h}] Live Monitoring... (Ctrl+C to stop)")
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file")
    args = parser.parse_args()
    default_path = "/home/deck/.local/share/Steam/steamapps/compatdata/1372530/pfx/drive_c/users/steamuser/AppData/LocalLow/KishMish Games/Fly Corp/CargoSaves/save_slot_0.json"
    path = args.file if args.file else default_path
    FlyCorpAdvisor(path).run()