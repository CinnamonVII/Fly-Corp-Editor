#!/usr/bin/env python3
import json
import os
import sys
import argparse

class FlyCorpEditor:
    def __init__(self, file_path, mock=False):
        self.file_path = file_path
        self.mock = mock
        self.data = {}
        self.load_data()

    def load_data(self):
        if self.mock:
            self.data = {
                "money": {"__type": "int", "value": 1000},
                "unlockedCountries": {"__type": "System.Collections.Generic.List`1[[System.String]]", "value": ["USA", "Russia", "UK", "Germany", "France"]},
                "allCountries": {"__type": "System.Collections.Generic.List`1[[System.String]]", "value": [
                    "USA", "Russia", "UK", "Germany", "France", "China", "Japan", "Brazil", 
                    "Canada", "Australia", "India", "Italy", "Spain", "Mexico", "South Korea",
                    "Indonesia", "Netherlands", "Saudi Arabia", "Turkey", "Switzerland", "Poland",
                    "Argentina", "Sweden", "Belgium", "Thailand", "Austria"
                ]}
            }
            return

        if not os.path.exists(self.file_path):
            print(f"Error: File not found at {self.file_path}")
            sys.exit(1)

        try:
            with open(self.file_path, 'rb') as f:
                raw_data = f.read()
            
            payload = raw_data
            self.binary_header = b""
            self.binary_footer = b""
            
            if raw_data.startswith(b'\x00\x01\x00\x00\x00'):
                idx = raw_data.find(b'\x06\x01\x00\x00\x00')
                if idx != -1:
                    p = idx + 5
                    length = 0
                    shift = 0
                    while True:
                        b = raw_data[p]
                        p += 1
                        length |= (b & 0x7F) << shift
                        if not (b & 0x80): break
                        shift += 7
                    self.binary_header = raw_data[:p]
                    payload = raw_data[p:p+length]
                    self.binary_footer = raw_data[p+length:]
                    print(f"Extracted payload ({len(payload)} bytes) from BinaryFormatter.")

            detected_key = None
            for k in range(256):
                if payload and (payload[0] ^ k) == ord('{'):
                    test_str = "".join([chr(b ^ k) for b in payload[:10]])
                    if test_str.startswith('{"') or test_str.startswith('{\n') or test_str.startswith('{ '):
                        detected_key = k
                        break
            
            if detected_key is not None:
                print(f"Detected XOR key: {detected_key}")
                self.xor_key = detected_key
                decoded = "".join([chr(b ^ detected_key) for b in payload])
                self.data = json.loads(decoded)
                print("Successfully parsed save data.")
            else:
                try:
                    self.data = json.loads(payload.decode('utf-8'))
                    self.xor_key = None
                    print("Successfully parsed as plain JSON.")
                except:
                    print("Error: Could not decode save file.")
                    sys.exit(1)
        except Exception as e:
            print(f"Error loading save file: {e}")
            sys.exit(1)

    def save_data(self):
        if self.mock:
            print("[MOCK] Data would be saved now.")
            return

        try:
            backup_path = self.file_path + ".bak"
            import shutil
            if os.path.exists(self.file_path):
                shutil.copy2(self.file_path, backup_path)
                print(f"Backup created at {backup_path}")

            json_str = json.dumps(self.data, separators=(',', ':'))
            if getattr(self, 'xor_key', None) is not None:
                payload = bytes([ord(c) ^ self.xor_key for c in json_str])
            else:
                payload = json_str.encode('utf-8')

            if getattr(self, 'binary_header', None):
                length = len(payload)
                len_bytes = bytearray()
                while length >= 0x80:
                    len_bytes.append((length & 0x7F) | 0x80)
                    length >>= 7
                len_bytes.append(length)
                
                idx = self.binary_header.find(b'\x06\x01\x00\x00\x00')
                header_base = self.binary_header[:idx+5]
                full_data = header_base + len_bytes + payload + self.binary_footer
            else:
                full_data = payload

            with open(self.file_path, 'wb') as f:
                f.write(full_data)
            print("Successfully saved changes!")
        except Exception as e:
            print(f"Error saving file: {e}")

    def modify_money(self):
        money_obj = self.data.setdefault("money", {"__type": "int", "value": 0})
        current_money = money_obj.get("value", 0)
        
        print(f"\nCurrent Money: {current_money}")
        new_money = input("Enter new amount: ")
        try:
            money_obj["value"] = int(new_money)
            print("Money updated.")
        except ValueError:
            print("Invalid input.")

    def country_browser(self):
        while True:
            unlocked_obj = self.data.setdefault("unlockedCountries", {"__type": "System.Collections.Generic.List`1[[System.String]]", "value": []})
            all_obj = self.data.get("allCountries", {"__type": "System.Collections.Generic.List`1[[System.String]]", "value": []})
            
            unlocked = unlocked_obj.get("value", [])
            all_possible = list(all_obj.get("value", unlocked))
            all_possible.sort()
            
            os.system('clear')
            print("=== Fly Corp Country Browser ===")
            print(f"Total: {len(all_possible)} | Unlocked: {len(unlocked)}\n")
            
            half = (len(all_possible) + 1) // 2
            for i in range(half):
                c1 = all_possible[i]
                s1 = "[X]" if c1 in unlocked else "[ ]"
                col1 = f"{i+1:3}. {s1} {c1[:15]:<15}"
                
                if i + half < len(all_possible):
                    c2 = all_possible[i + half]
                    s2 = "[X]" if c2 in unlocked else "[ ]"
                    col2 = f"{i+half+1:3}. {s2} {c2[:15]:<15}"
                else:
                    col2 = ""
                print(f"{col1} | {col2}")

            print("\nCommands: 'a' (Unlock All), 'n' (Lock All), number (Toggle), 'q' (Back)")
            choice = input("\nChoice: ").lower().strip()

            if choice == 'q':
                break
            elif choice == 'a':
                unlocked_obj["value"] = list(all_possible)
            elif choice == 'n':
                unlocked_obj["value"] = []
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(all_possible):
                    country = all_possible[idx]
                    if country in unlocked:
                        unlocked.remove(country)
                    else:
                        unlocked.append(country)
                unlocked_obj["value"] = list(unlocked)

    def main_menu(self):
        while True:
            os.system('clear')
            print("\n=== Fly Corp Save Editor ===")
            print(f"File: {self.file_path}")
            print("1. Modify Money")
            print("2. Country Browser")
            print("3. Unlock All Countries")
            print("4. Save and Exit")
            print("5. Exit without saving")

            choice = input("\nSelect an option: ")

            if choice == '1':
                self.modify_money()
            elif choice == '2':
                self.country_browser()
            elif choice == '3':
                unlocked_obj = self.data.setdefault("unlockedCountries", {"__type": "System.Collections.Generic.List`1[[System.String]]", "value": []})
                all_obj = self.data.get("allCountries", unlocked_obj)
                all_possible = all_obj.get("value", unlocked_obj.get("value", []))
                
                unlocked_obj["value"] = list(all_possible)
                print("All available countries unlocked!")
            elif choice == '4':
                self.save_data()
                break
            elif choice == '5':
                break
            else:
                print("Invalid choice.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fly Corp Save Editor")
    parser.add_argument("--file", help="Path to save1.dat")
    parser.add_argument("--mock", action="store_true", help="Run with mock data for testing")
    args = parser.parse_args()

    if not args.file and not args.mock:
        default_path = os.path.expanduser("~/.steam/steam/steamapps/common/Fly Corp/Fly Corp_Data/StreamingAssets/PlayerSaves/save1.dat")
        if os.path.exists(default_path):
            args.file = default_path
        else:
            print(f"Default save file not found at {default_path}")
            print("Please provide path with --file")
            sys.exit(1)

    editor = FlyCorpEditor(args.file, mock=args.mock)
    editor.main_menu()
