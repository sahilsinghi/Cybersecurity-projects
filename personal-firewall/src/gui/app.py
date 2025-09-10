import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
import threading
import time
from pathlib import Path
import os
import sys

# make sure we can import from ../core
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core import rules

LOG_FILE = "data/logs/traffic.log"

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Personal Firewall")
        self.root.geometry("800x450")

        # Title label
        tk.Label(root, text="Personal Firewall Monitor", font=("Arial", 14, "bold")).pack(pady=10)

        # Buttons frame
        button_frame = tk.Frame(root)
        button_frame.pack(pady=5)

        # Block ICMP button
        icmp_btn = ttk.Button(button_frame, text="Block All ICMP", command=self.block_icmp)
        icmp_btn.grid(row=0, column=0, padx=5, pady=5)

        # Reset Rules button
        reset_btn = ttk.Button(button_frame, text="Reset Rules", command=self.reset_rules)
        reset_btn.grid(row=0, column=1, padx=5, pady=5)

        # Profiles dropdown
        self.profile_var = tk.StringVar(value="Home")
        profiles = ["Home", "Public", "Office"]
        profile_menu = ttk.OptionMenu(button_frame, self.profile_var, profiles[0], *profiles, command=self.switch_profile)
        profile_menu.grid(row=0, column=2, padx=5, pady=5)

        # Log box
        self.log_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=22)
        self.log_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Start background log watcher
        self.stop_flag = False
        t = threading.Thread(target=self.watch_log, daemon=True)
        t.start()

    def block_icmp(self):
        rules.add_rule({"protocol": "ICMP", "action": "BLOCK"})
        self.log_box.insert(tk.END, "[*] Rule added: Block all ICMP traffic\n")
        self.log_box.see(tk.END)

    def reset_rules(self):
        rules.reset_rules()
        self.log_box.insert(tk.END, "[*] All rules have been reset (default allow).\n")
        self.log_box.see(tk.END)

    def switch_profile(self, choice):
        rules.reset_rules()
        if choice == "Home":
            self.log_box.insert(tk.END, "[*] Profile set: Home (allow all)\n")
        elif choice == "Public":
            rules.add_rule({"protocol": "ICMP", "action": "BLOCK"})
            self.log_box.insert(tk.END, "[*] Profile set: Public (block ICMP)\n")
        elif choice == "Office":
            rules.add_rule({"protocol": "ICMP", "action": "BLOCK"})
            self.log_box.insert(tk.END, "[*] Profile set: Office (block ICMP)\n")
        self.log_box.see(tk.END)

    def watch_log(self):
        # Wait until the sniffer creates the file
        while not Path(LOG_FILE).exists() and not self.stop_flag:
            time.sleep(0.5)

        if self.stop_flag:
            return

        try:
            # Open log file in read-only mode
            with open(LOG_FILE, "r") as f:
                f.seek(0, os.SEEK_END)  # tail from end
                while not self.stop_flag:
                    line = f.readline()
                    if line:
                        self.log_box.insert(tk.END, line)
                        self.log_box.see(tk.END)
                    else:
                        time.sleep(0.3)
        except PermissionError:
            self.log_box.insert(tk.END, "[!] Permission denied reading traffic.log. Fix permissions.\n")
            self.log_box.see(tk.END)

    def on_close(self):
        self.stop_flag = True
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

