import time
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import pandas as pd
import os
import subprocess
import threading
import atexit
from PIL import Image, ImageTk
import defense
import live_inference

# Set the modern dark theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class IDS_Dashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("XAI-IDS | Security Operations Center")
        self.geometry("1200x800")
        
        # --- PREVENTION STATE ---
        self.is_preventing = False
        self.attacker_ip = "192.168.56.101" # Set this to your Kali IP
        
        # Configure Grid Layout (4 rows, 2 columns)
        self.grid_columnconfigure(0, weight=2) 
        self.grid_columnconfigure(1, weight=1) 
        self.grid_rowconfigure(2, weight=1)    
        
        # --- UI SETUP ---
        self.setup_ui()
        
        # --- START BACKGROUND BACKEND ---
        self.start_backend_monitor()
        
        # --- BACKGROUND GUI CHECK ---
        self.update_dashboard()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def toggle_prevention(self):
        """Toggles the Active Prevention system using PowerShell Isolation."""
        if not self.is_preventing:
            # SCRIPT TO ENABLE BLOCK
            ps_cmd = f"New-NetFirewallRule -DisplayName 'IDS_TOGGLE_BLOCK' -Direction Inbound -Action Block -RemoteAddress {self.attacker_ip} -Protocol Any -Profile Any"
            try:
                subprocess.run(["powershell", "-Command", ps_cmd], check=True, shell=True)
                self.is_preventing = True
                self.btn_prevent.configure(text="DISABLE ACTIVE PREVENTION", fg_color="#FF4500", hover_color="#B22222")
                self.log_event(f"PREVENTION ARMED: Isolated {self.attacker_ip} via Firewall.")
                messagebox.showwarning("Active Prevention", f"Host {self.attacker_ip} has been fully isolated.")
            except Exception as e:
                self.log_event(f"ERROR: Failed to enable block. Run as Admin! {e}")
                messagebox.showerror("Permission Error", "Please run this application as Administrator to modify firewall rules.")
        else:
            # SCRIPT TO DISABLE BLOCK
            ps_cmd = "Remove-NetFirewallRule -DisplayName 'IDS_TOGGLE_BLOCK'"
            try:
                subprocess.run(["powershell", "-Command", ps_cmd], check=True, shell=True)
                self.is_preventing = False
                self.btn_prevent.configure(text="ENABLE ACTIVE PREVENTION", fg_color="green", hover_color="#006400")
                self.log_event("PREVENTION DISARMED: Firewall rules cleared.")
                messagebox.showinfo("Prevention Disabled", "The attacker IP has been unblocked.")
            except Exception as e:
                self.log_event(f"ERROR: Failed to clear rules: {e}")

    def start_backend_monitor(self):
        self.log_event("Starting Backend Sniffer & AI Model...")
        self.monitor_process = None

        self.log_event("Wiping old traffic logs for a clean startup...")
        files_to_delete = ['outputs/live_features.csv', 'outputs/alerts.csv', 'outputs/shap_alert.png']
        for file in files_to_delete:
            if os.path.exists(file):
                try:
                    os.remove(file)
                except:
                    pass
                    
        def run_sniffer():
            self.monitor_process = subprocess.Popen(["python", "traffic_monitor.py"])
            
        sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        sniffer_thread.start()
        
        def run_inference():
            time.sleep(2) 
            while True:
                try:
                    live_inference.evaluate_traffic()
                except Exception as e:
                    print(f"[ML THREAD ERROR] {e}")
                
                time.sleep(2) 
                
        inference_thread = threading.Thread(target=run_inference, daemon=True)
        inference_thread.start()
        atexit.register(self.kill_backend)

    def setup_ui(self):
        # --- 1. ALERT BANNER ---
        self.banner = ctk.CTkLabel(self, text="SYSTEM SECURE | MONITORING TRAFFIC", 
                                   fg_color="green", text_color="white", 
                                   font=ctk.CTkFont(size=18, weight="bold"), corner_radius=0)
        self.banner.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        # --- 2. STATUS CARDS ---
        self.cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.cards_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=10)
        self.cards_frame.grid_columnconfigure((0, 1, 2), weight=1)
        self.status_card = self.create_card(self.cards_frame, "System Status", "ONLINE", 0)
        self.threat_card = self.create_card(self.cards_frame, "Threat Level", "LOW", 1)
        self.model_card = self.create_card(self.cards_frame, "AI Model", "Random Forest (Active)", 2)

        # --- 3. DETECTED CONNECTIONS TABLE ---
        self.table_frame = ctk.CTkFrame(self)
        self.table_frame.grid(row=2, column=0, sticky="nsew", padx=(20, 10), pady=10)
        ctk.CTkLabel(self.table_frame, text="Active Network Threats", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("Treeview.Heading", background="#1f538d", foreground="white", font=('Arial', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#1f538d')])

        self.tree = ttk.Treeview(self.table_frame, columns=("IP", "Attack", "SHAP", "Bytes", "Protocol"), show="headings", height=10)
        self.tree.heading("IP", text="Source IP")
        self.tree.heading("Attack", text="ML Prediction")
        self.tree.heading("SHAP", text="Top SHAP Feature")
        self.tree.heading("Bytes", text="Bytes")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        # --- 4. XAI SHAP EXPLANATION ---
        self.xai_frame = ctk.CTkFrame(self)
        self.xai_frame.grid(row=2, column=1, sticky="nsew", padx=(10, 20), pady=10)
        ctk.CTkLabel(self.xai_frame, text="Explainable AI (SHAP Analysis)", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.image_label = ctk.CTkLabel(self.xai_frame, text="No anomalies detected.\nWaiting for SHAP data...")
        self.image_label.pack(fill="both", expand=True, padx=10, pady=10)

        # --- 5. SECURITY LOGS ---
        self.logs_frame = ctk.CTkFrame(self)
        self.logs_frame.grid(row=3, column=0, sticky="nsew", padx=(20, 10), pady=(10, 20))
        ctk.CTkLabel(self.logs_frame, text="Real-Time Security Logs", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10)
        self.log_box = ctk.CTkTextbox(self.logs_frame, height=120)
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.log_box.insert("0.0", "[SYSTEM] SOC Dashboard initialized. Awaiting traffic...\n")
        self.log_box.configure(state="disabled") 

        # --- 6. FIREWALL CONTROLS ---
        self.controls_frame = ctk.CTkFrame(self)
        self.controls_frame.grid(row=3, column=1, sticky="nsew", padx=(10, 20), pady=(10, 20))
        ctk.CTkLabel(self.controls_frame, text="Prevention Controls", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        
        # --- NEW TOGGLE BUTTON ---
        self.btn_prevent = ctk.CTkButton(self.controls_frame, text="ENABLE ACTIVE PREVENTION", 
                                          fg_color="green", hover_color="#006400", 
                                          command=self.toggle_prevention)
        self.btn_prevent.pack(pady=(10, 5), padx=20, fill="x")

        self.btn_unblock = ctk.CTkButton(self.controls_frame, text="Reset Firewall (Unblock All IPs)", 
                                         fg_color="#8B0000", hover_color="#5C0000", 
                                         command=self.reset_firewall)
        self.btn_unblock.pack(pady=5, padx=20, fill="x")

    def create_card(self, parent, title, value, col):
        frame = ctk.CTkFrame(parent, fg_color="#1e1e1e", corner_radius=10)
        frame.grid(row=0, column=col, sticky="ew", padx=10)
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=14, weight="bold"), text_color="gray").pack(pady=(10, 0))
        val_label = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=24, weight="bold"))
        val_label.pack(pady=(5, 10))
        return val_label

    def update_dashboard(self):
        if os.path.exists('outputs/alerts.csv'):
            try:
                self.banner.configure(text="⚠️ THREAT DETECTED | INTRUSION PREVENTION ACTIVE", fg_color="#8B0000")
                self.threat_card.configure(text="CRITICAL", text_color="#FF4500")
                self.status_card.configure(text="BLOCKING IPS", text_color="#FF4500")
                
                df = pd.read_csv('outputs/alerts.csv')
                for row in self.tree.get_children():
                    self.tree.delete(row)

                for index, row in df.iterrows():
                    ip = str(row.get('_src_ip_', "Unknown"))
                    attack = str(row.get('Attack_Type', "Anomaly")).upper()
                    shap_reason = str(row.get('SHAP_Reason', "N/A"))  
                    bytes_sent = str(row.get('src_bytes', 0))
                    proto = str(row.get('protocol_type', "N/A"))
                    self.tree.insert("", tk.END, values=(ip, attack, shap_reason, bytes_sent, proto))
                
                if os.path.exists('outputs/shap_alert.png'):
                    try:
                        img = Image.open('outputs/shap_alert.png')
                        img = img.resize((450, 250), Image.Resampling.LANCZOS)
                        photo = ctk.CTkImage(light_image=img, dark_image=img, size=(450, 250))
                        self.image_label.configure(image=photo, text="")
                    except:
                        pass
            except Exception as e:
                print(f"UI Update Error: {e}")
        else:
            self.banner.configure(text="SYSTEM SECURE | MONITORING TRAFFIC", fg_color="green")
            self.threat_card.configure(text="LOW", text_color="white")
            self.status_card.configure(text="ONLINE", text_color="white")
            for row in self.tree.get_children():
                self.tree.delete(row)
            self.image_label.configure(image="", text="No anomalies detected.\nWaiting for SHAP data...")

        self.after(2000, self.update_dashboard)

    def kill_backend(self):
        if self.monitor_process:
            self.monitor_process.kill()

    def log_event(self, message):
        try:
            self.log_box.configure(state="normal")
            timestamp = time.strftime("%H:%M:%S")
            self.log_box.insert("end", f"[{timestamp}] {message}\n")
            self.log_box.see("end") 
            self.log_box.configure(state="disabled")
        except:
            pass

    def reset_firewall(self):
        try:
            defense.unblock_all()
            self.is_preventing = False
            self.btn_prevent.configure(text="ENABLE ACTIVE PREVENTION", fg_color="green")
            self.log_event("Firewall reset initiated. All IDS blocks removed.")
            messagebox.showinfo("Firewall Reset", "All IDS blocking rules have been removed.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {e}")

    def on_closing(self):
        if hasattr(self, 'monitor_process') and self.monitor_process is not None:
            self.monitor_process.terminate()
        self.destroy()
        os._exit(0)

if __name__ == "__main__":
    app = IDS_Dashboard()
    app.mainloop()