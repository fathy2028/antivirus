import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
from main import scan_path, load_signatures, list_quarantine, restore_quarantined_file, delete_quarantined_file
from main import CONFIG

class AntivirusUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Antivirus Scanner")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5)
        self.style.configure('TLabel', padding=5)
        self.style.configure('TFrame', padding=5)
        
        # Create main container
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.scan_tab = ttk.Frame(self.notebook)
        self.quarantine_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.scan_tab, text="Scan")
        self.notebook.add(self.quarantine_tab, text="Quarantine")
        self.notebook.add(self.logs_tab, text="Logs")
        
        self.setup_scan_tab()
        self.setup_quarantine_tab()
        self.setup_logs_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_scan_tab(self):
        # Scan frame
        scan_frame = ttk.LabelFrame(self.scan_tab, text="Scan Options", padding="10")
        scan_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Path selection
        path_frame = ttk.Frame(scan_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(path_frame, text="Path to scan:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var, width=50)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse_path)
        browse_btn.pack(side=tk.LEFT)
        
        # Action selection
        action_frame = ttk.Frame(scan_frame)
        action_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(action_frame, text="Action on detection:").pack(side=tk.LEFT)
        self.action_var = tk.StringVar(value="report")
        actions = ["report", "quarantine", "remove"]
        for action in actions:
            ttk.Radiobutton(action_frame, text=action.capitalize(), 
                          variable=self.action_var, value=action).pack(side=tk.LEFT, padx=5)
        
        # Scan button
        scan_btn = ttk.Button(scan_frame, text="Start Scan", command=self.start_scan)
        scan_btn.pack(pady=10)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(scan_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(scan_frame, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)

    def setup_quarantine_tab(self):
        # Quarantine frame
        quarantine_frame = ttk.LabelFrame(self.quarantine_tab, text="Quarantined Items", padding="10")
        quarantine_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Quarantine list
        self.quarantine_tree = ttk.Treeview(quarantine_frame, columns=("ID", "Original Path", "Reason", "Date"), show="headings")
        self.quarantine_tree.heading("ID", text="ID")
        self.quarantine_tree.heading("Original Path", text="Original Path")
        self.quarantine_tree.heading("Reason", text="Reason")
        self.quarantine_tree.heading("Date", text="Date")
        
        self.quarantine_tree.column("ID", width=100)
        self.quarantine_tree.column("Original Path", width=300)
        self.quarantine_tree.column("Reason", width=200)
        self.quarantine_tree.column("Date", width=150)
        
        self.quarantine_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Buttons frame
        btn_frame = ttk.Frame(quarantine_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        refresh_btn = ttk.Button(btn_frame, text="Refresh", command=self.refresh_quarantine)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        restore_btn = ttk.Button(btn_frame, text="Restore Selected", command=self.restore_selected)
        restore_btn.pack(side=tk.LEFT, padx=5)
        
        delete_btn = ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected)
        delete_btn.pack(side=tk.LEFT, padx=5)
        
        # Load initial quarantine list
        self.refresh_quarantine()

    def setup_logs_tab(self):
        # Logs frame
        logs_frame = ttk.LabelFrame(self.logs_tab, text="Scan Logs", padding="10")
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, wrap=tk.WORD)
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        
        # Load initial logs
        self.load_logs()

    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.path_var.set(path)

    def start_scan(self):
        path = self.path_var.get()
        action = self.action_var.get()
        
        if not path:
            messagebox.showerror("Error", "Please select a path to scan")
            return
        
        self.status_var.set("Scanning...")
        self.progress_var.set(0)
        self.results_text.delete(1.0, tk.END)
        
        # Start scan in a separate thread
        threading.Thread(target=self.run_scan, args=(path, action), daemon=True).start()

    def run_scan(self, path, action):
        try:
            signatures = load_signatures(CONFIG["signature_db"])
            results = scan_path(path, signatures, action)
            
            self.root.after(0, self.update_scan_results, results)
        except Exception as e:
            self.root.after(0, self.show_error, str(e))

    def update_scan_results(self, results):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Scan Results:\n")
        self.results_text.insert(tk.END, f"Files Scanned: {results['files_scanned']}\n")
        self.results_text.insert(tk.END, f"Threats Found: {results['threats_found']}\n")
        self.results_text.insert(tk.END, f"Actions Taken: {results['actions_taken']}\n")
        self.results_text.insert(tk.END, f"Errors: {results['errors']}\n")
        
        self.progress_var.set(100)
        self.status_var.set("Scan Complete")
        self.load_logs()

    def refresh_quarantine(self):
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())
        items = list_quarantine()
        
        for item in items:
            self.quarantine_tree.insert("", tk.END, values=(
                item.get('id', 'N/A'),
                item.get('original_path', 'N/A'),
                item.get('reason', 'N/A'),
                item.get('date', 'N/A')
            ))

    def restore_selected(self):
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an item to restore")
            return
        
        item_id = self.quarantine_tree.item(selected[0])['values'][0]
        if messagebox.askyesno("Confirm", "Are you sure you want to restore this item?"):
            restore_quarantined_file(item_id)
            self.refresh_quarantine()

    def delete_selected(self):
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an item to delete")
            return
        
        item_id = self.quarantine_tree.item(selected[0])['values'][0]
        if messagebox.askyesno("Confirm", "Are you sure you want to permanently delete this item?"):
            delete_quarantined_file(item_id)
            self.refresh_quarantine()

    def load_logs(self):
        try:
            with open(CONFIG["log_file"], 'r') as f:
                logs = f.read()
            self.logs_text.delete(1.0, tk.END)
            self.logs_text.insert(tk.END, logs)
        except Exception as e:
            self.logs_text.delete(1.0, tk.END)
            self.logs_text.insert(tk.END, f"Error loading logs: {str(e)}")

    def show_error(self, error_msg):
        messagebox.showerror("Error", error_msg)
        self.status_var.set("Error occurred")
        self.progress_var.set(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusUI(root)
    root.mainloop() 