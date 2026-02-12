import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from pathlib import Path

from Core.scanner import FileScanner
from Core.types import ThreatLevel


class ModernScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AegisAI Scanner")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
       
        # Dark theme colors (unchanged)
        self.bg_dark = "#0a0e14"
        self.bg_secondary = "#1a1f2e"
        self.bg_tertiary = "#2a2f3e"
        self.accent_green = "#2d9669"
        self.accent_green_hover = "#3ab87c"
        self.text_primary = "#e6e6e6"
        self.text_secondary = "#a0a0a0"
        self.text_dim = "#606060"
       
        self.scanner = FileScanner()
       
        self.root.configure(bg=self.bg_dark)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
       
        self._create_widgets()
        self._configure_styles()

    def on_closing(self):
        try:
            self.root.quit()
            self.root.destroy()
        except:
            pass

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("Dark.TFrame", background=self.bg_dark)
        style.configure("Secondary.TFrame", background=self.bg_secondary, borderwidth=0)
        style.configure("Card.TFrame", background=self.bg_secondary, relief="flat")
        
        style.configure("Title.TLabel", background=self.bg_dark, foreground=self.text_primary,
                        font=("Segoe UI", 24, "bold"))
        style.configure("Subtitle.TLabel", background=self.bg_dark, foreground=self.text_secondary,
                        font=("Consolas", 9))
        style.configure("SectionHeader.TLabel", background=self.bg_secondary, foreground=self.text_dim,
                        font=("Consolas", 9))
        
        style.configure("Green.TButton", background=self.accent_green, foreground="white",
                        borderwidth=0, focuscolor="none", font=("Segoe UI", 10, "bold"), padding=(20, 12))
        style.map("Green.TButton", background=[("active", self.accent_green_hover), ("pressed", self.accent_green)])
        
        style.configure("Dark.TButton", background=self.bg_tertiary, foreground=self.text_secondary,
                        borderwidth=0, focuscolor="none", font=("Segoe UI", 9), padding=(12, 8))
        style.map("Dark.TButton", background=[("active", "#3a3f4e")])
        
        style.configure("Tab.TRadiobutton", background=self.bg_secondary, foreground=self.text_secondary,
                        font=("Segoe UI", 10), borderwidth=0, focuscolor="")
        style.map("Tab.TRadiobutton", background=[("selected", self.bg_secondary)],
                  foreground=[("selected", self.accent_green)])

    def _create_widgets(self):
        main_frame = tk.Frame(self.root, bg=self.bg_dark)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        header_frame = tk.Frame(main_frame, bg=self.bg_dark)
        header_frame.pack(fill=tk.X, pady=(40, 20))
        
        icon_label = tk.Label(header_frame, text="🛡", bg=self.bg_dark, foreground=self.accent_green,
                              font=("Segoe UI", 32))
        icon_label.pack()
        
        title_label = ttk.Label(header_frame, text="AegisAI Scanner", style="Title.TLabel")
        title_label.pack(pady=(5, 5))
        
        subtitle_label = ttk.Label(header_frame, text="Advanced threat detection & file analysis system",
                                  style="Subtitle.TLabel")
        subtitle_label.pack()
        
        content_card = tk.Frame(main_frame, bg=self.bg_secondary,
                                highlightbackground=self.bg_tertiary, highlightthickness=1)
        content_card.pack(fill=tk.BOTH, expand=True, padx=60, pady=20)
        
        mode_frame = tk.Frame(content_card, bg=self.bg_secondary)
        mode_frame.pack(fill=tk.X, padx=30, pady=(30, 20))
        
        self.mode_var = tk.StringVar(value="file")
        
        file_btn_frame = tk.Frame(mode_frame, bg=self.accent_green,
                                  highlightbackground=self.accent_green, highlightthickness=0)
        file_btn_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        self.file_radio = tk.Radiobutton(file_btn_frame,
                                        text="📄  File Scan",
                                        variable=self.mode_var,
                                        value="file",
                                        bg=self.accent_green,
                                        fg="white",
                                        activebackground=self.accent_green_hover,
                                        activeforeground="white",
                                        selectcolor=self.accent_green,
                                        font=("Segoe UI", 11, "bold"),
                                        borderwidth=0,
                                        highlightthickness=0,
                                        indicatoron=False,
                                        pady=12,
                                        cursor="hand2",
                                        command=self._update_mode_colors)
        self.file_radio.pack(fill=tk.BOTH, expand=True)
        
        dir_btn_frame = tk.Frame(mode_frame, bg=self.bg_tertiary,
                                 highlightbackground=self.bg_tertiary, highlightthickness=0)
        dir_btn_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.dir_radio = tk.Radiobutton(dir_btn_frame,
                                       text="📁  Directory Scan",
                                       variable=self.mode_var,
                                       value="directory",
                                       bg=self.bg_tertiary,
                                       fg=self.text_secondary,
                                       activebackground="#3a3f4e",
                                       activeforeground=self.text_primary,
                                       selectcolor=self.bg_tertiary,
                                       font=("Segoe UI", 11),
                                       borderwidth=0,
                                       highlightthickness=0,
                                       indicatoron=False,
                                       pady=12,
                                       cursor="hand2",
                                       command=self._update_mode_colors)
        self.dir_radio.pack(fill=tk.BOTH, expand=True)
        
        path_container = tk.Frame(content_card, bg=self.bg_secondary)
        path_container.pack(fill=tk.X, padx=30, pady=10)
        
        path_input_frame = tk.Frame(path_container, bg=self.bg_tertiary,
                                    highlightbackground="#3a3f4e", highlightthickness=1)
        path_input_frame.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 10))
        
        self.path_var = tk.StringVar()
        path_entry = tk.Entry(path_input_frame,
                              textvariable=self.path_var,
                              bg=self.bg_tertiary,
                              fg=self.text_primary,
                              font=("Consolas", 10),
                              borderwidth=0,
                              highlightthickness=0,
                              insertbackground=self.accent_green,
                              relief="flat")
        path_entry.pack(fill=tk.BOTH, expand=True, padx=15, pady=12)
        
        path_entry.insert(0, "Enter file path or click Browse...")
        path_entry.config(fg=self.text_dim)
        
        def on_focus_in(event):
            if path_entry.get() == "Enter file path or click Browse...":
                path_entry.delete(0, tk.END)
                path_entry.config(fg=self.text_primary)
        
        def on_focus_out(event):
            if not path_entry.get():
                path_entry.insert(0, "Enter file path or click Browse...")
                path_entry.config(fg=self.text_dim)
        
        path_entry.bind("<FocusIn>", on_focus_in)
        path_entry.bind("<FocusOut>", on_focus_out)
        
        browse_btn = tk.Button(path_container,
                               text="Browse",
                               command=self.browse,
                               bg=self.bg_tertiary,
                               fg=self.text_primary,
                               font=("Segoe UI", 10),
                               borderwidth=0,
                               highlightthickness=0,
                               activebackground="#3a3f4e",
                               activeforeground="white",
                               cursor="hand2",
                               padx=20,
                               pady=12)
        browse_btn.pack(side=tk.LEFT)
        
        action_frame = tk.Frame(content_card, bg=self.bg_secondary)
        action_frame.pack(fill=tk.X, padx=30, pady=15)
        
        scan_btn = tk.Button(action_frame,
                             text="▶  Start Scan",
                             command=self.start_scan,
                             bg=self.accent_green,
                             fg="white",
                             font=("Segoe UI", 11, "bold"),
                             borderwidth=0,
                             highlightthickness=0,
                             activebackground=self.accent_green_hover,
                             activeforeground="white",
                             cursor="hand2",
                             pady=14)
        scan_btn.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        clear_btn = tk.Button(action_frame,
                              text="🗑  Clear",
                              command=self.clear_results,
                              bg=self.bg_tertiary,
                              fg=self.text_secondary,
                              font=("Segoe UI", 10),
                              borderwidth=0,
                              highlightthickness=0,
                              activebackground="#3a3f4e",
                              activeforeground=self.text_primary,
                              cursor="hand2",
                              padx=25,
                              pady=14)
        clear_btn.pack(side=tk.LEFT)
        
        results_container = tk.Frame(content_card, bg=self.bg_secondary)
        results_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10, 30))
        
        results_header = tk.Frame(results_container, bg=self.bg_secondary)
        results_header.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(results_header, 
                  text="▶  scan_results",
                  style="SectionHeader.TLabel").pack(side=tk.LEFT)
        
        results_frame = tk.Frame(results_container, bg=self.bg_tertiary)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.result_text = tk.Text(results_frame,
                                   wrap=tk.WORD,
                                   bg=self.bg_tertiary,
                                   fg=self.text_secondary,
                                   font=("Consolas", 10),
                                   borderwidth=0,
                                   highlightthickness=0,
                                   insertbackground=self.accent_green,
                                   padx=15,
                                   pady=15,
                                   state="disabled")
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(results_frame, 
                                 command=self.result_text.yview,
                                 bg=self.bg_tertiary,
                                 troughcolor=self.bg_tertiary,
                                 activebackground=self.text_dim,
                                 width=12,
                                 borderwidth=0,
                                 highlightthickness=0)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.config(yscrollcommand=scrollbar.set)
        
        # Text tags
        self.result_text.tag_configure("malicious", foreground="#ff4757", font=("Consolas", 10, "bold"))
        self.result_text.tag_configure("suspicious", foreground="#ffa502")
        self.result_text.tag_configure("clean", foreground="#2ed573")
        self.result_text.tag_configure("header", foreground=self.text_primary, font=("Consolas", 11, "bold"))
        self.result_text.tag_configure("empty", foreground=self.text_dim, font=("Segoe UI", 10))
        self.result_text.tag_configure("icon", foreground=self.text_dim, font=("Segoe UI", 32))
        self.result_text.tag_configure("danger_header", foreground="#ff4757", font=("Segoe UI", 14, "bold"))
        self.result_text.tag_configure("danger_item", foreground="#ff9999")
        
        self._show_empty_state()

    def _update_mode_colors(self):
        if self.mode_var.get() == "file":
            self.file_radio.config(bg=self.accent_green, fg="white", 
                                  font=("Segoe UI", 11, "bold"))
            self.dir_radio.config(bg=self.bg_tertiary, fg=self.text_secondary,
                                 font=("Segoe UI", 11))
        else:
            self.dir_radio.config(bg=self.accent_green, fg="white",
                                 font=("Segoe UI", 11, "bold"))
            self.file_radio.config(bg=self.bg_tertiary, fg=self.text_secondary,
                                  font=("Segoe UI", 11))

    def _show_empty_state(self):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        
        self.result_text.insert("1.0", "\n\n\n\n")
        self.result_text.insert(tk.END, "🛡\n", "icon")
        self.result_text.insert(tk.END, "\nNo scan results yet\n", "empty")
        self.result_text.insert(tk.END, "Select a target and start scanning", "empty")
        
        self.result_text.tag_configure("icon", justify="center")
        self.result_text.tag_configure("empty", justify="center")
        
        self.result_text.config(state="disabled")

    def clear_results(self):
        self._show_empty_state()

    def browse(self):
        if self.mode_var.get() == "file":
            path = filedialog.askopenfilename(
                title="Select File to Scan",
                filetypes=[("All Files", "*.*"), ("Executables", "*.exe *.dll *.scr *.bat")]
            )
        else:
            path = filedialog.askdirectory(title="Select Directory to Scan")

        if path:
            self.path_var.set(path)

    def start_scan(self):
        path_str = self.path_var.get().strip()
        
        if not path_str or path_str == "Enter file path or click Browse...":
            messagebox.showwarning("No path", "Please select a file or directory first.",
                                 parent=self.root)
            return

        target = Path(path_str)
        if not target.exists():
            messagebox.showerror("Error", f"Path does not exist:\n{target}",
                               parent=self.root)
            return

        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, f"Scanning: {target}\n\n", "header")
        self.result_text.see(tk.END)
        self.result_text.config(state="disabled")

        results = []
        danger_results = []  # collect malicious & suspicious here

        try:
            if self.mode_var.get() == "file":
                if not target.is_file():
                    messagebox.showerror("Error", "Selected path is not a file.",
                                       parent=self.root)
                    return
                result = self.scanner.scan_file(target)
                results.append(result)
                self._display_result(result)
                if result.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS):
                    danger_results.append(result)

            else:  # directory
                if not target.is_dir():
                    messagebox.showerror("Error", "Selected path is not a directory.",
                                       parent=self.root)
                    return

                self.result_text.config(state="normal")
                self.result_text.insert(tk.END, "Scanning directory (recursive)...\n\n", "header")
                self.result_text.config(state="disabled")

                count = 0
                for result in self.scanner.scan_directory(target, recursive=True):
                    count += 1
                    self._display_result(result)
                    results.append(result)
                    if result.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS):
                        danger_results.append(result)

                    if count % 20 == 0:
                        self.root.update_idletasks()

                self.result_text.config(state="normal")
                self.result_text.insert(tk.END, f"\nFinished. Scanned {count} files.\n", "header")
                self.result_text.config(state="disabled")

        except Exception as e:
            self.result_text.config(state="normal")
            self.result_text.insert(tk.END, f"\nError during scan: {str(e)}\n", "error")
            self.result_text.config(state="disabled")
            return

        # Show Danger Zone section (only if there are risky files)
        if danger_results:
            self.result_text.config(state="normal")
            self.result_text.insert(tk.END, "\n" + "═" * 80 + "\n", "header")
            self.result_text.insert(tk.END, "DANGER ZONE – Review These Files Carefully\n", "danger_header")
            self.result_text.insert(tk.END, "═" * 80 + "\n\n", "header")

            for result in danger_results:
                if result.threat_level == ThreatLevel.MALICIOUS:
                    tag = "malicious"
                    prefix = "MALICIOUS "
                else:
                    tag = "suspicious"
                    prefix = "SUSPICIOUS "

                line = f"{prefix} {result.file_path.name}"
                if result.reason:
                    line += f" → {result.reason}"
                if result.signature_match:
                    line += f"  [Signature: {result.signature_match}]"

                self.result_text.insert(tk.END, line + "\n", tag)

                if result.hash_value and isinstance(result.hash_value, dict):
                    self.result_text.insert(tk.END, "  Hashes:\n", "clean")
                    for algo, h in result.hash_value.items():
                        self.result_text.insert(tk.END, f"    {algo.upper()}: {h}\n", "clean")

                self.result_text.insert(tk.END, "\n")

            self.result_text.config(state="disabled")
            self.result_text.see(tk.END)

        # Final summary
        malicious = sum(1 for r in results if r.threat_level == ThreatLevel.MALICIOUS)
        suspicious = sum(1 for r in results if r.threat_level == ThreatLevel.SUSPICIOUS)

        summary = (
            f"\nSummary:\n"
            f"  Malicious:   {malicious}\n"
            f"  Suspicious:  {suspicious}\n"
            f"  Clean:       {len(results) - malicious - suspicious}\n"
        )
        
        self.result_text.config(state="normal")
        self.result_text.insert(tk.END, summary, "header")
        self.result_text.see(tk.END)
        self.result_text.config(state="disabled")

    def _display_result(self, result):
        if result.threat_level == ThreatLevel.MALICIOUS:
            tag = "malicious"
            prefix = "MALICIOUS "
        elif result.threat_level == ThreatLevel.SUSPICIOUS:
            tag = "suspicious"
            prefix = "SUSPICIOUS "
        else:
            tag = "clean"
            prefix = "CLEAN     "

        line = f"{prefix} {result.file_path.name}"
        if result.reason:
            line += f" → {result.reason}"
        if result.signature_match:
            line += f"  [Signature: {result.signature_match}]"

        self.result_text.config(state="normal")
        self.result_text.insert(tk.END, line + "\n", tag)

        if result.hash_value and isinstance(result.hash_value, dict):
            self.result_text.insert(tk.END, "  Hashes:\n", "clean")
            for algo, h in result.hash_value.items():
                self.result_text.insert(tk.END, f"    {algo.upper()}: {h}\n", "clean")

        self.result_text.insert(tk.END, "\n")
        self.result_text.see(tk.END)
        self.result_text.config(state="disabled")
        self.root.update_idletasks()


def main():
    try:
        root = tk.Tk()
        app = ModernScannerGUI(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication closed by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        try:
            root.destroy()
        except:
            pass


if __name__ == "__main__":
    main()