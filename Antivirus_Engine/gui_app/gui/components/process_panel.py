"""
Process Monitor Panel Component
Displays running processes with threat analysis
"""

import customtkinter as ctk
from typing import List, Dict, Callable, Optional
import threading

class ProcessPanel(ctk.CTkFrame):
    """Panel for monitoring running processes"""
    
    def __init__(self, parent, on_refresh: Optional[Callable] = None, on_kill: Optional[Callable] = None):
        super().__init__(parent, fg_color="transparent")
        
        self.on_refresh = on_refresh
        self.on_kill = on_kill
        self.processes = []
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # Create UI
        self._create_header()
        self._create_filter_bar()
        self._create_process_list()
        self._create_stats_panel()
    
    def _create_header(self):
        """Create header with title and refresh button"""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        title = ctk.CTkLabel(
            header_frame,
            text="🖥️  Process Monitor",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w")
        
        # Refresh button
        self.refresh_btn = ctk.CTkButton(
            header_frame,
            text="🔄 Refresh",
            width=100,
            command=self._handle_refresh
        )
        self.refresh_btn.grid(row=0, column=1, padx=(10, 0))
        
        # Auto-refresh toggle
        self.auto_refresh_var = ctk.BooleanVar(value=False)
        self.auto_refresh_check = ctk.CTkCheckBox(
            header_frame,
            text="Auto-refresh",
            variable=self.auto_refresh_var,
            command=self._toggle_auto_refresh
        )
        self.auto_refresh_check.grid(row=0, column=2, padx=(10, 0))
    
    def _create_filter_bar(self):
        """Create filter controls"""
        filter_frame = ctk.CTkFrame(self, fg_color="transparent")
        filter_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        filter_frame.grid_columnconfigure(1, weight=1)
        
        # Filter label
        ctk.CTkLabel(
            filter_frame,
            text="Show:",
            font=ctk.CTkFont(size=12)
        ).grid(row=0, column=0, padx=(0, 10))
        
        # Filter dropdown
        self.filter_var = ctk.StringVar(value="All Processes")
        self.filter_dropdown = ctk.CTkOptionMenu(
            filter_frame,
            variable=self.filter_var,
            values=["All Processes", "Threats Only", "Safe Only", "Critical Only"],
            command=self._apply_filter
        )
        self.filter_dropdown.grid(row=0, column=1, sticky="w")
        
        # Search box
        self.search_entry = ctk.CTkEntry(
            filter_frame,
            placeholder_text="🔍 Search processes...",
            width=200
        )
        self.search_entry.grid(row=0, column=2, padx=(20, 0))
        self.search_entry.bind("<KeyRelease>", lambda e: self._apply_filter())
    
    def _create_process_list(self):
        """Create scrollable process list"""
        # Frame for process list
        self.process_list_frame = ctk.CTkScrollableFrame(
            self,
            label_text="Running Processes"
        )
        self.process_list_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        self.process_list_frame.grid_columnconfigure(0, weight=1)
        
        # Headers
        headers_frame = ctk.CTkFrame(self.process_list_frame)
        headers_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        headers_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(headers_frame, text="PID", width=60, font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=5)
        ctk.CTkLabel(headers_frame, text="Process Name", font=ctk.CTkFont(weight="bold")).grid(row=0, column=1, sticky="w", padx=5)
        ctk.CTkLabel(headers_frame, text="Memory", width=80, font=ctk.CTkFont(weight="bold")).grid(row=0, column=2, padx=5)
        ctk.CTkLabel(headers_frame, text="Status", width=100, font=ctk.CTkFont(weight="bold")).grid(row=0, column=3, padx=5)
        ctk.CTkLabel(headers_frame, text="Action", width=80, font=ctk.CTkFont(weight="bold")).grid(row=0, column=4, padx=5)
        
        # Process rows will be added here
        self.process_rows = []
    
    def _create_stats_panel(self):
        """Create statistics panel"""
        stats_frame = ctk.CTkFrame(self)
        stats_frame.grid(row=3, column=0, sticky="ew")
        stats_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)
        
        # Total processes
        self.total_label = self._create_stat_widget(stats_frame, "Total", "0", 0)
        
        # Safe processes
        self.safe_label = self._create_stat_widget(stats_frame, "Safe", "0", 1, "green")
        
        # Suspicious processes
        self.suspicious_label = self._create_stat_widget(stats_frame, "Suspicious", "0", 2, "orange")
        
        # Malicious processes
        self.malicious_label = self._create_stat_widget(stats_frame, "Malicious", "0", 3, "red")
        
        # Critical processes
        self.critical_label = self._create_stat_widget(stats_frame, "Critical", "0", 4, "purple")
    
    def _create_stat_widget(self, parent, label, value, column, color="gray"):
        """Create a single stat widget"""
        frame = ctk.CTkFrame(parent)
        frame.grid(row=0, column=column, padx=5, pady=10, sticky="ew")
        
        value_label = ctk.CTkLabel(
            frame,
            text=value,
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=color
        )
        value_label.pack(pady=(10, 0))
        
        text_label = ctk.CTkLabel(
            frame,
            text=label,
            font=ctk.CTkFont(size=12)
        )
        text_label.pack(pady=(0, 10))
        
        return value_label
    
    def _handle_refresh(self):
        """Handle refresh button click"""
        if self.on_refresh:
            self.refresh_btn.configure(state="disabled", text="⏳ Scanning...")
            threading.Thread(target=self._refresh_thread, daemon=True).start()
    
    def _refresh_thread(self):
        """Refresh processes in background thread"""
        if self.on_refresh:
            self.on_refresh()
        
        self.after(0, lambda: self.refresh_btn.configure(state="normal", text="🔄 Refresh"))
    
    def _toggle_auto_refresh(self):
        """Toggle auto-refresh"""
        if self.auto_refresh_var.get():
            self._start_auto_refresh()
        else:
            self._stop_auto_refresh()
    
    def _start_auto_refresh(self):
        """Start auto-refresh timer"""
        self._auto_refresh_active = True
        self._auto_refresh_loop()
    
    def _stop_auto_refresh(self):
        """Stop auto-refresh timer"""
        self._auto_refresh_active = False
    
    def _auto_refresh_loop(self):
        """Auto-refresh loop"""
        if getattr(self, '_auto_refresh_active', False):
            self._handle_refresh()
            self.after(5000, self._auto_refresh_loop)  # Refresh every 5 seconds
    
    def _apply_filter(self, *args):
        """Apply filter and search to process list"""
        filter_value = self.filter_var.get()
        search_term = self.search_entry.get().lower()
        
        # Filter and search
        for row_frame, process in zip(self.process_rows, self.processes):
            show = True
            
            # Apply filter
            if filter_value == "Threats Only" and not process.get("is_threat"):
                show = False
            elif filter_value == "Safe Only" and process.get("is_threat"):
                show = False
            elif filter_value == "Critical Only" and process.get("threat_level") != "Critical":
                show = False
            
            # Apply search
            if search_term:
                name = process.get("name", "").lower()
                pid = str(process.get("pid", ""))
                if search_term not in name and search_term not in pid:
                    show = False
            
            # Show/hide row
            if show:
                row_frame.grid()
            else:
                row_frame.grid_remove()
    
    def update_processes(self, processes: List[Dict], statistics: Dict):
        """Update the process list display"""
        # Clear existing rows
        for row in self.process_rows:
            row.destroy()
        self.process_rows.clear()
        
        self.processes = processes
        
        # Add new rows
        for idx, process in enumerate(processes):
            row = self._create_process_row(idx, process)
            self.process_rows.append(row)
        
        # Update statistics
        self._update_statistics(statistics)
        
        # Apply current filter
        self._apply_filter()
    
    def _create_process_row(self, index: int, process: Dict):
        """Create a row for a single process"""
        row_frame = ctk.CTkFrame(self.process_list_frame)
        row_frame.grid(row=index + 1, column=0, sticky="ew", pady=2)
        row_frame.grid_columnconfigure(1, weight=1)
        
        # Determine colors based on threat level
        threat_level = process.get("threat_level", "Safe")
        colors = {
            "Safe": ("gray", "transparent"),
            "Suspicious": ("orange", "transparent"),
            "Malicious": ("red", ("#3d1010" if ctk.get_appearance_mode() == "Dark" else "#ffe0e0")),
            "Critical": ("purple", ("#2d1030" if ctk.get_appearance_mode() == "Dark" else "#f0e0ff"))
        }
        text_color, bg_color = colors.get(threat_level, ("gray", "transparent"))
        
        if bg_color != "transparent":
            row_frame.configure(fg_color=bg_color)
        
        # PID
        ctk.CTkLabel(
            row_frame,
            text=str(process.get("pid", "?")),
            width=60,
            text_color=text_color
        ).grid(row=0, column=0, padx=5, pady=5)
        
        # Process name (with icon based on threat)
        icon = {
            "Safe": "✅",
            "Suspicious": "⚠️",
            "Malicious": "🚨",
            "Critical": "💀"
        }.get(threat_level, "")
        
        name_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
        name_frame.grid(row=0, column=1, sticky="w", padx=5)
        
        ctk.CTkLabel(
            name_frame,
            text=f"{icon} {process.get('name', 'Unknown')}",
            font=ctk.CTkFont(weight="bold" if process.get("is_threat") else "normal"),
            text_color=text_color
        ).pack(anchor="w")
        
        # Show suspicious behaviors if any
        behaviors = process.get("suspicious_behaviors", [])
        if behaviors:
            behavior_text = ", ".join(behaviors[:2])  # Show first 2
            if len(behaviors) > 2:
                behavior_text += f" (+{len(behaviors) - 2} more)"
            
            ctk.CTkLabel(
                name_frame,
                text=behavior_text,
                font=ctk.CTkFont(size=10),
                text_color="orange"
            ).pack(anchor="w")
        
        # Memory usage
        memory = process.get("memory_mb", "0")
        ctk.CTkLabel(
            row_frame,
            text=f"{memory} MB",
            width=80,
            text_color=text_color
        ).grid(row=0, column=2, padx=5)
        
        # Status
        ctk.CTkLabel(
            row_frame,
            text=threat_level,
            width=100,
            text_color=text_color
        ).grid(row=0, column=3, padx=5)
        
        # Kill button (only for threats)
        if process.get("is_threat"):
            kill_btn = ctk.CTkButton(
                row_frame,
                text="🗡️ Kill",
                width=80,
                fg_color="red",
                hover_color="darkred",
                command=lambda p=process: self._handle_kill(p)
            )
            kill_btn.grid(row=0, column=4, padx=5, pady=5)
        else:
            ctk.CTkLabel(row_frame, text="", width=80).grid(row=0, column=4, padx=5)
        
        return row_frame
    
    def _handle_kill(self, process: Dict):
        """Handle kill process button click"""
        if self.on_kill:
            pid = process.get("pid")
            name = process.get("name")
            
            # Show confirmation dialog
            from gui.dialogs.confirm_dialog import ConfirmDialog
            dialog = ConfirmDialog(
                self,
                title="Terminate Process",
                message=f"Are you sure you want to terminate process '{name}' (PID: {pid})?\n\nThis action cannot be undone.",
                confirm_text="Terminate",
                cancel_text="Cancel"
            )
            
            if dialog.get_result():
                self.on_kill(pid)
    
    def _update_statistics(self, stats: Dict):
        """Update statistics display"""
        self.total_label.configure(text=str(stats.get("total_processes", 0)))
        self.safe_label.configure(text=str(stats.get("safe_processes", 0)))
        self.suspicious_label.configure(text=str(stats.get("suspicious_processes", 0)))
        self.malicious_label.configure(text=str(stats.get("malicious_processes", 0)))
        self.critical_label.configure(text=str(stats.get("critical_processes", 0)))
    
    def clear_processes(self):
        """Clear all processes from display"""
        for row in self.process_rows:
            row.destroy()
        self.process_rows.clear()
        self.processes = []
        self._update_statistics({
            "total_processes": 0,
            "safe_processes": 0,
            "suspicious_processes": 0,
            "malicious_processes": 0,
            "critical_processes": 0
        })
    
    def set_scanning_state(self, scanning: bool):
        """Set the scanning state"""
        state = "disabled" if scanning else "normal"
        self.refresh_btn.configure(state=state)
        self.filter_dropdown.configure(state=state)