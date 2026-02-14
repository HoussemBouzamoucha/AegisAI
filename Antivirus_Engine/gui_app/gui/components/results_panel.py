"""
Results Panel Component
=======================
Display scan results with filtering and sorting.
"""

import customtkinter as ctk
from utils.rust_bridge import ThreatLevel


class ResultsPanel(ctk.CTkFrame):
    """Panel for displaying scan results."""
    
    def __init__(self, parent):
        super().__init__(parent)
        
        self.results = []
        self.filtered_results = []
        self.current_filter = "all"
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Create widgets
        self._create_widgets()
    
    def _create_widgets(self):
        """Create results panel widgets."""
        # Header with filters
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 10))
        header_frame.grid_columnconfigure(1, weight=1)
        
        # Title
        title_label = ctk.CTkLabel(
            header_frame,
            text="Scan Results",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.grid(row=0, column=0, sticky="w", padx=10)
        
        # Filter buttons
        filter_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        filter_frame.grid(row=0, column=1, sticky="e", padx=10)
        
        self.filter_buttons = {}
        filters = [
            ("All", "all", None),
            ("Clean", "clean", "green"),
            ("Suspicious", "suspicious", "orange"),
            ("Malicious", "malicious", "red"),
            ("Errors", "errors", "gray")
        ]
        
        for idx, (text, filter_key, color) in enumerate(filters):
            button = ctk.CTkButton(
                filter_frame,
                text=text,
                width=80,
                height=30,
                command=lambda f=filter_key: self._apply_filter(f),
                fg_color="transparent" if idx != 0 else None,
                border_width=2 if idx == 0 else 0,
                text_color=color if color else None
            )
            button.pack(side="left", padx=3)
            self.filter_buttons[filter_key] = button
        
        # Results scrollable frame
        self.results_scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=("gray85", "gray20")
        )
        self.results_scroll.grid(row=1, column=0, sticky="nsew")
        self.results_scroll.grid_columnconfigure(0, weight=1)
        
        # Empty state
        self.empty_label = ctk.CTkLabel(
            self.results_scroll,
            text="No scan results yet.\nStart a scan to see results here.",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        self.empty_label.grid(row=0, column=0, pady=50)
        
        # Summary frame (hidden initially)
        self.summary_frame = ctk.CTkFrame(self)
        self.summary_frame.grid(row=2, column=0, sticky="ew", padx=0, pady=(10, 0))
        self.summary_frame.grid_remove()
    
    def add_results(self, new_results):
        """
        Add new scan results.
        
        Args:
            new_results: List of ScanResult objects
        """
        self.results.extend(new_results)
        self._apply_filter(self.current_filter)
    
    def clear_results(self):
        """Clear all results."""
        self.results.clear()
        self.filtered_results.clear()
        
        # Destroy all result items
        for widget in self.results_scroll.winfo_children():
            if widget != self.empty_label:
                widget.destroy()
        
        # Show empty label
        self.empty_label.grid()
        
        # Hide summary
        self.summary_frame.grid_remove()
    
    def _apply_filter(self, filter_key):
        """
        Apply result filter.
        
        Args:
            filter_key: Filter type ('all', 'clean', 'suspicious', 'malicious', 'errors')
        """
        self.current_filter = filter_key
        
        # Update filter button states
        for key, button in self.filter_buttons.items():
            if key == filter_key:
                button.configure(fg_color=None, border_width=2)
            else:
                button.configure(fg_color="transparent", border_width=0)
        
        # Filter results
        if filter_key == "all":
            self.filtered_results = self.results.copy()
        elif filter_key == "clean":
            self.filtered_results = [r for r in self.results if r.level == ThreatLevel.CLEAN]
        elif filter_key == "suspicious":
            self.filtered_results = [r for r in self.results if r.level == ThreatLevel.SUSPICIOUS]
        elif filter_key == "malicious":
            self.filtered_results = [r for r in self.results if r.level == ThreatLevel.MALICIOUS]
        elif filter_key == "errors":
            self.filtered_results = [r for r in self.results if r.level == ThreatLevel.ERROR]
        
        # Refresh display
        self._refresh_display()
    
    def _refresh_display(self):
        """Refresh the results display."""
        # Clear existing items (except empty label)
        for widget in self.results_scroll.winfo_children():
            if widget != self.empty_label:
                widget.destroy()
        
        if not self.filtered_results:
            self.empty_label.grid()
            return
        
        # Hide empty label
        self.empty_label.grid_remove()
        
        # Create result items
        for idx, result in enumerate(self.filtered_results):
            self._create_result_item(result, idx)
    
    def _create_result_item(self, result, row):
        """Create a visual item for a scan result."""
        # Determine colors based on threat level
        if result.level == ThreatLevel.CLEAN:
            icon = "✅"
            color = "green"
            bg_color = ("lightgreen", "darkgreen")
        elif result.level == ThreatLevel.SUSPICIOUS:
            icon = "⚠️"
            color = "orange"
            bg_color = ("lightyellow", "darkorange")
        elif result.level == ThreatLevel.MALICIOUS:
            icon = "🛑"
            color = "red"
            bg_color = ("lightcoral", "darkred")
        else:  # ERROR
            icon = "❌"
            color = "gray"
            bg_color = ("lightgray", "darkgray")
        
        # Create item frame
        item_frame = ctk.CTkFrame(
            self.results_scroll,
            fg_color=("gray90", "gray25"),
            corner_radius=8
        )
        item_frame.grid(row=row, column=0, sticky="ew", pady=3, padx=5)
        item_frame.grid_columnconfigure(1, weight=1)
        
        # Icon
        icon_label = ctk.CTkLabel(
            item_frame,
            text=icon,
            font=ctk.CTkFont(size=20)
        )
        icon_label.grid(row=0, column=0, rowspan=2, padx=10, pady=10)
        
        # File path
        from pathlib import Path
        path_obj = Path(result.path)
        
        name_label = ctk.CTkLabel(
            item_frame,
            text=path_obj.name,
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w"
        )
        name_label.grid(row=0, column=1, sticky="w", pady=(10, 2))
        
        # Details
        detail_text = f"{str(path_obj.parent)} • {result.level.value}"
        if result.reason:
            detail_text += f" • {result.reason}"
        
        detail_label = ctk.CTkLabel(
            item_frame,
            text=detail_text,
            font=ctk.CTkFont(size=10),
            text_color="gray",
            anchor="w"
        )
        detail_label.grid(row=1, column=1, sticky="w", pady=(2, 10))
        
        # Threat level badge
        level_badge = ctk.CTkButton(
            item_frame,
            text=result.level.value,
            width=100,
            height=25,
            fg_color=color,
            hover=False,
            state="disabled",
            font=ctk.CTkFont(size=10, weight="bold")
        )
        level_badge.grid(row=0, column=2, rowspan=2, padx=10)
    
    def show_summary(self, stats):
        """
        Show scan summary.
        
        Args:
            stats: Dictionary with statistics
        """
        # Clear existing summary
        for widget in self.summary_frame.winfo_children():
            widget.destroy()
        
        # Create summary
        summary_label = ctk.CTkLabel(
            self.summary_frame,
            text="Scan Complete",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        summary_label.pack(side="left", padx=20, pady=15)
        
        # Stats
        stats_text = (
            f"Total: {stats['total']} | "
            f"Clean: {stats['clean']} | "
            f"Suspicious: {stats['suspicious']} | "
            f"Malicious: {stats['malicious']} | "
            f"Errors: {stats['errors']}"
        )
        
        stats_label = ctk.CTkLabel(
            self.summary_frame,
            text=stats_text,
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        stats_label.pack(side="left", pady=15)
        
        # Show summary frame
        self.summary_frame.grid()