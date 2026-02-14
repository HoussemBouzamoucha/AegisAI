"""
Header Component
================
Top header with app branding and statistics.
"""

import customtkinter as ctk
from tkinter import PhotoImage


class HeaderFrame(ctk.CTkFrame):
    """Header frame with logo and statistics."""
    
    def __init__(self, parent, config):
        super().__init__(parent, fg_color="transparent")
        
        self.config = config
        
        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        
        # Create widgets
        self._create_widgets()
    
    def _create_widgets(self):
        """Create header widgets."""
        # Logo and title section
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.grid(row=0, column=0, sticky="w")
        
        # App icon (shield emoji as placeholder)
        icon_label = ctk.CTkLabel(
            title_frame,
            text="🛡️",
            font=ctk.CTkFont(size=32)
        )
        icon_label.pack(side="left", padx=(0, 10))
        
        # Title and tagline
        text_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        text_frame.pack(side="left")
        
        title_label = ctk.CTkLabel(
            text_frame,
            text=self.config.app_name,
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(anchor="w")
        
        tagline = ctk.CTkLabel(
            text_frame,
            text="Advanced Threat Protection",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        tagline.pack(anchor="w")
        
        # Statistics section
        self.stats_frame = ctk.CTkFrame(self)
        self.stats_frame.grid(row=0, column=1, sticky="e", padx=20)
        
        # Statistics labels
        self._create_stat_widget("Files Scanned", "0", "files_scanned")
        self._create_stat_widget("Threats Found", "0", "threats_found", color="red")
        self._create_stat_widget("Clean Files", "0", "clean_files", color="green")
    
    def _create_stat_widget(self, title, value, key, color=None):
        """Create a statistics widget."""
        stat_frame = ctk.CTkFrame(self.stats_frame, fg_color="transparent")
        stat_frame.pack(side="left", padx=15)
        
        value_label = ctk.CTkLabel(
            stat_frame,
            text=value,
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=color if color else None
        )
        value_label.pack()
        
        title_label = ctk.CTkLabel(
            stat_frame,
            text=title,
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        title_label.pack()
        
        # Store reference for updates
        setattr(self, f"{key}_label", value_label)
    
    def update_statistics(self, stats):
        """
        Update statistics display.
        
        Args:
            stats: Dictionary with 'total', 'clean', 'suspicious', 'malicious', 'errors'
        """
        self.files_scanned_label.configure(text=str(stats['total']))
        
        threats = stats['suspicious'] + stats['malicious']
        self.threats_found_label.configure(text=str(threats))
        
        self.clean_files_label.configure(text=str(stats['clean']))
    
    def reset_statistics(self):
        """Reset all statistics to zero."""
        self.files_scanned_label.configure(text="0")
        self.threats_found_label.configure(text="0")
        self.clean_files_label.configure(text="0")