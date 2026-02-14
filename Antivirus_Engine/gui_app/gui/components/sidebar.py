"""
Sidebar Component
=================
Left sidebar with navigation and quick actions.
"""

import customtkinter as ctk


class SidebarFrame(ctk.CTkFrame):
    """Sidebar with navigation and actions."""
    
    def __init__(self, parent, config, on_scan_click, on_settings_click):
        super().__init__(parent, corner_radius=0)
        
        self.config = config
        self.on_scan_click = on_scan_click
        self.on_settings_click = on_settings_click
        
        # Configure grid
        self.grid_rowconfigure(4, weight=1)
        
        # Create widgets
        self._create_widgets()
    
    def _create_widgets(self):
        """Create sidebar widgets."""
        # Logo section
        logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=30)
        
        logo_label = ctk.CTkLabel(
            logo_frame,
            text="🛡️",
            font=ctk.CTkFont(size=48)
        )
        logo_label.pack()
        
        app_name = ctk.CTkLabel(
            logo_frame,
            text="AegisAI",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        app_name.pack()
        
        # Main actions
        self.scan_button = self._create_nav_button(
            "🔍 Quick Scan",
            self.on_scan_click,
            row=1
        )
        
        self.full_scan_button = self._create_nav_button(
            "🗂️ Full Scan",
            self.on_scan_click,
            row=2
        )
        
        self.custom_scan_button = self._create_nav_button(
            "⚙️ Custom Scan",
            self.on_scan_click,
            row=3
        )
        
        # Spacer
        spacer = ctk.CTkFrame(self, fg_color="transparent")
        spacer.grid(row=4, column=0, sticky="nsew")
        
        # Bottom actions
        self.settings_button = self._create_nav_button(
            "⚙️ Settings",
            self.on_settings_click,
            row=5,
            style="secondary"
        )
        
        self.about_button = self._create_nav_button(
            "ℹ️ About",
            self._show_about,
            row=6,
            style="secondary"
        )
        
        # Version info
        version_label = ctk.CTkLabel(
            self,
            text=f"v{self.config.version}",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        version_label.grid(row=7, column=0, pady=(5, 20))
    
    def _create_nav_button(self, text, command, row, style="primary"):
        """Create a navigation button."""
        if style == "primary":
            button = ctk.CTkButton(
                self,
                text=text,
                command=command,
                height=40,
                font=ctk.CTkFont(size=14),
                anchor="w"
            )
        else:
            button = ctk.CTkButton(
                self,
                text=text,
                command=command,
                height=40,
                font=ctk.CTkFont(size=14),
                fg_color="transparent",
                hover_color=("gray70", "gray30"),
                anchor="w"
            )
        
        button.grid(row=row, column=0, padx=20, pady=10, sticky="ew")
        return button
    
    def set_scanning_state(self, is_scanning):
        """
        Update button states during scanning.
        
        Args:
            is_scanning: True if scan is in progress
        """
        state = "disabled" if is_scanning else "normal"
        
        self.scan_button.configure(state=state)
        self.full_scan_button.configure(state=state)
        self.custom_scan_button.configure(state=state)
        
        if is_scanning:
            self.scan_button.configure(text="⏳ Scanning...")
        else:
            self.scan_button.configure(text="🔍 Quick Scan")
    
    def _show_about(self):
        """Show about dialog."""
        from gui.dialogs.message_dialog import MessageDialog
        
        about_text = f"""
{self.config.app_name}
Version {self.config.version}

Advanced antivirus protection powered by Rust engine.

Features:
• Real-time file scanning
• Heuristic analysis
• Malware signature database
• Fast and efficient

© 2024 AegisAI Team
        """.strip()
        
        dialog = MessageDialog(
            self.master,
            title="About AegisAI",
            message=about_text,
            icon="info"
        )
        dialog.grab_set()