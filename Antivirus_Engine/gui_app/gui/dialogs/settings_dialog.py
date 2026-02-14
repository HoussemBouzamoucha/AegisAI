"""
Settings Dialog
===============
Application settings and preferences.
"""

import customtkinter as ctk


class SettingsDialog(ctk.CTkToplevel):
    """Settings dialog window."""
    
    def __init__(self, parent, config):
        super().__init__(parent)
        
        self.config = config
        
        self.title("Settings")
        self.geometry("500x400")
        self.resizable(False, False)
        
        # Center on parent
        self._center_on_parent(parent)
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Create widgets
        self._create_widgets()
    
    def _create_widgets(self):
        """Create settings widgets."""
        # Main frame
        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text="⚙️ Settings",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.grid(row=0, column=0, pady=(10, 20))
        
        # Scan Settings Section
        scan_section = ctk.CTkFrame(main_frame)
        scan_section.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        scan_section.grid_columnconfigure(1, weight=1)
        
        section_label = ctk.CTkLabel(
            scan_section,
            text="Scan Settings",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        section_label.grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 5))
        
        # Recursive scan checkbox
        self.recursive_var = ctk.BooleanVar(value=self.config.recursive_scan)
        recursive_check = ctk.CTkCheckBox(
            scan_section,
            text="Scan subdirectories recursively",
            variable=self.recursive_var,
            font=ctk.CTkFont(size=12)
        )
        recursive_check.grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        
        # Max file size
        max_size_label = ctk.CTkLabel(
            scan_section,
            text="Maximum file size (MB):",
            font=ctk.CTkFont(size=12)
        )
        max_size_label.grid(row=2, column=0, sticky="w", padx=10, pady=10)
        
        self.max_size_entry = ctk.CTkEntry(
            scan_section,
            width=100,
            placeholder_text="100"
        )
        self.max_size_entry.grid(row=2, column=1, sticky="w", padx=10, pady=10)
        self.max_size_entry.insert(0, str(self.config.max_file_size // (1024 * 1024)))
        
        # Appearance Section
        appearance_section = ctk.CTkFrame(main_frame)
        appearance_section.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        appearance_section.grid_columnconfigure(1, weight=1)
        
        appearance_label = ctk.CTkLabel(
            appearance_section,
            text="Appearance",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        appearance_label.grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 5))
        
        # Theme selection
        theme_label = ctk.CTkLabel(
            appearance_section,
            text="Theme:",
            font=ctk.CTkFont(size=12)
        )
        theme_label.grid(row=1, column=0, sticky="w", padx=10, pady=10)
        
        self.theme_var = ctk.StringVar(value=self.config.theme)
        theme_menu = ctk.CTkOptionMenu(
            appearance_section,
            values=["dark", "light", "system"],
            variable=self.theme_var,
            command=self._change_theme
        )
        theme_menu.grid(row=1, column=1, sticky="w", padx=10, pady=10)
        
        # Engine Path Section
        engine_section = ctk.CTkFrame(main_frame)
        engine_section.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        engine_section.grid_columnconfigure(1, weight=1)
        
        engine_label = ctk.CTkLabel(
            engine_section,
            text="Rust Engine",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        engine_label.grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 5))
        
        path_label = ctk.CTkLabel(
            engine_section,
            text=f"Path: {self.config.rust_engine_path}",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        path_label.grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        
        status_text = "✅ Found" if self.config.rust_engine_path.exists() else "❌ Not Found"
        status_label = ctk.CTkLabel(
            engine_section,
            text=status_text,
            font=ctk.CTkFont(size=10)
        )
        status_label.grid(row=2, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 10))
        
        # Button frame
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=1, column=0, pady=(0, 20))
        
        # Save button
        save_button = ctk.CTkButton(
            button_frame,
            text="💾 Save",
            command=self._save_settings,
            width=100,
            height=35
        )
        save_button.pack(side="left", padx=5)
        
        # Cancel button
        cancel_button = ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=self.destroy,
            width=100,
            height=35,
            fg_color="transparent",
            border_width=2
        )
        cancel_button.pack(side="left", padx=5)
    
    def _change_theme(self, theme):
        """Change application theme."""
        ctk.set_appearance_mode(theme)
    
    def _save_settings(self):
        """Save settings and close dialog."""
        # Update config
        self.config.recursive_scan = self.recursive_var.get()
        
        try:
            max_size_mb = int(self.max_size_entry.get())
            self.config.max_file_size = max_size_mb * 1024 * 1024
        except ValueError:
            pass  # Keep current value if invalid
        
        self.config.theme = self.theme_var.get()
        
        # Save to file
        self.config.save_config()
        
        # Close dialog
        self.destroy()
    
    def _center_on_parent(self, parent):
        """Center dialog on parent window."""
        self.update_idletasks()
        
        parent_x = parent.winfo_x()
        parent_y = parent.winfo_y()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()
        
        dialog_width = self.winfo_width()
        dialog_height = self.winfo_height()
        
        x = parent_x + (parent_width // 2) - (dialog_width // 2)
        y = parent_y + (parent_height // 2) - (dialog_height // 2)
        
        self.geometry(f"+{x}+{y}")