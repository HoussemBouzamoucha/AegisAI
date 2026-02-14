"""
Scan Panel Component
====================
Input panel for selecting files/folders to scan.
"""

import customtkinter as ctk
from tkinter import filedialog
from pathlib import Path


class ScanPanel(ctk.CTkFrame):
    """Panel for selecting scan targets and starting scans."""
    
    def __init__(self, parent, on_scan):
        super().__init__(parent)
        
        self.on_scan = on_scan
        self.scan_targets = []
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        
        # Create widgets
        self._create_widgets()
    
    def _create_widgets(self):
        """Create scan panel widgets."""
        # Title
        title_label = ctk.CTkLabel(
            self,
            text="Select Files or Folders to Scan",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        
        # Target list frame
        self.targets_frame = ctk.CTkFrame(self, fg_color=("gray85", "gray20"))
        self.targets_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.targets_frame.grid_columnconfigure(0, weight=1)
        
        # Scrollable frame for targets
        self.targets_scroll = ctk.CTkScrollableFrame(
            self.targets_frame,
            height=150,
            fg_color="transparent"
        )
        self.targets_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        self.targets_scroll.grid_columnconfigure(0, weight=1)
        
        # Empty state label
        self.empty_label = ctk.CTkLabel(
            self.targets_scroll,
            text="No items selected. Click 'Add Files' or 'Add Folder' to begin.",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.empty_label.grid(row=0, column=0, pady=30)
        
        # Button frame
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        button_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Add files button
        self.add_files_button = ctk.CTkButton(
            button_frame,
            text="📄 Add Files",
            command=self._add_files,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.add_files_button.grid(row=0, column=0, padx=5, sticky="ew")
        
        # Add folder button
        self.add_folder_button = ctk.CTkButton(
            button_frame,
            text="📁 Add Folder",
            command=self._add_folder,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.add_folder_button.grid(row=0, column=1, padx=5, sticky="ew")
        
        # Clear button
        self.clear_button = ctk.CTkButton(
            button_frame,
            text="🗑️ Clear All",
            command=self._clear_targets,
            height=40,
            font=ctk.CTkFont(size=14),
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        self.clear_button.grid(row=0, column=2, padx=5, sticky="ew")
        
        # Progress section (hidden initially)
        self.progress_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.progress_frame.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="ew")
        self.progress_frame.grid_columnconfigure(0, weight=1)
        self.progress_frame.grid_remove()  # Hide initially
        
        self.progress_label = ctk.CTkLabel(
            self.progress_frame,
            text="Scanning: 0 / 0 files",
            font=ctk.CTkFont(size=12)
        )
        self.progress_label.grid(row=0, column=0, sticky="w")
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.grid(row=1, column=0, sticky="ew", pady=5)
        self.progress_bar.set(0)
        
        # Scan button
        self.scan_button = ctk.CTkButton(
            self,
            text="🔍 Start Scan",
            command=self.on_scan,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=("green", "darkgreen"),
            hover_color=("darkgreen", "green")
        )
        self.scan_button.grid(row=4, column=0, padx=20, pady=(10, 20), sticky="ew")
    
    def _add_files(self):
        """Open file dialog to add files."""
        files = filedialog.askopenfilenames(
            title="Select Files to Scan",
            filetypes=[("All Files", "*.*")]
        )
        
        for file_path in files:
            self._add_target(file_path, is_file=True)
    
    def _add_folder(self):
        """Open folder dialog to add a folder."""
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        
        if folder:
            self._add_target(folder, is_file=False)
    
    def _add_target(self, path, is_file=True):
        """Add a scan target to the list."""
        if path in self.scan_targets:
            return  # Already added
        
        self.scan_targets.append(path)
        
        # Hide empty label
        self.empty_label.grid_remove()
        
        # Create target item
        self._create_target_item(path, is_file)
    
    def _create_target_item(self, path, is_file):
        """Create a visual item for a scan target."""
        item_frame = ctk.CTkFrame(
            self.targets_scroll,
            fg_color=("gray90", "gray25"),
            corner_radius=8
        )
        row = len(self.targets_scroll.winfo_children())
        item_frame.grid(row=row, column=0, sticky="ew", pady=5)
        item_frame.grid_columnconfigure(1, weight=1)
        
        # Icon
        icon = "📄" if is_file else "📁"
        icon_label = ctk.CTkLabel(
            item_frame,
            text=icon,
            font=ctk.CTkFont(size=20)
        )
        icon_label.grid(row=0, column=0, padx=10, pady=10)
        
        # Path info
        path_obj = Path(path)
        name_label = ctk.CTkLabel(
            item_frame,
            text=path_obj.name,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w"
        )
        name_label.grid(row=0, column=1, sticky="w", pady=(10, 2))
        
        full_path_label = ctk.CTkLabel(
            item_frame,
            text=str(path_obj.parent),
            font=ctk.CTkFont(size=10),
            text_color="gray",
            anchor="w"
        )
        full_path_label.grid(row=1, column=1, sticky="w", pady=(2, 10))
        
        # Remove button
        remove_button = ctk.CTkButton(
            item_frame,
            text="✕",
            width=30,
            height=30,
            command=lambda: self._remove_target(path, item_frame),
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        remove_button.grid(row=0, column=2, rowspan=2, padx=10)
    
    def _remove_target(self, path, item_frame):
        """Remove a target from the list."""
        if path in self.scan_targets:
            self.scan_targets.remove(path)
        
        item_frame.destroy()
        
        # Show empty label if no targets
        if not self.scan_targets:
            self.empty_label.grid()
    
    def _clear_targets(self):
        """Clear all scan targets."""
        self.scan_targets.clear()
        
        # Destroy all target items
        for widget in self.targets_scroll.winfo_children():
            if widget != self.empty_label:
                widget.destroy()
        
        # Show empty label
        self.empty_label.grid()
    
    def get_scan_targets(self):
        """Get list of scan targets."""
        return self.scan_targets.copy()
    
    def update_progress(self, current, total):
        """
        Update scan progress.
        
        Args:
            current: Current file number
            total: Total files to scan
        """
        if total > 0:
            progress = current / total
            self.progress_bar.set(progress)
            self.progress_label.configure(text=f"Scanning: {current} / {total} files")
    
    def set_scanning_state(self, is_scanning):
        """
        Update UI state during scanning.
        
        Args:
            is_scanning: True if scan is in progress
        """
        if is_scanning:
            # Disable buttons
            self.add_files_button.configure(state="disabled")
            self.add_folder_button.configure(state="disabled")
            self.clear_button.configure(state="disabled")
            self.scan_button.configure(
                text="⏳ Scanning...",
                state="disabled"
            )
            
            # Show progress
            self.progress_frame.grid()
            self.progress_bar.set(0)
            
        else:
            # Enable buttons
            self.add_files_button.configure(state="normal")
            self.add_folder_button.configure(state="normal")
            self.clear_button.configure(state="normal")
            self.scan_button.configure(
                text="🔍 Start Scan",
                state="normal"
            )
            
            # Hide progress
            self.progress_frame.grid_remove()