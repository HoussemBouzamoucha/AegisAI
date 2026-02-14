"""
Main Window
===========
Main application window with modern UI and animations.
"""

import customtkinter as ctk
from gui.components.header import HeaderFrame
from gui.components.scan_panel import ScanPanel
from gui.components.results_panel import ResultsPanel
from gui.components.sidebar import SidebarFrame
from utils.rust_bridge import RustEngine


class MainWindow(ctk.CTk):
    """Main application window."""
    
    def __init__(self, config):
        super().__init__()
        
        self.config = config
        self.rust_engine = RustEngine(config.rust_engine_path)
        self.current_results = []
        
        # Configure window
        self.title(f"{config.app_name} v{config.version}")
        self.geometry(f"{config.window_width}x{config.window_height}")
        self.minsize(config.min_width, config.min_height)
        
        # Center window on screen
        self._center_window()
        
        # Configure grid layout (3x2)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Create UI components
        self._create_widgets()
        
        # Bind events
        self._bind_events()
        
        # Initial animation
        self._animate_startup()
    
    def _center_window(self):
        """Center the window on screen."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
    
    def _create_widgets(self):
        """Create all UI widgets."""
        # Sidebar (left)
        self.sidebar = SidebarFrame(
            self,
            config=self.config,
            on_scan_click=self._handle_scan,
            on_settings_click=self._show_settings
        )
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=0, pady=0)
        
        # Header (top)
        self.header = HeaderFrame(self, config=self.config)
        self.header.grid(row=0, column=1, sticky="ew", padx=20, pady=(20, 0))
        
        # Main content frame
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.grid(row=1, column=1, sticky="nsew", padx=20, pady=20)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(1, weight=1)
        
        # Scan panel (input)
        self.scan_panel = ScanPanel(
            self.content_frame,
            on_scan=self._start_scan
        )
        self.scan_panel.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        # Results panel (output)
        self.results_panel = ResultsPanel(self.content_frame)
        self.results_panel.grid(row=1, column=0, sticky="nsew")
    
    def _bind_events(self):
        """Bind keyboard shortcuts and events."""
        self.bind("<Control-q>", lambda e: self.quit())
        self.bind("<F5>", lambda e: self._start_scan())
    
    def _animate_startup(self):
        """Animate window appearance on startup."""
        self.attributes('-alpha', 0.0)
        self._fade_in(0.0)
    
    def _fade_in(self, alpha):
        """Fade in animation."""
        if alpha < 1.0:
            alpha += 0.05
            self.attributes('-alpha', alpha)
            self.after(self.config.animation_speed, lambda: self._fade_in(alpha))
    
    def _handle_scan(self):
        """Handle scan button click from sidebar."""
        self._start_scan()
    
    def _show_settings(self):
        """Show settings dialog."""
        from gui.dialogs.settings_dialog import SettingsDialog
        dialog = SettingsDialog(self, self.config)
        dialog.grab_set()  # Make modal
    
    def _start_scan(self):
        """Start the scanning process."""
        # Get scan targets from scan panel
        targets = self.scan_panel.get_scan_targets()
        
        if not targets:
            self._show_error("No scan targets selected")
            return
        
        # Clear previous results
        self.results_panel.clear_results()
        
        # Update UI to scanning state
        self.scan_panel.set_scanning_state(True)
        self.sidebar.set_scanning_state(True)
        
        # Start scan in background thread
        import threading
        thread = threading.Thread(
            target=self._perform_scan,
            args=(targets,),
            daemon=True
        )
        thread.start()
    
    def _perform_scan(self, targets):
        """
        Perform the actual scan (runs in background thread).
        
        Args:
            targets: List of file/directory paths to scan
        """
        all_results = []
        
        for target in targets:
            from pathlib import Path
            path = Path(target)
            
            if path.is_file():
                result = self.rust_engine.scan_file(target)
                self._update_results([result])
                all_results.append(result)
            elif path.is_dir():
                results = self.rust_engine.scan_directory(
                    target,
                    recursive=self.config.recursive_scan,
                    callback=self._scan_progress_callback
                )
                all_results.extend(results)
            else:
                # Invalid path
                from utils.rust_bridge import ScanResult, ThreatLevel
                result = ScanResult(
                    path=target,
                    level=ThreatLevel.ERROR,
                    reason="Path does not exist"
                )
                self._update_results([result])
                all_results.append(result)
        
        # Scan complete
        self.current_results = all_results
        self._scan_complete(all_results)
    
    def _scan_progress_callback(self, current, total, result):
        """
        Callback for scan progress updates.
        
        Args:
            current: Current file number
            total: Total files to scan
            result: ScanResult for current file
        """
        # Update progress in UI (must use after() for thread safety)
        self.after(0, lambda: self.scan_panel.update_progress(current, total))
        self.after(0, lambda: self._update_results([result]))
    
    def _update_results(self, results):
        """
        Update results panel with new results.
        
        Args:
            results: List of ScanResult objects
        """
        self.results_panel.add_results(results)
    
    def _scan_complete(self, results):
        """
        Handle scan completion.
        
        Args:
            results: All scan results
        """
        # Update UI state (must use after() for thread safety)
        self.after(0, lambda: self.scan_panel.set_scanning_state(False))
        self.after(0, lambda: self.sidebar.set_scanning_state(False))
        
        # Calculate and display statistics
        stats = self.rust_engine.get_statistics(results)
        self.after(0, lambda: self.header.update_statistics(stats))
        self.after(0, lambda: self.results_panel.show_summary(stats))
    
    def _show_error(self, message):
        """Show error message to user."""
        from gui.dialogs.message_dialog import MessageDialog
        dialog = MessageDialog(
            self,
            title="Error",
            message=message,
            icon="error"
        )
        dialog.grab_set()