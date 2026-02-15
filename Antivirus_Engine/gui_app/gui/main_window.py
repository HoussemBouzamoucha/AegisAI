"""
DIAGNOSTIC VERSION - Main Window with Extensive Logging
"""

import customtkinter as ctk
from gui.components.header import HeaderFrame
from gui.components.scan_panel import ScanPanel
from gui.components.results_panel import ResultsPanel
from gui.components.sidebar import SidebarFrame
from utils.rust_bridge import RustEngine
import traceback
from engine_wrapper import AntivirusEngine

class MainWindow(ctk.CTk):
    """Main application window."""
    
    def __init__(self, config):
        super().__init__()
        self.engine = AntivirusEngine(config.engine_path)

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
        
        print("=" * 80)
        print("DIAGNOSTIC: Main window created successfully")
        print(f"DIAGNOSTIC: Results panel object: {self.results_panel}")
        print("=" * 80)
    
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
        dialog.grab_set()
    
    def _start_scan(self):
        """Start the scanning process."""
        print("\n" + "=" * 80)
        print("DIAGNOSTIC: _start_scan called")
        
        # Get scan targets from scan panel
        targets = self.scan_panel.get_scan_targets()
        print(f"DIAGNOSTIC: Scan targets: {targets}")
        
        if not targets:
            print("DIAGNOSTIC: No targets selected, showing error")
            self._show_error("No scan targets selected")
            return
        
        # Clear previous results
        print("DIAGNOSTIC: Clearing previous results")
        self.results_panel.clear_results()
        self.current_results = []
        
        # Reset header statistics
        self.header.reset_statistics()
        
        # Update UI to scanning state
        self.scan_panel.set_scanning_state(True)
        self.sidebar.set_scanning_state(True)
        
        print(f"DIAGNOSTIC: Starting background scan thread for {len(targets)} targets")
        
        # Start scan in background thread
        import threading
        thread = threading.Thread(
            target=self._perform_scan,
            args=(targets,),
            daemon=True
        )
        thread.start()
        print("DIAGNOSTIC: Background thread started")
        print("=" * 80 + "\n")
    
    def _perform_scan(self, targets):
        """
        Perform the actual scan (runs in background thread).
        """
        try:
            print("\n" + "=" * 80)
            print("DIAGNOSTIC: _perform_scan started (in background thread)")
            print(f"DIAGNOSTIC: Targets to scan: {targets}")
            
            all_results = []
            
            for idx, target in enumerate(targets):
                from pathlib import Path
                path = Path(target)
                
                print(f"\nDIAGNOSTIC: Processing target {idx + 1}/{len(targets)}: {target}")
                print(f"DIAGNOSTIC: Path exists: {path.exists()}")
                print(f"DIAGNOSTIC: Is file: {path.is_file()}")
                print(f"DIAGNOSTIC: Is dir: {path.is_dir()}")
                
                if path.is_file():
                    print("DIAGNOSTIC: Scanning as file")
                    result = self.rust_engine.scan_file(target)
                    print(f"DIAGNOSTIC: File scan result: {result}")
                    
                    # Update UI immediately
                    self.after(0, lambda r=result: self._update_results([r]))
                    all_results.append(result)
                    
                elif path.is_dir():
                    print("DIAGNOSTIC: Scanning as directory")
                    print(f"DIAGNOSTIC: Recursive: {self.config.recursive_scan}")
                    
                    results = self.rust_engine.scan_directory(
                        target,
                        recursive=self.config.recursive_scan,
                        callback=self._scan_progress_callback
                    )
                    
                    print(f"DIAGNOSTIC: Directory scan returned {len(results)} results")
                    
                    if results:
                        print(f"DIAGNOSTIC: First result: {results[0]}")
                        print(f"DIAGNOSTIC: Last result: {results[-1]}")
                    else:
                        print("DIAGNOSTIC: WARNING - No results returned from directory scan!")
                    
                    all_results.extend(results)
                    
                else:
                    print("DIAGNOSTIC: Path is neither file nor directory - creating error result")
                    from utils.rust_bridge import ScanResult, ThreatLevel
                    result = ScanResult(
                        path=target,
                        level=ThreatLevel.ERROR,
                        reason="Path does not exist"
                    )
                    self.after(0, lambda r=result: self._update_results([r]))
                    all_results.append(result)
            
            print(f"\nDIAGNOSTIC: Scan loop complete")
            print(f"DIAGNOSTIC: Total results collected: {len(all_results)}")
            
            # Store results
            self.current_results = all_results
            
            # Call scan complete
            print("DIAGNOSTIC: Calling _scan_complete")
            self.after(0, lambda: self._scan_complete(all_results))
            
            print("=" * 80 + "\n")
            
        except Exception as e:
            print("\n" + "!" * 80)
            print(f"DIAGNOSTIC ERROR in _perform_scan: {e}")
            print("DIAGNOSTIC Traceback:")
            traceback.print_exc()
            print("!" * 80 + "\n")
    
    def _scan_progress_callback(self, current, total, result):
        """
        Callback for scan progress updates.
        """
        print(f"DIAGNOSTIC: Progress callback: {current}/{total} - {result.path}")
        
        # Update progress in UI
        self.after(0, lambda: self.scan_panel.update_progress(current, total))
        
        # Add result to display
        self.after(0, lambda r=result: self._update_results([r]))
    
    def _update_results(self, results):
        """
        Update results panel with new results.
        """
        try:
            print(f"\nDIAGNOSTIC: _update_results called")
            print(f"DIAGNOSTIC: Number of results: {len(results)}")
            print(f"DIAGNOSTIC: Results panel object: {self.results_panel}")
            
            if results:
                print(f"DIAGNOSTIC: First result details:")
                print(f"  - Path: {results[0].path}")
                print(f"  - Level: {results[0].level}")
                print(f"  - Reason: {results[0].reason}")
            
            print(f"DIAGNOSTIC: Calling results_panel.add_results()")
            self.results_panel.add_results(results)
            print(f"DIAGNOSTIC: add_results() completed")
            
        except Exception as e:
            print("\n" + "!" * 80)
            print(f"DIAGNOSTIC ERROR in _update_results: {e}")
            print("DIAGNOSTIC Traceback:")
            traceback.print_exc()
            print("!" * 80 + "\n")
    
    def _scan_complete(self, results):
        """
        Handle scan completion.
        """
        try:
            print(f"\n" + "=" * 80)
            print(f"DIAGNOSTIC: _scan_complete called")
            print(f"DIAGNOSTIC: Total results: {len(results)}")
            
            # Update UI state
            self.scan_panel.set_scanning_state(False)
            self.sidebar.set_scanning_state(False)
            
            # Calculate statistics
            stats = self.rust_engine.get_statistics(results)
            print(f"DIAGNOSTIC: Statistics calculated: {stats}")
            
            # Update UI
            self.header.update_statistics(stats)
            self.results_panel.show_summary(stats)
            
            print("DIAGNOSTIC: Scan complete - UI updated")
            print("=" * 80 + "\n")
            
        except Exception as e:
            print("\n" + "!" * 80)
            print(f"DIAGNOSTIC ERROR in _scan_complete: {e}")
            print("DIAGNOSTIC Traceback:")
            traceback.print_exc()
            print("!" * 80 + "\n")
    
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