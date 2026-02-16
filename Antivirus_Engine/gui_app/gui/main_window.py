"""
Main Window - Fixed to use AntivirusEngine wrapper
"""

import customtkinter as ctk
from gui.components.header import HeaderFrame
from gui.components.scan_panel import ScanPanel
from gui.components.results_panel import ResultsPanel
from gui.components.sidebar import SidebarFrame
from engine_wrapper import AntivirusEngine
import traceback
from pathlib import Path

class MainWindow(ctk.CTk):
    """Main application window."""
    
    def __init__(self, config):
        super().__init__()
        
        # Initialize the NEW engine wrapper
        self.engine = AntivirusEngine(config.rust_engine_path)
        print(f"✅ Rust engine initialized at: {config.rust_engine_path}")

        self.config = config
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
        
        print("✅ Main window created successfully")
    
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
        print("Starting scan...")
        
        # Get scan targets from scan panel
        targets = self.scan_panel.get_scan_targets()
        print(f"Scan targets: {targets}")
        
        if not targets:
            self._show_error("No scan targets selected")
            return
        
        # Clear previous results
        self.results_panel.clear_results()
        self.current_results = []
        
        # Reset header statistics
        self.header.reset_statistics()
        
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
        print("=" * 80 + "\n")
    
    def _perform_scan(self, targets):
        """
        Perform the actual scan (runs in background thread).
        Uses the new AntivirusEngine wrapper.
        """
        try:
            print("Scanning with new engine wrapper...")
            all_results = []
            
            for idx, target in enumerate(targets):
                path = Path(target)
                
                print(f"Processing {idx + 1}/{len(targets)}: {target}")
                
                if path.is_file():
                    # Scan single file
                    print(f"Scanning file: {target}")
                    json_result = self.engine.scan_file(target)
                    
                    # Convert JSON to ScanResult
                    result = self._json_to_scan_result(json_result)
                    print(f"Result: {result.level.value} - {result.reason}")
                    
                    # Update UI
                    self.after(0, lambda r=result: self._update_results([r]))
                    all_results.append(result)
                    
                elif path.is_dir():
                    # Scan directory
                    print(f"Scanning directory: {target}")
                    json_result = self.engine.scan_directory(target)
                    
                    if not json_result.get("success"):
                        print(f"Directory scan error: {json_result.get('error')}")
                        continue
                    
                    # Convert all file results
                    files = json_result.get("files", [])
                    print(f"Directory contains {len(files)} files")
                    
                    for file_data in files:
                        result = self._json_to_scan_result(file_data)
                        all_results.append(result)
                        
                        # Update UI every 10 files
                        if len(all_results) % 10 == 0:
                            self.after(0, lambda r=all_results[-10:]: self._update_results(r))
                    
                    # Update remaining
                    if len(all_results) % 10 != 0:
                        remaining = all_results[-(len(all_results) % 10):]
                        self.after(0, lambda r=remaining: self._update_results(r))
                    
                else:
                    print(f"Invalid path: {target}")
                    from utils.rust_bridge import ScanResult, ThreatLevel
                    result = ScanResult(
                        path=str(target),
                        level=ThreatLevel.ERROR,
                        reason="Path does not exist",
                        hash=None,
                        signature=None
                    )
                    self.after(0, lambda r=result: self._update_results([r]))
                    all_results.append(result)
            
            print(f"Scan complete: {len(all_results)} files scanned")
            
            # Store results
            self.current_results = all_results
            
            # Call scan complete
            self.after(0, lambda: self._scan_complete(all_results))
            
        except Exception as e:
            print(f"ERROR in _perform_scan: {e}")
            traceback.print_exc()
            self.after(0, lambda: self._show_error(f"Scan error: {e}"))
    
    def _json_to_scan_result(self, json_data):
        """Convert JSON result from engine to ScanResult object."""
        from utils.rust_bridge import ScanResult, ThreatLevel
        
        # Handle errors
        if not json_data.get("success", True):
            return ScanResult(
                path=json_data.get("path", "unknown"),
                level=ThreatLevel.ERROR,
                reason=json_data.get("error", "Unknown error"),
                hash=None,
                signature=None
            )
        
        # Map level string to ThreatLevel enum
        level_str = json_data.get("level", "Clean")
        level_map = {
            "Clean": ThreatLevel.CLEAN,
            "Suspicious": ThreatLevel.SUSPICIOUS,
            "Malicious": ThreatLevel.MALICIOUS,
        }
        level = level_map.get(level_str, ThreatLevel.CLEAN)
        
        return ScanResult(
            path=json_data.get("path", "unknown"),
            level=level,
            reason=json_data.get("reason", ""),
            hash=json_data.get("hash"),
            signature=json_data.get("signature")
        )
    
    def _scan_progress_callback(self, current, total, result):
        """Callback for scan progress updates."""
        self.after(0, lambda: self.scan_panel.update_progress(current, total))
        self.after(0, lambda r=result: self._update_results([r]))
    
    def _update_results(self, results):
        """Update results panel with new results."""
        try:
            self.results_panel.add_results(results)
        except Exception as e:
            print(f"ERROR in _update_results: {e}")
            traceback.print_exc()
    
    def _scan_complete(self, results):
        """Handle scan completion."""
        try:
            print("Scan complete - updating UI")
            
            # Update UI state
            self.scan_panel.set_scanning_state(False)
            self.sidebar.set_scanning_state(False)
            
            # Calculate statistics
            stats = self._calculate_statistics(results)
            print(f"Statistics: {stats}")
            
            # Update UI
            self.header.update_statistics(stats)
            self.results_panel.show_summary(stats)
            
            print("UI updated successfully")
            
        except Exception as e:
            print(f"ERROR in _scan_complete: {e}")
            traceback.print_exc()
    
    def _calculate_statistics(self, results):
        """Calculate scan statistics from results."""
        from utils.rust_bridge import ThreatLevel
        
        stats = {
            'total': len(results),
            'clean': 0,
            'suspicious': 0,
            'malicious': 0,
            'errors': 0
        }
        
        for result in results:
            if result.level == ThreatLevel.CLEAN:
                stats['clean'] += 1
            elif result.level == ThreatLevel.SUSPICIOUS:
                stats['suspicious'] += 1
            elif result.level == ThreatLevel.MALICIOUS:
                stats['malicious'] += 1
            elif result.level == ThreatLevel.ERROR:
                stats['errors'] += 1
        
        return stats
    
    def _show_error(self, message):
        """Show error message to user."""
        try:
            from gui.dialogs.message_dialog import MessageDialog
            dialog = MessageDialog(
                self,
                title="Error",
                message=message,
                icon="error"
            )
            dialog.grab_set()
        except:
            # Fallback if dialog doesn't exist
            print(f"ERROR: {message}")