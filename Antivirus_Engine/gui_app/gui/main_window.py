"""
Main Window - With File Scanner and Process Monitor Tabs
"""

import customtkinter as ctk
from gui.components.header import HeaderFrame
from gui.components.scan_panel import ScanPanel
from gui.components.results_panel import ResultsPanel
from gui.components.sidebar import SidebarFrame
from engine_wrapper import AntivirusEngine
import traceback
from pathlib import Path
import threading

class MainWindow(ctk.CTk):
    """Main application window with file scanner and process monitor."""
    
    def __init__(self, config):
        super().__init__()
        
        # Initialize the engine
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
        
        # Main content frame with tabs
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.grid(row=1, column=1, sticky="nsew", padx=20, pady=20)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # Create tabview
        self.tabview = ctk.CTkTabview(self.content_frame)
        self.tabview.pack(fill="both", expand=True)
        
        # Tab 1: File Scanner
        self.file_tab = self.tabview.add("📁 File Scanner")
        self._create_file_scanner_tab()
        
        # Tab 2: Process Monitor
        self.process_tab = self.tabview.add("🖥️ Process Monitor")
        self._create_process_monitor_tab()
        
        print("✅ Main window created successfully with tabs")
    
    def _create_file_scanner_tab(self):
        """Create file scanner tab content"""
        # Configure tab grid
        self.file_tab.grid_columnconfigure(0, weight=1)
        self.file_tab.grid_rowconfigure(1, weight=1)
        
        # Scan panel (input)
        self.scan_panel = ScanPanel(
            self.file_tab,
            on_scan=self._start_scan
        )
        self.scan_panel.grid(row=0, column=0, sticky="ew", pady=(0, 20), padx=10)
        
        # Results panel (output)
        self.results_panel = ResultsPanel(self.file_tab)
        self.results_panel.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
    
    def _create_process_monitor_tab(self):
        """Create process monitor tab content"""
        try:
            from gui.components.process_panel import ProcessPanel
            
            # Process monitoring panel
            self.process_panel = ProcessPanel(
                self.process_tab,
                on_refresh=self._scan_processes,
                on_kill=self._kill_process
            )
            self.process_panel.pack(fill="both", expand=True, padx=10, pady=10)
            
            print("✅ Process monitor tab created")
            
        except ImportError as e:
            print(f"⚠️  Process panel not available: {e}")
            # Create placeholder
            placeholder = ctk.CTkLabel(
                self.process_tab,
                text="🚧 Process Monitor\n\nProcess monitoring feature is not yet available.\nPlease add process_panel.py to gui/components/",
                font=ctk.CTkFont(size=16),
                text_color="gray"
            )
            placeholder.pack(expand=True)
    
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
        # Switch to file scanner tab
        self.tabview.set("📁 File Scanner")
        self._start_scan()
    
    def _show_settings(self):
        """Show settings dialog."""
        try:
            from gui.dialogs.settings_dialog import SettingsDialog
            dialog = SettingsDialog(self, self.config)
            dialog.grab_set()
        except ImportError:
            print("⚠️  Settings dialog not available")
    
    # ========================================
    # FILE SCANNING METHODS
    # ========================================
    
    def _start_scan(self):
        """Start the file scanning process."""
        print("\n" + "=" * 80)
        print("Starting file scan...")
        
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
        thread = threading.Thread(
            target=self._perform_scan,
            args=(targets,),
            daemon=True
        )
        thread.start()
        print("=" * 80 + "\n")
    
    def _perform_scan(self, targets):
        """Perform the actual scan (runs in background thread)."""
        try:
            print("Scanning with engine wrapper...")
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
    
    # ========================================
    # PROCESS MONITORING METHODS
    # ========================================
    
    def _scan_processes(self):
        """Scan all running processes"""
        print("Scanning processes...")
        
        # Disable refresh button
        if hasattr(self, 'process_panel'):
            self.process_panel.set_scanning_state(True)
        
        def scan_thread():
            try:
                result = self.engine.scan_processes()
                
                if result.get("success"):
                    processes = result.get("processes", [])
                    stats = result.get("statistics", {})
                    
                    print(f"Found {len(processes)} processes")
                    print(f"Statistics: {stats}")
                    
                    # Update UI on main thread
                    self.after(0, lambda: self._update_process_display(processes, stats))
                else:
                    error = result.get("error", "Unknown error")
                    print(f"Process scan error: {error}")
                    self.after(0, lambda: self._show_error(f"Process scan failed: {error}"))
                    
            except Exception as e:
                print(f"ERROR scanning processes: {e}")
                traceback.print_exc()
                self.after(0, lambda: self._show_error(f"Process scan error: {e}"))
            
            # Re-enable refresh button
            if hasattr(self, 'process_panel'):
                self.after(0, lambda: self.process_panel.set_scanning_state(False))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def _update_process_display(self, processes, stats):
        """Update process panel with scan results"""
        try:
            if hasattr(self, 'process_panel'):
                self.process_panel.update_processes(processes, stats)
                print(f"Process panel updated with {len(processes)} processes")
        except Exception as e:
            print(f"ERROR updating process display: {e}")
            traceback.print_exc()
    
    def _kill_process(self, pid: int):
        """Terminate a malicious process"""
        print(f"Terminating process PID: {pid}")
        
        def kill_thread():
            try:
                result = self.engine.kill_process(pid)
                
                if result.get("success"):
                    print(f"Process {pid} terminated successfully")
                    # Refresh process list after 1 second
                    self.after(1000, self._scan_processes)
                    self.after(0, lambda: self._show_success(f"Process {pid} terminated"))
                else:
                    error = result.get("error", "Unknown error")
                    print(f"Failed to kill process: {error}")
                    self.after(0, lambda: self._show_error(f"Failed to kill process: {error}"))
                    
            except Exception as e:
                print(f"ERROR killing process: {e}")
                traceback.print_exc()
                self.after(0, lambda: self._show_error(f"Error: {e}"))
        
        threading.Thread(target=kill_thread, daemon=True).start()
    
    # ========================================
    # UTILITY METHODS
    # ========================================
    
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
            # Show in a simple dialog
            import tkinter.messagebox as messagebox
            messagebox.showerror("Error", message)
    
    def _show_success(self, message):
        """Show success message to user."""
        try:
            from gui.dialogs.message_dialog import MessageDialog
            dialog = MessageDialog(
                self,
                title="Success",
                message=message,
                icon="success"
            )
            dialog.grab_set()
        except:
            # Fallback
            print(f"SUCCESS: {message}")
            import tkinter.messagebox as messagebox
            messagebox.showinfo("Success", message)