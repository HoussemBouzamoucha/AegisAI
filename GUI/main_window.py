"""
Main window for the AegisAI Scanner application
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from pathlib import Path

from .styles import AppStyles
from .widgets import ModeSelector, PathInput, ActionButtons, ResultsDisplay
from logic.scan_thread import ScanThread
from Core.types import ThreatLevel


class ModernScannerGUI(QMainWindow):
    """Main application window"""
    
    def __init__(self, scanner):
        super().__init__()
        
        self.scanner = scanner
        self.scan_thread = None
        self.all_results = []
        
        self.setWindowTitle("AegisAI Scanner")
        self.setGeometry(100, 100, 900, 700)
        
        self._setup_ui()
        self._apply_styles()
        self.results_display.show_empty_state()
    
    def _setup_ui(self):
        """Setup the user interface"""
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header section
        main_layout.addWidget(self._create_header())
        
        # Content card
        main_layout.addWidget(self._create_content_card(), 1)
    
    def _create_header(self):
        """Create the header section"""
        header_widget = QWidget()
        header_layout = QVBoxLayout(header_widget)
        header_layout.setAlignment(Qt.AlignCenter)
        header_layout.setContentsMargins(0, 40, 0, 20)
        
        # Shield icon
        icon_label = QLabel("🛡")
        icon_label.setFont(QFont("Segoe UI", 32))
        icon_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(icon_label)
        
        # Title
        title_label = QLabel("AegisAI Scanner")
        title_label.setFont(QFont("Segoe UI", 24, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Advanced threat detection & file analysis system")
        subtitle_label.setFont(QFont("Consolas", 9))
        subtitle_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(subtitle_label)
        
        return header_widget
    
    def _create_content_card(self):
        """Create the main content card"""
        # Container
        card_container = QWidget()
        card_container.setObjectName("content_card")
        card_layout = QVBoxLayout(card_container)
        card_layout.setContentsMargins(60, 20, 60, 20)
        
        # Content card frame
        content_card = QFrame()
        content_card.setObjectName("card_frame")
        content_card.setFrameStyle(QFrame.Box)
        content_layout = QVBoxLayout(content_card)
        content_layout.setContentsMargins(30, 30, 30, 30)
        content_layout.setSpacing(15)
        
        # Mode selector
        self.mode_selector = ModeSelector()
        content_layout.addWidget(self.mode_selector)
        
        # Path input
        self.path_input = PathInput()
        self.path_input.browse_clicked.connect(self._on_browse)
        content_layout.addWidget(self.path_input)
        
        # Action buttons
        self.action_buttons = ActionButtons()
        self.action_buttons.scan_clicked.connect(self._on_start_scan)
        self.action_buttons.clear_clicked.connect(self._on_clear_results)
        content_layout.addWidget(self.action_buttons)
        
        # Results display
        self.results_display = ResultsDisplay()
        content_layout.addWidget(self.results_display, 1)
        
        card_layout.addWidget(content_card)
        return card_container
    
    def _apply_styles(self):
        """Apply stylesheets"""
        self.setStyleSheet(AppStyles.get_main_stylesheet())
    
    def _on_browse(self):
        """Handle browse button click"""
        if self.mode_selector.is_file_mode():
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Select File to Scan",
                "",
                "All Files (*.*);;Executables (*.exe *.dll *.scr *.bat)"
            )
        else:
            path = QFileDialog.getExistingDirectory(
                self,
                "Select Directory to Scan"
            )
        
        if path:
            self.path_input.set_path(path)
    
    def _on_clear_results(self):
        """Handle clear button click"""
        self.results_display.show_empty_state()
        self.all_results = []
    
    def _on_start_scan(self):
        """Handle start scan button click"""
        path_str = self.path_input.get_path()
        
        if not path_str or path_str == "Enter file path or click Browse...":
            QMessageBox.warning(self, "No path", "Please select a file or directory first.")
            return
        
        target = Path(path_str)
        if not target.exists():
            QMessageBox.critical(self, "Error", f"Path does not exist:\n{target}")
            return
        
        # Clear results
        self.results_display.clear()
        self.all_results = []
        
        # Add header
        self.results_display.append_text(f"Scanning: {target}\n\n", "header")
        
        # Disable scan button
        self.action_buttons.set_scanning(True)
        
        # Determine scan type
        is_file = self.mode_selector.is_file_mode()
        
        if is_file and not target.is_file():
            QMessageBox.critical(self, "Error", "Selected path is not a file.")
            self.action_buttons.set_scanning(False)
            return
        
        if not is_file and not target.is_dir():
            QMessageBox.critical(self, "Error", "Selected path is not a directory.")
            self.action_buttons.set_scanning(False)
            return
        
        # Start scan thread
        self.scan_thread = ScanThread(self.scanner, target, is_file)
        self.scan_thread.result_ready.connect(self._on_result_ready)
        self.scan_thread.progress_update.connect(self._on_progress_update)
        self.scan_thread.scan_complete.connect(self._on_scan_complete)
        self.scan_thread.error_occurred.connect(self._on_scan_error)
        self.scan_thread.start()
    
    def _on_result_ready(self, result):
        """Handle individual scan result"""
        self.all_results.append(result)
        
        if result.threat_level == ThreatLevel.MALICIOUS:
            tag = "malicious"
            prefix = "MALICIOUS "
        elif result.threat_level == ThreatLevel.SUSPICIOUS:
            tag = "suspicious"
            prefix = "SUSPICIOUS "
        else:
            tag = "clean"
            prefix = "CLEAN     "
        
        line = f"{prefix} {result.file_path.name}"
        if result.reason:
            line += f" → {result.reason}"
        if hasattr(result, 'signature_match') and result.signature_match:
            line += f"  [Signature: {result.signature_match}]"
        
        self.results_display.append_text(line + "\n", tag)
        
        if hasattr(result, 'hash_value') and result.hash_value and isinstance(result.hash_value, dict):
            self.results_display.append_text("  Hashes:\n", "clean")
            for algo, h in result.hash_value.items():
                self.results_display.append_text(f"    {algo.upper()}: {h}\n", "clean")
        
        self.results_display.append_text("\n")
    
    def _on_progress_update(self, text):
        """Handle progress update"""
        self.results_display.append_text(text, "header")
    
    def _on_scan_complete(self, results):
        """Handle scan completion"""
        # Show danger zone
        danger_results = [r for r in results if r.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS)]
        
        if danger_results:
            self.results_display.append_text("\n" + "═" * 80 + "\n", "header")
            self.results_display.append_text("DANGER ZONE – Review These Files Carefully\n", "danger_header")
            self.results_display.append_text("═" * 80 + "\n\n", "header")
            
            for result in danger_results:
                if result.threat_level == ThreatLevel.MALICIOUS:
                    tag = "malicious"
                    prefix = "MALICIOUS "
                else:
                    tag = "suspicious"
                    prefix = "SUSPICIOUS "
                
                line = f"{prefix} {result.file_path.name}"
                if result.reason:
                    line += f" → {result.reason}"
                if hasattr(result, 'signature_match') and result.signature_match:
                    line += f"  [Signature: {result.signature_match}]"
                
                self.results_display.append_text(line + "\n", tag)
                
                if hasattr(result, 'hash_value') and result.hash_value and isinstance(result.hash_value, dict):
                    self.results_display.append_text("  Hashes:\n", "clean")
                    for algo, h in result.hash_value.items():
                        self.results_display.append_text(f"    {algo.upper()}: {h}\n", "clean")
                
                self.results_display.append_text("\n")
        
        # Summary
        malicious = sum(1 for r in results if r.threat_level == ThreatLevel.MALICIOUS)
        suspicious = sum(1 for r in results if r.threat_level == ThreatLevel.SUSPICIOUS)
        
        summary = (
            f"\nSummary:\n"
            f"  Malicious:   {malicious}\n"
            f"  Suspicious:  {suspicious}\n"
            f"  Clean:       {len(results) - malicious - suspicious}\n"
        )
        
        self.results_display.append_text(summary, "header")
        
        # Re-enable scan button
        self.action_buttons.set_scanning(False)
    
    def _on_scan_error(self, error_msg):
        """Handle scan error"""
        self.results_display.append_text(f"\nError during scan: {error_msg}\n", "malicious")
        self.action_buttons.set_scanning(False)
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_thread.wait()
        event.accept()