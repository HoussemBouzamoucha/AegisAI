"""
Custom widgets for the scanner GUI
"""

from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
    QRadioButton, QLineEdit, QTextEdit, QFrame, QButtonGroup, QFileDialog
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QTextCursor, QTextCharFormat, QColor
from pathlib import Path

from .styles import AppStyles


class ModeSelector(QWidget):
    """Widget for selecting scan mode (File or Directory)"""
    
    mode_changed = Signal(bool)  # True for file, False for directory
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.button_group = QButtonGroup(self)
        
        # File Scan button
        self.file_radio = QRadioButton("📄  File Scan")
        self.file_radio.setObjectName("file_radio")
        self.file_radio.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.file_radio.setCursor(Qt.PointingHandCursor)
        self.file_radio.setChecked(True)
        self.file_radio.toggled.connect(self._on_mode_changed)
        self.button_group.addButton(self.file_radio)
        layout.addWidget(self.file_radio, 1)
        
        # Directory Scan button
        self.dir_radio = QRadioButton("📁  Directory Scan")
        self.dir_radio.setObjectName("dir_radio")
        self.dir_radio.setFont(QFont("Segoe UI", 11))
        self.dir_radio.setCursor(Qt.PointingHandCursor)
        self.dir_radio.toggled.connect(self._on_mode_changed)
        self.button_group.addButton(self.dir_radio)
        layout.addWidget(self.dir_radio, 1)
    
    def _on_mode_changed(self):
        """Handle mode selection change"""
        if self.file_radio.isChecked():
            self.file_radio.setStyleSheet(AppStyles.get_radio_active_style())
            self.dir_radio.setStyleSheet(AppStyles.get_radio_inactive_style())
            self.file_radio.setFont(QFont("Segoe UI", 11, QFont.Bold))
            self.dir_radio.setFont(QFont("Segoe UI", 11))
        else:
            self.dir_radio.setStyleSheet(AppStyles.get_radio_active_style())
            self.file_radio.setStyleSheet(AppStyles.get_radio_inactive_style())
            self.dir_radio.setFont(QFont("Segoe UI", 11, QFont.Bold))
            self.file_radio.setFont(QFont("Segoe UI", 11))
        
        self.mode_changed.emit(self.file_radio.isChecked())
    
    def is_file_mode(self):
        """Returns True if file mode is selected"""
        return self.file_radio.isChecked()


class PathInput(QWidget):
    """Widget for path input with browse button"""
    
    browse_clicked = Signal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Path input frame
        path_frame = QFrame()
        path_frame.setObjectName("path_frame")
        path_frame_layout = QHBoxLayout(path_frame)
        path_frame_layout.setContentsMargins(15, 12, 15, 12)
        
        self.path_entry = QLineEdit()
        self.path_entry.setObjectName("path_entry")
        self.path_entry.setPlaceholderText("Enter file path or click Browse...")
        self.path_entry.setFont(QFont("Consolas", 10))
        path_frame_layout.addWidget(self.path_entry)
        
        layout.addWidget(path_frame, 1)
        
        # Browse button
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setObjectName("browse_btn")
        self.browse_btn.setFont(QFont("Segoe UI", 10))
        self.browse_btn.setCursor(Qt.PointingHandCursor)
        self.browse_btn.clicked.connect(self.browse_clicked.emit)
        layout.addWidget(self.browse_btn)
    
    def get_path(self):
        """Returns the current path"""
        return self.path_entry.text().strip()
    
    def set_path(self, path):
        """Sets the path"""
        self.path_entry.setText(path)


class ActionButtons(QWidget):
    """Widget for action buttons (Start Scan, Clear)"""
    
    scan_clicked = Signal()
    clear_clicked = Signal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Start Scan button
        self.scan_btn = QPushButton("▶  Start Scan")
        self.scan_btn.setObjectName("scan_btn")
        self.scan_btn.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.scan_btn.setCursor(Qt.PointingHandCursor)
        self.scan_btn.clicked.connect(self.scan_clicked.emit)
        layout.addWidget(self.scan_btn, 1)
        
        # Clear button
        self.clear_btn = QPushButton("🗑  Clear")
        self.clear_btn.setObjectName("clear_btn")
        self.clear_btn.setFont(QFont("Segoe UI", 10))
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.clicked.connect(self.clear_clicked.emit)
        layout.addWidget(self.clear_btn)
    
    def set_scanning(self, is_scanning):
        """Enable/disable scan button and update text"""
        self.scan_btn.setEnabled(not is_scanning)
        if is_scanning:
            self.scan_btn.setText("⏳ Scanning...")
        else:
            self.scan_btn.setText("▶  Start Scan")


class ResultsDisplay(QWidget):
    """Widget for displaying scan results"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Results header
        header = QLabel("▶  scan_results")
        header.setFont(QFont("Consolas", 9))
        layout.addWidget(header)
        
        # Results text area
        self.result_text = QTextEdit()
        self.result_text.setObjectName("result_text")
        self.result_text.setFont(QFont("Consolas", 10))
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text, 1)
    
    def clear(self):
        """Clear all results"""
        self.result_text.clear()
    
    def show_empty_state(self):
        """Display empty state message"""
        self.result_text.clear()
        cursor = self.result_text.textCursor()
        
        # Add spacing
        cursor.insertText("\n\n\n\n")
        
        # Icon
        icon_format = QTextCharFormat()
        icon_format.setFont(QFont("Segoe UI", 32))
        icon_format.setForeground(QColor(AppStyles.TEXT_DIM))
        
        block_format = cursor.blockFormat()
        block_format.setAlignment(Qt.AlignCenter)
        cursor.setBlockFormat(block_format)
        
        cursor.insertText("🛡\n", icon_format)
        
        # Empty state text
        empty_format = QTextCharFormat()
        empty_format.setFont(QFont("Segoe UI", 10))
        empty_format.setForeground(QColor(AppStyles.TEXT_DIM))
        
        cursor.insertText("\nNo scan results yet\n", empty_format)
        cursor.insertText("Select a target and start scanning", empty_format)
    
    def append_text(self, text, style="normal"):
        """Append text with specified style"""
        cursor = self.result_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        char_format = QTextCharFormat()
        
        if style == "header":
            char_format.setFont(QFont("Consolas", 11, QFont.Bold))
            char_format.setForeground(QColor(AppStyles.TEXT_PRIMARY))
        elif style == "malicious":
            char_format.setFont(QFont("Consolas", 10, QFont.Bold))
            char_format.setForeground(QColor(AppStyles.COLOR_MALICIOUS))
        elif style == "suspicious":
            char_format.setFont(QFont("Consolas", 10))
            char_format.setForeground(QColor(AppStyles.COLOR_SUSPICIOUS))
        elif style == "clean":
            char_format.setFont(QFont("Consolas", 10))
            char_format.setForeground(QColor(AppStyles.COLOR_CLEAN))
        elif style == "danger_header":
            char_format.setFont(QFont("Segoe UI", 14, QFont.Bold))
            char_format.setForeground(QColor(AppStyles.COLOR_MALICIOUS))
        else:
            char_format.setFont(QFont("Consolas", 10))
            char_format.setForeground(QColor(AppStyles.TEXT_SECONDARY))
        
        cursor.insertText(text, char_format)
        self.result_text.ensureCursorVisible()