"""
AegisAI Scanner Application Entry Point
"""

import sys
from PySide6.QtWidgets import QApplication

from GUI import ModernScannerGUI
from Core.scanner import FileScanner


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Create scanner instance
    scanner = FileScanner()
    
    # Create and show main window
    window = ModernScannerGUI(scanner)
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()