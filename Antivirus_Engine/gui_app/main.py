"""
AegisAI Antivirus - Main Application Entry Point
================================================
Modern desktop antivirus application with animated UI.

Author: AegisAI Team
Version: 1.0.0
"""

import customtkinter as ctk
from gui.main_window import MainWindow
from utils.config import AppConfig
import sys


def main():
    """Main entry point for the application."""
    # Set appearance mode and color theme
    ctk.set_appearance_mode("dark")  # Modes: "dark", "light", "system"
    ctk.set_default_color_theme("blue")  # Themes: "blue", "green", "dark-blue"
    
    # Initialize configuration
    config = AppConfig()
    
    # Create and run the main window
    app = MainWindow(config)
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)