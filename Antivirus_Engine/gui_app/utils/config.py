"""
Configuration Module
===================
Handles application configuration and settings.
"""

import os
import json
from pathlib import Path


class AppConfig:
    """Application configuration manager."""
    
    def __init__(self):
        self.app_name = "AegisAI Antivirus"
        self.version = "1.0.0"
        self.window_width = 1100
        self.window_height = 700
        self.min_width = 900
        self.min_height = 600
        
        # Rust engine path (relative to project root)
        self.rust_engine_path = self._find_rust_engine()
        
        # Scan settings
        self.max_file_size = 100 * 1024 * 1024  # 100 MB
        self.recursive_scan = True
        
        # UI Settings
        self.animation_speed = 20  # milliseconds
        self.theme = "dark"
        
        # Paths
        self.config_dir = Path.home() / ".aegisai"
        self.config_file = self.config_dir / "config.json"
        self.log_dir = self.config_dir / "logs"
        
        # Create necessary directories
        self._ensure_directories()
        
        # Load saved configuration
        self.load_config()
    
    def _find_rust_engine(self) -> Path:
        """Locate the Rust antivirus engine executable."""
        # Try common locations
        possible_paths = [
            Path("../target/release/antivirus_engine.exe"),
            Path("../target/release/antivirus_engine"),
            Path("./antivirus_engine.exe"),
            Path("./antivirus_engine"),
        ]
        
        for path in possible_paths:
            if path.exists():
                return path.resolve()
        
        # Default to release build path
        return Path("../target/release/antivirus_engine")
    
    def _ensure_directories(self):
        """Create necessary application directories."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def load_config(self):
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.max_file_size = data.get('max_file_size', self.max_file_size)
                    self.recursive_scan = data.get('recursive_scan', self.recursive_scan)
                    self.theme = data.get('theme', self.theme)
            except Exception as e:
                print(f"Error loading config: {e}")
    
    def save_config(self):
        """Save configuration to file."""
        try:
            data = {
                'max_file_size': self.max_file_size,
                'recursive_scan': self.recursive_scan,
                'theme': self.theme,
            }
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")