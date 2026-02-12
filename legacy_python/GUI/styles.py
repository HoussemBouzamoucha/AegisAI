"""
Styling definitions for the application
"""

class AppStyles:
    """Contains all color and style definitions"""
    
    # Dark theme colors
    BG_DARK = "#0a0e14"
    BG_SECONDARY = "#1a1f2e"
    BG_TERTIARY = "#2a2f3e"
    ACCENT_GREEN = "#2d9669"
    ACCENT_GREEN_HOVER = "#3ab87c"
    TEXT_PRIMARY = "#e6e6e6"
    TEXT_SECONDARY = "#a0a0a0"
    TEXT_DIM = "#606060"
    
    # Threat level colors
    COLOR_MALICIOUS = "#ff4757"
    COLOR_SUSPICIOUS = "#ffa502"
    COLOR_CLEAN = "#2ed573"
    
    @classmethod
    def get_main_stylesheet(cls):
        """Returns the main application stylesheet"""
        return f"""
            QMainWindow {{
                background-color: {cls.BG_DARK};
            }}
            
            QWidget {{
                background-color: {cls.BG_DARK};
                color: {cls.TEXT_PRIMARY};
            }}
            
            #content_card {{
                background-color: {cls.BG_DARK};
            }}
            
            #card_frame {{
                background-color: {cls.BG_SECONDARY};
                border: 1px solid {cls.BG_TERTIARY};
                border-radius: 0px;
            }}
            
            QLabel {{
                background-color: transparent;
                color: {cls.TEXT_PRIMARY};
            }}
            
            QRadioButton {{
                background-color: {cls.BG_TERTIARY};
                color: {cls.TEXT_SECONDARY};
                border: none;
                padding: 12px;
                spacing: 8px;
            }}
            
            QRadioButton#file_radio {{
                background-color: {cls.ACCENT_GREEN};
                color: white;
                font-weight: bold;
            }}
            
            QRadioButton#file_radio:hover {{
                background-color: {cls.ACCENT_GREEN_HOVER};
            }}
            
            QRadioButton#dir_radio {{
                background-color: {cls.BG_TERTIARY};
                color: {cls.TEXT_SECONDARY};
            }}
            
            QRadioButton#dir_radio:hover {{
                background-color: #3a3f4e;
            }}
            
            QRadioButton::indicator {{
                width: 0px;
                height: 0px;
            }}
            
            #path_frame {{
                background-color: {cls.BG_TERTIARY};
                border: 1px solid #3a3f4e;
                border-radius: 0px;
            }}
            
            QLineEdit {{
                background-color: {cls.BG_TERTIARY};
                color: {cls.TEXT_PRIMARY};
                border: none;
                padding: 0px;
            }}
            
            QLineEdit::placeholder {{
                color: {cls.TEXT_DIM};
            }}
            
            QPushButton#browse_btn {{
                background-color: {cls.BG_TERTIARY};
                color: {cls.TEXT_PRIMARY};
                border: none;
                padding: 12px 20px;
            }}
            
            QPushButton#browse_btn:hover {{
                background-color: #3a3f4e;
                color: white;
            }}
            
            QPushButton#scan_btn {{
                background-color: {cls.ACCENT_GREEN};
                color: white;
                border: none;
                padding: 14px;
            }}
            
            QPushButton#scan_btn:hover {{
                background-color: {cls.ACCENT_GREEN_HOVER};
            }}
            
            QPushButton#scan_btn:disabled {{
                background-color: #1a4d3a;
                color: #808080;
            }}
            
            QPushButton#clear_btn {{
                background-color: {cls.BG_TERTIARY};
                color: {cls.TEXT_SECONDARY};
                border: none;
                padding: 14px 25px;
            }}
            
            QPushButton#clear_btn:hover {{
                background-color: #3a3f4e;
                color: {cls.TEXT_PRIMARY};
            }}
            
            QTextEdit#result_text {{
                background-color: {cls.BG_TERTIARY};
                color: {cls.TEXT_SECONDARY};
                border: none;
                padding: 15px;
            }}
            
            QScrollBar:vertical {{
                background-color: {cls.BG_TERTIARY};
                width: 12px;
                border: none;
            }}
            
            QScrollBar::handle:vertical {{
                background-color: {cls.TEXT_DIM};
                border-radius: 6px;
                min-height: 20px;
            }}
            
            QScrollBar::handle:vertical:hover {{
                background-color: {cls.TEXT_SECONDARY};
            }}
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: none;
            }}
        """
    
    @classmethod
    def get_radio_active_style(cls):
        """Style for active radio button"""
        return f"""
            background-color: {cls.ACCENT_GREEN};
            color: white;
            border: none;
            padding: 12px;
            font-weight: bold;
        """
    
    @classmethod
    def get_radio_inactive_style(cls):
        """Style for inactive radio button"""
        return f"""
            background-color: {cls.BG_TERTIARY};
            color: {cls.TEXT_SECONDARY};
            border: none;
            padding: 12px;
            font-weight: normal;
        """