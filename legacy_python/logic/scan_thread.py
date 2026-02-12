"""
Threading logic for file scanning operations
"""

from PySide6.QtCore import QThread, Signal


class ScanThread(QThread):
    """Thread for running scans without blocking the UI"""
    
    result_ready = Signal(object)
    scan_complete = Signal(list)
    error_occurred = Signal(str)
    progress_update = Signal(str)
    
    def __init__(self, scanner, target, is_file):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.is_file = is_file
        
    def run(self):
        """Execute the scan operation"""
        results = []
        try:
            if self.is_file:
                result = self.scanner.scan_file(self.target)
                results.append(result)
                self.result_ready.emit(result)
            else:
                self.progress_update.emit("Scanning directory (recursive)...\n\n")
                count = 0
                for result in self.scanner.scan_directory(self.target, recursive=True):
                    count += 1
                    results.append(result)
                    self.result_ready.emit(result)
                    
                    if count % 20 == 0:
                        QThread.msleep(1)  # Allow UI updates
                
                self.progress_update.emit(f"\nFinished. Scanned {count} files.\n")
            
            self.scan_complete.emit(results)
        except Exception as e:
            self.error_occurred.emit(str(e))