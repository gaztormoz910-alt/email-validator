# main.py
import sys
import os

# Suppress annoying dnspython UDP dropped packet warnings in terminal
class StderrFilter:
    def __init__(self, original_stderr):
        self.original_stderr = original_stderr

    def write(self, msg):
        if "expected message id:" in msg or "ignoring response from" in msg or "dropped" in msg:
            return
        self.original_stderr.write(msg)

    def flush(self):
        self.original_stderr.flush()

sys.stderr = StderrFilter(sys.stderr)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ui.gui import ValidatorApp

def main():
    app = ValidatorApp()
    
    app.safe_log("[INFO] Система успешно инициализирована. Валидатор готов к работе.", "info")
    app.safe_log("[INFO] Ожидание загрузки базы (.txt)...", "info")
    
    app.mainloop()

if __name__ == "__main__":
    main()
