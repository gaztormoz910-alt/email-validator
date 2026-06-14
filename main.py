# main.py
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ui.gui import ValidatorApp

def main():
    app = ValidatorApp()
    
    app.safe_log("[INFO] Система успешно инициализирована. Валидатор готов к работе.", "info")
    app.safe_log("[INFO] Ожидание загрузки базы (.txt)...", "info")
    
    app.mainloop()

if __name__ == "__main__":
    main()
