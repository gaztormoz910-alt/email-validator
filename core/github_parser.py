# core/github_parser.py
import os
import urllib.request

class BlacklistDownloader:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        # Создаем папку data, если её нет
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            
        # Ссылки на GitHub репозитории с базами
        self.sources = {
            "disposable.txt": "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
            "spam_traps.txt": "https://raw.githubusercontent.com/unkn0w/disposable-email-domain-list/master/domains.txt"
        }

    def download_all(self):
        """Скачивает черные списки с GitHub и объединяет их с локальными (накопительная база)."""
        import time
        for filename, url in self.sources.items():
            filepath = os.path.join(self.data_dir, filename)
            
            should_download = True
            local_domains = set()
            
            if os.path.exists(filepath):
                # Читаем локальную базу
                with open(filepath, "r", encoding="utf-8") as f:
                    local_domains = set(line.strip() for line in f if line.strip())
                    
                # Обновляем не чаще 1 раза в сутки (86400 секунд), чтобы не спамить GitHub
                if time.time() - os.path.getmtime(filepath) < 86400:
                    should_download = False
            
            if not should_download:
                continue
                
            try:
                # Скачиваем свежую базу в память
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    content = response.read().decode('utf-8')
                    
                new_domains = set(line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#'))
                
                # ГЛАВНАЯ ФИШКА: Объединяем локальную и новую базу! 
                combined_domains = local_domains | new_domains
                
                # ПРЕДОХРАНИТЕЛЬ: Если база вдруг разрастется больше 50 Мегабайт (это около 3.5 МИЛЛИОНОВ доменов)
                # Оставляем только свежие домены, чтобы не забивать оперативную память.
                if len(combined_domains) > 3500000:
                    # Берем последние 3.5 миллиона добавленных (сортировка или конвертация)
                    combined_domains = set(list(combined_domains)[:3500000])
                
                with open(filepath, "w", encoding="utf-8") as f:
                    for d in sorted(combined_domains):
                        f.write(d + "\n")
            except Exception:
                pass # Если ошибка скачивания, просто продолжаем использовать старую локальную базу
