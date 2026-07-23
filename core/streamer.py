import os
import re

CLEAN_PREFIX_RE = re.compile(r'^\d+[-.)\]:й]*\s+')

def clean_input_line_fast(line):
    return CLEAN_PREFIX_RE.sub('', line.strip())

class StreamLoader:
    """Утилита для потокового чтения данных из различных источников (файлы или текст)"""
    def __init__(self, sources):
        self.sources = sources
        
    def stream_emails(self):
        """Генератор, который выдает пары (email, data)"""
        for source in self.sources:
            if source["type"] == "text":
                for line in source["content"].split("\n"):
                    line = line.strip()
                    if not line: continue
                    parts = line.split(":")
                    email = clean_input_line_fast(parts[0])
                    if email:
                        data = {"name": "", "gender": "", "country": ""}
                        if len(parts) >= 2: data["name"] = parts[1].strip()
                        if len(parts) >= 3: data["gender"] = parts[2].strip()
                        if len(parts) >= 4: data["country"] = parts[3].strip()
                        yield email, data
            elif source["type"] == "file":
                filepath = source["path"]
                if os.path.exists(filepath):
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line: continue
                            parts = line.split(":")
                            email = clean_input_line_fast(parts[0])
                            if email:
                                data = {"name": "", "gender": "", "country": ""}
                                if len(parts) >= 2: data["name"] = parts[1].strip()
                                if len(parts) >= 3: data["gender"] = parts[2].strip()
                                if len(parts) >= 4: data["country"] = parts[3].strip()
                                yield email, data

    def stream_lines(self):
        """Генератор для прокси и дорков"""
        for source in self.sources:
            if source["type"] == "text":
                for line in source["content"].split("\n"):
                    line = line.strip()
                    if line:
                        yield clean_input_line_fast(line)
            elif source["type"] == "file":
                filepath = source["path"]
                if os.path.exists(filepath):
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                yield clean_input_line_fast(line)

    def count_total_lines(self):
        """Быстрый подсчет строк без загрузки в память"""
        total = 0
        for source in self.sources:
            if source["type"] == "text":
                total += len([line for line in source["content"].split("\n") if line.strip()])
            elif source["type"] == "file":
                filepath = source["path"]
                if os.path.exists(filepath):
                    # Очень быстрый подсчет через генератор
                    with open(filepath, "rb") as f:
                        total += sum(1 for _ in f)
        return total
