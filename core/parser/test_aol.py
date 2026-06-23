import sys
sys.path.append('.')
import engine

class Dummy:
    timeout = 10.0
    def get_proxy(self): return None
    def mark_dead(self, u): pass
    def mark_success(self, u): pass
    def get_total_count(self): return 0

a = engine.AOLEngine(Dummy(), on_log=print)
gen = a.search_generator('site:linkedin.com "CEO" "email"')
try:
    for _ in range(5):
        print(next(gen)[:50])
except Exception as e:
    print(e)
