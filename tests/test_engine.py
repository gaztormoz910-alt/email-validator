import unittest
import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.parser.engine import ProxyManager, DuckDuckGoEngine

class TestProxyManager(unittest.TestCase):
    def setUp(self):
        # We simulate some proxies
        self.raw_proxies = [
            "127.0.0.1:9050",
            "socks5://192.168.1.1:1080",
            "http://10.0.0.1:8080"
        ]
        self.manager = ProxyManager(self.raw_proxies)

    def test_proxy_parsing_and_round_robin(self):
        # The manager should automatically add socks5:// if missing
        self.assertEqual(self.manager.get_total_count(), 3)
        self.assertEqual(self.manager.get_live_count(), 3)
        
        proxy1 = self.manager.get_proxy()
        proxy2 = self.manager.get_proxy()
        proxy3 = self.manager.get_proxy()
        proxy4 = self.manager.get_proxy() # Should cycle back to 1
        
        self.assertEqual(proxy1, "socks5://127.0.0.1:9050")
        self.assertEqual(proxy2, "socks5://192.168.1.1:1080")
        self.assertEqual(proxy3, "http://10.0.0.1:8080")
        self.assertEqual(proxy4, "socks5://127.0.0.1:9050") # Round-robin verified

    def test_proxy_dead_marking(self):
        proxy1 = self.manager.get_proxy()
        # Proxy only dies after 10 fails (bumped from 3 for resilience against transient errors)
        for _ in range(10):
            self.manager.mark_fail(proxy1)

        # Now there should be only 2 live proxies
        self.assertEqual(self.manager.get_live_count(), 2)
        
        # Next get_proxy should skip the dead one completely
        new_proxy1 = self.manager.get_proxy()
        new_proxy2 = self.manager.get_proxy()
        new_proxy3 = self.manager.get_proxy()
        
        self.assertEqual(new_proxy1, "http://10.0.0.1:8080")
        self.assertEqual(new_proxy2, "socks5://192.168.1.1:1080")
        self.assertEqual(new_proxy3, "http://10.0.0.1:8080")

class TestEngine(unittest.TestCase):
    def test_engine_initialization(self):
        manager = ProxyManager(["127.0.0.1:9050"])
        engine = DuckDuckGoEngine(manager)
        self.assertIsNotNone(engine)

if __name__ == '__main__':
    unittest.main()
