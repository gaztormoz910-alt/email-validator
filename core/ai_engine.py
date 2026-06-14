# core/ai_engine.py
import math
import re
import numpy as np

class EmailAI:
    def __init__(self):
        self.nb_classifier = None
        self.rf_classifier = None
        self.is_trained = False

    def _calculate_entropy(self, text):
        if not text:
            return 0
        entropy = 0
        for x in set(text):
            p_x = float(text.count(x)) / len(text)
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract_features(self, email):
        local_part = email.split('@')[0] if '@' in email else email
        length = len(local_part)
        entropy = self._calculate_entropy(local_part)
        
        digits = sum(c.isdigit() for c in local_part)
        digit_ratio = digits / length if length > 0 else 0
        
        vowels = sum(c in 'aeiouy' for c in local_part.lower())
        vowel_ratio = vowels / length if length > 0 else 0
        
        consonants_str = re.sub(r'[^bcdfghjklmnpqrstvwxz]', ' ', local_part.lower())
        max_cons = max([len(c) for c in consonants_str.split()], default=0)
        
        return [length, entropy, digit_ratio, vowel_ratio, max_cons]

    def _generate_synthetic_data(self):
        X, y = [], []
        
        valid_samples = [
            "john.doe", "alexander", "mike1990", "sarah.smith", "admin",
            "support", "info", "contact", "developer", "david_b", 
            "christopher", "jessica22", "team", "hello", "marketing", "user",
            "gaztormoz910"
        ]
        for v in valid_samples:
            X.append(self.extract_features(v))
            y.append(0)
            
        spam_samples = [
            "fake-acc-123456789", "ajsjdhfkasd", "qweqwe123", "usr9912384712",
            "xxyyzz99", "1234567890", "asdfghjkl", "temp123456", "b1g_b0y_1337",
            "zxcvbnm123", "qwertyuiop", "a1s2d3f4g5", "1a2b3c4d5e", "hacker"
        ]
        for s in spam_samples:
            X.append(self.extract_features(s))
            y.append(1)
            
        for _ in range(500):
            X.append([np.random.randint(5, 15), np.random.uniform(2.0, 3.8), 
                      np.random.uniform(0.0, 0.5), np.random.uniform(0.1, 0.6), np.random.randint(1, 5)])
            y.append(0)
            
            X.append([np.random.randint(15, 30), np.random.uniform(4.0, 5.0), 
                      np.random.uniform(0.6, 1.0), np.random.uniform(0.0, 0.1), np.random.randint(6, 10)])
            y.append(1)
            
        return np.array(X), np.array(y)

    def train_models(self):
        try:
            from sklearn.naive_bayes import GaussianNB
            from sklearn.ensemble import RandomForestClassifier
        except ImportError:
            print("[WARNING] Библиотека Scikit-Learn не установлена. ИИ-фильтр отключен.")
            return

        X, y = self._generate_synthetic_data()
        
        self.nb_classifier = GaussianNB()
        self.nb_classifier.fit(X, y)
        
        self.rf_classifier = RandomForestClassifier(n_estimators=50, random_state=42)
        self.rf_classifier.fit(X, y)
        
        self.is_trained = True
        
    def predict(self, email):
        if not self.is_trained:
            return False
            
        features = np.array([self.extract_features(email)])
        nb_pred = self.nb_classifier.predict(features)[0]
        rf_prob = self.rf_classifier.predict_proba(features)[0][1]
        
        # Делаем ИИ максимально лояльным к людям. Блокируем только если уверенность нейросети > 95%
        if rf_prob >= 0.95:
            return True
        return False
