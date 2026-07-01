import logging

class MLPredictor:
    def __init__(self, enable_ml=True):
        self.enable_ml = enable_ml
        self.gender_detector = None
        
        if self.enable_ml:
            try:
                import gender_guesser.detector as gender
                self.gender_detector = gender.Detector()
            except ImportError:
                logging.warning("gender-guesser module not found.")
                
            try:
                import spacy
                self.nlp = spacy.load("en_core_web_sm")
            except Exception as e:
                logging.warning(f"spaCy module not found or model not downloaded: {e}")
                self.nlp = None

    def is_person(self, text):
        """
        Uses spaCy NER to verify if the text is a PERSON.
        Returns False if the text is clearly an Organization, Product, etc.
        """
        if not self.enable_ml or not self.nlp or not text:
            return True # Fallback: assume valid if ML is disabled/missing
            
        # Title case significantly improves NER accuracy for names
        doc = self.nlp(text.title()) 
        for ent in doc.ents:
            if ent.label_ in ["ORG", "PRODUCT", "WORK_OF_ART", "EVENT", "FAC"]:
                return False
        return True

    def predict(self, name, email=None):
        """
        Takes an extracted full name and predicts Gender.
        If email is provided, extracts Country from the TLD.
        Returns a tuple: (gender, country)
        """
        gender = ""
        country = ""
        
        # 1. Predict Gender
        if self.enable_ml and name:
            if self.gender_detector:
                # Попробуем сначала первое слово (обычно имя)
                first_name = name.split()[0]
                predicted_gender = self.gender_detector.get_gender(first_name)
                
                # Если пол не найден или унисекс, попробуем скормить все имя целиком
                if predicted_gender in ['unknown', 'andy']:
                    predicted_gender = self.gender_detector.get_gender(name)
                    
                if predicted_gender in ['male', 'mostly_male']:
                    gender = "Мужской"
                elif predicted_gender in ['female', 'mostly_female']:
                    gender = "Женский"
                elif predicted_gender == 'andy':
                    # User specifically dislikes "Унисекс" and "Неизвестно", 
                    # so we just leave it blank if we aren't sure.
                    pass

        # 2. Extract Country from TLD
        if email and "@" in email:
            domain = email.split("@")[1].lower()
            if "." in domain:
                tld = domain.split(".")[-1]
                tld_map = {
                    "ru": "Россия",
                    "su": "СССР",
                    "by": "Беларусь",
                    "kz": "Казахстан",
                    "ua": "Украина",
                    "de": "Германия",
                    "fr": "Франция",
                    "uk": "Великобритания",
                    "it": "Италия",
                    "es": "Испания",
                    "pl": "Польша",
                    "nl": "Нидерланды",
                    "jp": "Япония",
                    "cn": "Китай",
                    "in": "Индия",
                    "br": "Бразилия",
                    "au": "Австралия",
                    "ca": "Канада",
                    "us": "США",
                    "ch": "Швейцария",
                    "se": "Швеция",
                    "no": "Норвегия",
                    "fi": "Финляндия",
                    "dk": "Дания",
                    "pt": "Португалия",
                    "tr": "Турция"
                }
                if tld in tld_map:
                    country = tld_map[tld]
                elif tld in ["com", "net", "org", "info", "biz", "pro"]:
                    country = "Международный"

        return (gender, country)

if __name__ == '__main__':
    predictor = MLPredictor()
    test_names = ["John", "Sarah", "Alex", "Maria", "Bruce"]
    for n in test_names:
        print(f"{n} -> {predictor.predict(n)}")
