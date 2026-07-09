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

            try:
                from names_dataset import NameDataset
                self.nd = NameDataset()
            except ImportError:
                logging.warning("names_dataset module not found.")
                self.nd = None

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

        return (gender, country)

    def predict_country(self, name):
        """
        Takes an extracted full name and predicts Country.
        Returns the country string.
        """
        if not self.enable_ml or getattr(self, 'nd', None) is None or not name:
            return ""
            
        first_name = name.split()[0].title()
        res = self.nd.search(first_name)
        
        if not res or 'first_name' not in res or not res['first_name'] or 'country' not in res['first_name']:
            return ""
            
        country_data = res['first_name'].get('country')
        if not country_data:
            return ""
            
        # Get the country with highest probability
        valid_countries = {k: v for k, v in country_data.items() if v is not None}
        if not valid_countries:
            return ""
            
        best_country = max(valid_countries.items(), key=lambda x: x[1])
        country_name = best_country[0]
        
        translation_map = {
            "Afghanistan": "Афганистан", "Albania": "Албания", "Algeria": "Алжир", "Andorra": "Андорра", "Angola": "Ангола", 
            "Antigua and Barbuda": "Антигуа и Барбуда", "Argentina": "Аргентина", "Armenia": "Армения", "Australia": "Австралия", 
            "Austria": "Австрия", "Azerbaijan": "Азербайджан", "Bahamas": "Багамы", "Bahrain": "Бахрейн", "Bangladesh": "Бангладеш", 
            "Barbados": "Барбадос", "Belarus": "Беларусь", "Belgium": "Бельгия", "Belize": "Белиз", "Benin": "Бенин", "Bhutan": "Бутан", 
            "Bolivia, Plurinational State of": "Боливия", "Bosnia and Herzegovina": "Босния и Герцеговина", "Botswana": "Ботсвана", 
            "Brazil": "Бразилия", "Brunei Darussalam": "Бруней", "Bulgaria": "Болгария", "Burkina Faso": "Буркина-Фасо", "Burundi": "Бурунди", 
            "Cabo Verde": "Кабо-Верде", "Cambodia": "Камбоджа", "Cameroon": "Камерун", "Canada": "Канада", "Central African Republic": "ЦАР", 
            "Chad": "Чад", "Chile": "Чили", "China": "Китай", "Colombia": "Колумбия", "Comoros": "Коморы", "Congo": "Конго", 
            "Congo, The Democratic Republic of the": "ДР Конго", "Costa Rica": "Коста-Рика", "Croatia": "Хорватия", "Cuba": "Куба", 
            "Cyprus": "Кипр", "Czech Republic": "Чехия", "Denmark": "Дания", "Djibouti": "Джибути", "Dominica": "Доминика", 
            "Dominican Republic": "Доминиканская Республика", "Ecuador": "Эквадор", "Egypt": "Египет", "El Salvador": "Сальвадор", 
            "Equatorial Guinea": "Экваториальная Гвинея", "Eritrea": "Эритрея", "Estonia": "Эстония", "Eswatini": "Эсватини", 
            "Ethiopia": "Эфиопия", "Fiji": "Фиджи", "Finland": "Финляндия", "France": "Франция", "Gabon": "Габон", "Gambia": "Гамбия", 
            "Georgia": "Грузия", "Germany": "Германия", "Ghana": "Гана", "Greece": "Греция", "Grenada": "Гренада", "Guatemala": "Гватемала", 
            "Guinea": "Гвинея", "Guinea-Bissau": "Гвинея-Бисау", "Guyana": "Гайана", "Haiti": "Гаити", "Honduras": "Гондурас", 
            "Hungary": "Венгрия", "Iceland": "Исландия", "India": "Индия", "Indonesia": "Индонезия", "Iran, Islamic Republic of": "Иран", 
            "Iraq": "Ирак", "Ireland": "Ирландия", "Israel": "Израиль", "Italy": "Италия", "Jamaica": "Ямайка", "Japan": "Япония", 
            "Jordan": "Иордания", "Kazakhstan": "Казахстан", "Kenya": "Кения", "Kiribati": "Кирибати", 
            "Korea, Democratic People's Republic of": "КНДР", "Korea, Republic of": "Южная Корея", "Kuwait": "Кувейт", 
            "Kyrgyzstan": "Кыргызстан", "Lao People's Democratic Republic": "Лаос", "Latvia": "Латвия", "Lebanon": "Ливан", 
            "Lesotho": "Лесото", "Liberia": "Либерия", "Libya": "Ливия", "Liechtenstein": "Лихтенштейн", "Lithuania": "Литва", 
            "Luxembourg": "Люксембург", "Madagascar": "Мадагаскар", "Malawi": "Малави", "Malaysia": "Малайзия", "Maldives": "Мальдивы", 
            "Mali": "Мали", "Malta": "Мальта", "Marshall Islands": "Маршалловы острова", "Mauritania": "Мавритания", 
            "Mauritius": "Маврикий", "Mexico": "Мексика", "Micronesia, Federated States of": "Микронезия", 
            "Moldova, Republic of": "Молдова", "Monaco": "Монако", "Mongolia": "Монголия", "Montenegro": "Черногория", 
            "Morocco": "Марокко", "Mozambique": "Мозамби", "Myanmar": "Мьянма", "Namibia": "Намибия", "Nauru": "Науру", 
            "Nepal": "Непал", "Netherlands": "Нидерланды", "New Zealand": "Новая Зеландия", "Nicaragua": "Никарагуа", 
            "Niger": "Нигер", "Nigeria": "Нигерия", "North Macedonia": "Северная Македония", "Norway": "Норвегия", "Oman": "Оман", 
            "Pakistan": "Пакистан", "Palau": "Палау", "Palestine, State of": "Палестина", "Panama": "Панама", 
            "Papua New Guinea": "Папуа - Новая Гвинея", "Paraguay": "Парагвай", "Peru": "Перу", "Philippines": "Филиппины", 
            "Poland": "Польша", "Portugal": "Португалия", "Qatar": "Катар", "Romania": "Румыния", "Russian Federation": "Россия", 
            "Russia": "Россия", "Rwanda": "Руанда", "Saint Kitts and Nevis": "Сент-Китс", "Saint Lucia": "Сент-Люсия", 
            "Saint Vincent and the Grenadines": "Сент-Винсент", "Samoa": "Самоа", "San Marino": "Сан-Марино", 
            "Sao Tome and Principe": "Сан-Томе", "Saudi Arabia": "Саудовская Аравия", "Senegal": "Сенегал", "Serbia": "Сербия", 
            "Seychelles": "Сейшелы", "Sierra Leone": "Сьерра-Леоне", "Singapore": "Сингапур", "Slovakia": "Словакия", 
            "Slovenia": "Словения", "Solomon Islands": "Соломоновы Острова", "Somalia": "Сомали", "South Africa": "ЮАР", 
            "South Sudan": "Южный Судан", "Spain": "Испания", "Sri Lanka": "Шри-Ланка", "Sudan": "Судан", "Suriname": "Суринам", 
            "Sweden": "Швеция", "Switzerland": "Швейцария", "Syrian Arab Republic": "Сирия", "Taiwan, Province of China": "Тайвань", 
            "Tajikistan": "Таджикистан", "Tanzania, United Republic of": "Танзания", "Thailand": "Таиланд", "Timor-Leste": "Тимор", 
            "Togo": "Того", "Tonga": "Тонга", "Trinidad and Tobago": "Тринидад и Тобаго", "Tunisia": "Тунис", "Turkey": "Турция", 
            "Turkmenistan": "Туркменистан", "Tuvalu": "Тувалу", "Uganda": "Уганда", "Ukraine": "Украина", "United Arab Emirates": "ОАЭ", 
            "United Kingdom": "Великобритания", "United States": "США", "Uruguay": "Уругвай", "Uzbekistan": "Узбекистан", 
            "Vanuatu": "Вануату", "Venezuela, Bolivarian Republic of": "Венесуэла", "Viet Nam": "Вьетнам", "Yemen": "Йемен", 
            "Zambia": "Замбия", "Zimbabwe": "Зимбабве", "Hong Kong": "Гонконг", "Macao": "Макао", "Puerto Rico": "Пуэрто-Рико",
            "Türkiye": "Турция", "Turkiye": "Турция"
        }
        
        return translation_map.get(country_name, country_name)

if __name__ == '__main__':
    predictor = MLPredictor()
    test_names = ["John", "Sarah", "Alex", "Maria", "Bruce"]
    for n in test_names:
        print(f"{n} -> {predictor.predict(n)}")
