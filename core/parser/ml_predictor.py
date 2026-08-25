import logging

from core.provider import country_from_domain
from .translit import variants as translit_variants

# Страна (как мы её называем) -> ключ страны в gender_guesser.
#
# Зачем: у неоднозначных имён пол зависит от страны, и словарь это знает.
# Замерено: Andrea без страны -> female, в Италии -> male; Simone без страны ->
# female, в Италии -> male; Jean без страны -> male, в США -> mostly_female.
# Страну мы и так знаем из домена, так что точность растёт бесплатно.
_GENDER_COUNTRY = {
    "Россия": "russia", "Украина": "ukraine", "Беларусь": "belarus",
    "Германия": "germany", "Австрия": "austria", "Швейцария": "swiss",
    "Италия": "italy", "Франция": "france", "Испания": "spain",
    "Португалия": "portugal", "Великобритания": "great_britain",
    "Ирландия": "ireland", "США": "usa", "Бельгия": "belgium",
    "Дания": "denmark", "Швеция": "sweden", "Норвегия": "norway",
    "Финляндия": "finland", "Польша": "poland", "Чехия": "czech_republic",
    "Словакия": "slovakia", "Венгрия": "hungary", "Румыния": "romania",
    "Болгария": "bulgaria", "Хорватия": "croatia", "Сербия": "serbia",
    "Словения": "slovenia", "Греция": "greece", "Турция": "turkey",
    "Израиль": "israel", "Китай": "china", "Индия": "india",
    "Япония": "japan", "Южная Корея": "korea", "Вьетнам": "vietnam",
    "ОАЭ": "arabia", "Саудовская Аравия": "arabia",
}

# Пороги для страны по имени. Ноль означает «берём лидера всегда».
#
# ЭТО ОСОЗНАННЫЙ ВЫБОР ВЛАДЕЛЬЦА, А НЕ НЕДОСМОТР. Замерено на 1600 самых
# частых имён из восьми стран, где страна человека известна точно:
#
#     с порогами (0.35 / 2.0):   верно 49.6%,  пусто 41.7%,  НЕВЕРНО  8.8%
#     без порогов (эти нули):    верно 65.6%,  пусто  0.0%,  НЕВЕРНО 34.4%
#
# То есть колонка заполняется почти всегда ценой того, что примерно каждая
# третья страна — выдумка, и отличить её от правильной по самой колонке
# нельзя. Различить можно только по `country_source`: `домен` — это факт
# (web.de всегда Германия), `имя` — догадка с указанной выше точностью.
# Для гео-таргетинга это выбор «больше адресов, но треть не из той страны»
# против «меньше адресов, но попадание точное».
#
# Порядок источников при этом НЕ менялся: домен по-прежнему решает там, где
# знает, и имя спрашивается только при его молчании (.com, .net и подобные).
#
# РЕЖИМ ВЫБИРАЕТСЯ ИЗ ИНТЕРФЕЙСА, а не правкой этого файла. Раньше смена
# режима означала редактирование исходника — то есть на практике режим был
# один и навсегда. Теперь их два, и переключатель лежит в боковой панели.
COUNTRY_MODES = {
    # Заполненность: колонка заполняется почти всегда, примерно каждая третья
    # страна — выдумка. Отличить её можно только по country_source == "имя".
    "coverage": (0.0, 0.0),
    # Точность: слабое распределение отбрасывается. Замерено на 1600 именах —
    # верно 49.6%, пусто 41.7%, неверно 8.8% против 65.6/0/34.4 в "coverage".
    "accuracy": (0.35, 2.0),
}

DEFAULT_COUNTRY_MODE = "coverage"

NAME_COUNTRY_MIN_SHARE, NAME_COUNTRY_MIN_RATIO = COUNTRY_MODES[DEFAULT_COUNTRY_MODE]

_country_mode = DEFAULT_COUNTRY_MODE


def set_country_mode(mode):
    """Переключает строгость определения страны по имени. Возвращает имя режима.

    Глобальная настройка, а не параметр вызова: предиктор создаётся внутри
    пайплайна, и протаскивать флаг через пять слоёв ради одной галочки —
    лишняя связанность. Неизвестное имя режима игнорируется: молча сменить
    поведение на противоположное хуже, чем не сменить его вовсе.
    """
    global NAME_COUNTRY_MIN_SHARE, NAME_COUNTRY_MIN_RATIO, _country_mode
    if mode not in COUNTRY_MODES:
        return _country_mode
    _country_mode = mode
    NAME_COUNTRY_MIN_SHARE, NAME_COUNTRY_MIN_RATIO = COUNTRY_MODES[mode]
    return _country_mode


def get_country_mode():
    """Текущий режим определения страны по имени."""
    return _country_mode


_COUNTRY_RU = {
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


class MLPredictor:
    def __init__(self, enable_ml=True):
        self.enable_ml = enable_ml
        self.gender_detector = None
        self.nlp = None
        self.nd = None

        # Словарь имён грузим ВСЕГДА: gender_guesser — это таблица, а не
        # нейросеть, и держать её за флагом ИИ незачем. Раньше при выключенном
        # переключателе колонка «Пол» была пуста на всей базе.
        try:
            import gender_guesser.detector as gender
            self.gender_detector = gender.Detector()
        except ImportError:
            logging.warning("gender-guesser module not found.")

        if self.enable_ml:
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

    def predict(self, name, email=None, country_hint=""):
        """Возвращает (пол, страна).

        Страна берётся ИЗ ДОМЕНА, а не из имени. Домен знает её точно
        (web.de — Германия), а распределение имени по странам размазано и
        делает Ивана итальянцем. Предсказание по имени подключается отдельно
        и только там, где домен молчит.
        """
        country = ""
        if email and isinstance(email, str) and "@" in email:
            country = country_from_domain(email.rsplit("@", 1)[1])
        gender = self.predict_gender(name, country_hint or country)
        return (gender, country)

    def predict_gender(self, name, country=""):
        """Пол по имени. При известной стране словарь спрашивается с её учётом."""
        if not self.gender_detector or not isinstance(name, str) or not name.strip():
            return ""
        parts = name.split()
        if not parts:
            return ""
        first = parts[0]
        country_key = _GENDER_COUNTRY.get(country or "")

        raw = self._lookup_gender(first, country_key)
        # Унисекс или неизвестно — пробуем полное имя: иногда фамилия уточняет
        if raw in ("unknown", "andy") and len(parts) > 1:
            raw = self._lookup_gender(name, country_key)

        if raw in ("male", "mostly_male"):
            return "Мужской"
        if raw in ("female", "mostly_female"):
            return "Женский"
        # 'andy' (унисекс) и 'unknown' оставляем пустыми: врать про пол хуже,
        # чем не указать его.
        return ""

    def _lookup_gender(self, text, country_key):
        """Спрашивает словарь, при неудаче — без страны, при любой ошибке — 'unknown'."""
        for attempt in ((text, country_key), (text.capitalize(), country_key),
                        (text, None), (text.capitalize(), None)):
            value, key = attempt
            try:
                result = (self.gender_detector.get_gender(value, key) if key
                          else self.gender_detector.get_gender(value))
            except Exception:
                continue
            if result not in ("unknown", None):
                return result
        return "unknown"

    def country_distribution(self, name):
        """(страна_en, доля лидера, доля второго) по базе имён.

        Отдаётся как есть, без порогов — чтобы вызывающий код (и тесты) видели,
        на чём основано решение. Транслит перебирается: dmitriy / dmitry /
        dmitri — одно имя, но база знает их по-разному.
        """
        if not self.nd or not isinstance(name, str) or not name.strip():
            return ("", 0.0, 0.0)
        parts = name.split()
        if not parts:
            return ("", 0.0, 0.0)

        for variant in translit_variants(parts[0].lower()):
            try:
                res = self.nd.search(variant.title())
            except Exception:
                continue
            first_name = (res or {}).get("first_name") or {}
            data = first_name.get("country") or {}
            valid = {k: v for k, v in data.items() if v}
            if not valid:
                continue
            ranked = sorted(valid.items(), key=lambda kv: -kv[1])
            leader, share = ranked[0]
            second = ranked[1][1] if len(ranked) > 1 else 0.0
            return (leader, float(share), float(second))
        return ("", 0.0, 0.0)

    def predict_country(self, name):
        """Страна по имени. Строгость задаётся порогами наверху файла.

        При нулевых порогах (текущая настройка) берётся страна-лидер
        распределения, какой бы слабой она ни была. Это даёт заполненную
        колонку ценой примерно трети выдуманных значений — цифры и причина
        выбора расписаны у самих порогов.

        Вызывающий код обязан пометить результат как догадку: в пайплайне
        это `country_source = "имя"`. Без такой пометки предсказание в
        выгрузке неотличимо от факта, взятого из домена.
        """
        leader, share, second = self.country_distribution(name)
        if not leader:
            return ""
        # Пороги читаются из глобальных констант модуля НА КАЖДОМ вызове.
        # set_country_mode() присваивает именно их, поэтому переключатель в
        # интерфейсе и прямая правка константы работают одинаково — и то и
        # другое видно предиктору сразу.
        if NAME_COUNTRY_MIN_SHARE and share < NAME_COUNTRY_MIN_SHARE:
            return ""
        if NAME_COUNTRY_MIN_RATIO and second and share < second * NAME_COUNTRY_MIN_RATIO:
            return ""
        return _COUNTRY_RU.get(leader, leader)


if __name__ == '__main__':
    predictor = MLPredictor()
    test_names = ["John", "Sarah", "Alex", "Maria", "Bruce"]
    for n in test_names:
        print(f"{n} -> {predictor.predict(n)}")
