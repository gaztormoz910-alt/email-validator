import re
import os
import wordsegment
import threading
from .osint import OSINTOperator

_nd = None
_nd_lock = threading.Lock()

def get_name_dataset():
    global _nd
    if _nd is None:
        with _nd_lock:
            if _nd is None:
                try:
                    from names_dataset import NameDataset
                    _nd = NameDataset()
                except ImportError:
                    _nd = None
    return _nd

class NameExtractor:
    def __init__(self, enable_osint=False):
        # Load wordsegment corpus into memory (only happens once per process)
        wordsegment.load()
        self.enable_osint = enable_osint
        self.osint_operator = OSINTOperator() if enable_osint else None
        
        # Load the 138 million names dataset
        self.nd = get_name_dataset()
        
        # Load English words dictionary
        self.english_words = set()
        try:
            dict_path = os.path.join(os.path.dirname(__file__), "..", "english_words.txt")
            with open(dict_path, "r", encoding="utf-8") as f:
                self.english_words = {line.strip().lower() for line in f if line.strip()}
        except Exception:
            pass
            
        # Exception list for English words that are extremely common real names
        self.name_exceptions = {
            "mark", "will", "may", "april", "june", "august", "hope", "faith", "joy", 
            "grace", "rose", "lily", "christian", "miles", "chase", "grant", "hunter", 
            "mason", "carter", "parker", "peter", "john", "paul", "george", "adam", 
            "david", "scott", "frank", "jack", "harry", "nick", "chris", "alex", "sam", 
            "max", "robin", "brook", "dawn", "eve", "glen", "jean", "kelly", "page",
            "penny", "ray", "victor", "art", "cliff", "crystal", "earl", "guy", "jasper",
            "james", "robert", "mary", "patricia", "michael", "linda", "william",
            "elizabeth", "barbara", "richard", "susan", "joseph", "jessica", "sarah",
            "thomas", "karen", "charles", "lisa", "matthew", "betty", "anthony",
            "donald", "sandra", "ashley", "dorothy", "steven", "kimberly", "andrew",
            "emily", "joshua", "donna", "kenneth", "michelle", "kevin", "carol", "brian",
            "amanda", "melissa", "edward", "deborah"
        }

    def _is_generic_word(self, word):
        """Returns True if the word is a generic dictionary word and not a common name."""
        w = word.lower()
        bad_roles = {
            "admin", "info", "support", "sales", "contact", "help", "office", "marketing", 
            "webmaster", "postmaster", "hello", "noreply", "no-reply", "news", "update",
            "service", "team", "billing", "press", "media", "jobs", "careers"
        }
        if w in bad_roles:
            return True
            
        # Check against dictionary, ignoring our whitelist of names that are also dictionary words
        if w in self.english_words and w not in self.name_exceptions:
            return True
            
        return False

    def _has_business_words(self, words_list):
        """Returns True if any word in the list strongly indicates a business/organization."""
        business_keywords = {
            "properties", "photos", "college", "university", "school", "academy", 
            "company", "inc", "llc", "group", "services", "solutions", "holdings", 
            "management", "studios", "productions", "designs", "realty", "realestate", 
            "consulting", "logistics", "auto", "motors", "clinic", "dental", "medical", 
            "hospital", "church", "bible", "ministries", "plenty", "daily", "news", 
            "update", "press", "media", "agency", "tech", "technologies", "software",
            "hardware", "store", "shop", "boutique", "market", "mart", "farm", "farms",
            "stables", "foundation", "trust", "charity", "club", "association", "society",
            "institute", "center", "centre", "network", "system", "systems", "global",
            "international", "national", "regional", "local", "county", "city", "town",
            "state", "republic", "union", "bank", "credit", "insurance", "capital",
            "investment", "investments", "wealth", "finance", "financial", "accounting",
            "tax", "legal", "law", "attorney", "attorneys", "lawyers", "firm", "firms",
            "partners", "associates", "brothers", "sons", "daughters", "family"
        }
        for w in words_list:
            if w.lower() in business_keywords:
                return True
        return False

    def _is_valid_name(self, word):
        """Checks if a word is a legitimate human name using the 138M dataset."""
        if not self.nd or not word:
            return False
            
        word_clean = word.title().strip()
        if len(word_clean) < 2:
            return False
            
        res = self.nd.search(word_clean)
        # res returns a dict with 'first_name' and 'last_name' matches.
        # If the word exists in either category as a valid name somewhere in the world, we accept it.
        if res and (res.get('first_name') or res.get('last_name')):
            return True
            
        return False

    def extract_name(self, email):
        """
        Extracts and formats a potential name from an email address using Phase 1 & 2 heuristics.
        Returns the formatted name or None if extraction fails.
        """
        if not email or '@' not in email:
            return None
            
        username = email.split('@')[0].strip()
        username_clean = re.sub(r'\d+', '', username)
        
        if len(username_clean) < 3:
            return self._fallback_osint(email)

        # ----------------------------------------------------
        # Phase 1: Check for common separators (john.doe)
        # ----------------------------------------------------
        if any(sep in username_clean for sep in ['.', '_', '-']):
            parts = re.split(r'[._-]', username_clean)
            clean_parts = [part.title() for part in parts if part.strip()]
            
            if clean_parts:
                if len(clean_parts) > 3:
                    return self._fallback_osint(email)
                    
                if self._has_business_words(clean_parts):
                    return self._fallback_osint(email)
                    
                first_part = clean_parts[0]
                if self._is_generic_word(first_part):
                    return self._fallback_osint(email)
                    
                if self.nd and not self._is_valid_name(first_part):
                    return self._fallback_osint(email)
                    
                return " ".join(clean_parts)
                
        # ----------------------------------------------------
        # Phase 1.5: Check for CamelCase (JohnDoe)
        # ----------------------------------------------------
        camel_case_parts = re.findall(r'[A-Z][a-z]+', username_clean)
        if len(camel_case_parts) >= 2 and ''.join(camel_case_parts) == username_clean:
            if len(camel_case_parts) > 3:
                return self._fallback_osint(email)
                
            if self._has_business_words(camel_case_parts):
                return self._fallback_osint(email)
                
            first_part = camel_case_parts[0]
            if self._is_generic_word(first_part):
                return self._fallback_osint(email)
                
            if self.nd and not self._is_valid_name(first_part):
                return self._fallback_osint(email)
                
            return " ".join(camel_case_parts)
            
        # ----------------------------------------------------
        # Phase 2: Word segmentation for merged names (robertanderson)
        # ----------------------------------------------------
        segmented = wordsegment.segment(username_clean.lower())
        
        if segmented:
            # Reject if it segments into more than 3 words (highly likely a phrase or business name)
            if len(segmented) > 3:
                return self._fallback_osint(email)
                
            if self._has_business_words(segmented):
                return self._fallback_osint(email)
                
            first_word = segmented[0]
            
            # Reject if the first word is a generic dictionary word (e.g. "the", "lets", "porn", "uk")
            if self._is_generic_word(first_word):
                return self._fallback_osint(email)
                
            if self.nd and not self._is_valid_name(first_word):
                return self._fallback_osint(email)
            
            extracted = " ".join(part.title() for part in segmented)
            return extracted
            
        return self._fallback_osint(email)
        
    def _fallback_osint(self, email):
        if self.enable_osint and self.osint_operator:
            name = self.osint_operator.search_name(email)
            if name:
                return name
        return ""
