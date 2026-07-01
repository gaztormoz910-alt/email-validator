import hashlib
import json
import urllib.request
import urllib.error

class OSINTOperator:
    def __init__(self):
        pass

    def get_name_from_gravatar(self, email):
        """
        Queries Gravatar API for public profile information using the MD5 hash of the email.
        This is a safe, free, key-less OSINT technique.
        """
        if not email:
            return None
            
        # Gravatar requires MD5 hash of lowercased email
        email_hash = hashlib.md5(email.strip().lower().encode('utf-8')).hexdigest()
        url = f"https://en.gravatar.com/{email_hash}.json"
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5.0) as response:
                data = json.loads(response.read().decode('utf-8'))
                if 'entry' in data and len(data['entry']) > 0:
                    profile = data['entry'][0]
                    # Check for displayName or name components
                    if 'name' in profile and 'formatted' in profile['name']:
                        return profile['name']['formatted']
                    elif 'displayName' in profile:
                        return profile['displayName']
        except urllib.error.HTTPError as e:
            # 404 means no profile found, which is normal
            pass
        except Exception:
            # Ignore network or JSON errors
            pass
            
        return None

    def search_name(self, email):
        """
        Orchestrates various OSINT methods to find a name for the email.
        Currently uses Gravatar API.
        """
        # Method 1: Gravatar
        name = self.get_name_from_gravatar(email)
        if name:
            return name
            
        # We can add Holehe, HaveIBeenPwned API (if paid), etc. here in the future
        
        return None

if __name__ == '__main__':
    # Test with known gravatar emails
    operator = OSINTOperator()
    print("Testing OSINT Operator...")
    test_email = "beau@automattic.com" # Public gravatar test profile
    print(f"{test_email} -> {operator.search_name(test_email)}")
