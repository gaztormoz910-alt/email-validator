import re

query = '"@gmail.com" "New Jersey" "Technician"'
match = re.search(r'["\']?@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?', query)
domain_filter = match.group(1).lower() if match else None
print(f"Domain filter: {domain_filter}")

emails = {'john@gmail.com', 'admin@gooddns.net', 'test@rtcs.eu', 'bob@gmail.com', 'rts@rtcs.eu'}
filtered = {e for e in emails if e.endswith('@' + domain_filter)} if domain_filter else emails
print(f"Before: {emails}")
print(f"After:  {filtered}")
