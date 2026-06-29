import re
sub_query = 'site:linkedin.com/in/ "crypto writer" "@gmail.com"'
domain_match = re.search(r'["\']?@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?', sub_query)
domain_filter = domain_match.group(1).lower() if domain_match else None
print("Domain filter:", domain_filter)

emails = {'vipulved@gmail.com', 'test@yahoo.com'}
valid_emails = set()
for e in emails:
    e_domain = e.split('@')[-1].lower()
    if (domain_filter and e_domain == domain_filter):
        valid_emails.add(e)

print("Valid emails:", valid_emails)
