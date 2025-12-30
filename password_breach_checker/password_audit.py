import hashlib
import requests
import re

# Hash password
def hash_password(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    return sha1[:5], sha1[5:]

# Get breach data
def get_pwned_data(prefix):
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    r = requests.get(url)
    if r.status_code != 200:
        raise RuntimeError("API error")
    return r.text

# Check breaches
def check_breach(password):
    prefix, suffix = hash_password(password)
    data = get_pwned_data(prefix)

    for line in data.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0

# Score strength
def strength_score(password):
    score = 0
    if len(password) >= 12: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*()_+=-]", password): score += 1
    return score

def main():
    password = input("Enter password: ")
    breaches = check_breach(password)
    score = strength_score(password)

    print("\nResults")
    if breaches:
        print(f"Found in breaches: {breaches}")
    else:
        print("Not found in breaches")

    print(f"Strength: {score}/5")

if __name__ == "__main__":
    main()
