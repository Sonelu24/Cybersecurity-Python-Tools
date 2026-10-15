# 🔐 Password Breach Checker

A Python tool that checks whether a password has appeared in **known data breaches**, using the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) Pwned Passwords database. Your password is never sent anywhere. It also rates the password's strength.

## ✨ Features
- Checks the password against more than 800 million breached passwords
- **Privacy-preserving** thanks to k-anonymity (explained below)
- Input is hidden while you type (`getpass`)
- Strength estimate based on entropy
- Pure Python standard library, nothing to install

## 🛡️ How k-anonymity Works
1. The password is hashed locally with SHA-1, e.g. `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
2. Only the **first 5 characters** (`5BAA6`) are sent to the API
3. The API sends back every hash suffix that starts with that prefix (hundreds of them)
4. The script looks for a match **on your computer**

The server never sees your password or its full hash. Padding is also turned on, so the size of the response doesn't give anything away either.

## 🚀 Usage
Requires **Python 3.9+** and an internet connection.

```bash
python breach_checker.py
```

## 📊 Example Output
![Password Breach Checker demo](demo.png)

```
=== Password Breach Checker (k-anonymity, your password is never sent) ===
Enter password to check (input hidden):

Length            : 8 characters
Estimated entropy : 26.6 bits (WEAK)

[!!] PWNED: this password was seen 70,606,130 times in data breaches.
     Do NOT use it. Pick a new, unique password (a password manager helps).
```
```
Length            : 11 characters
Estimated entropy : 72.1 bits (STRONG)

[+] Good news: not found in any known breach.
```

## 🧠 What I Learned
- Cryptographic hashing and why SHA-1 is fine here (it's used for lookup, not for storing passwords)
- Privacy-preserving API design with k-anonymity
- Handling secrets carefully: hidden input, no logging, nothing written to disk

## 🛣️ Future Improvements
- Check many passwords at once from a file (for auditing)
- Pattern detection (dictionary words, keyboard walks like `qwerty`)
- Suggest strong passphrases
