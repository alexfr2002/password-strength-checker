import tkinter as tk 
from tkinter import messagebox
import re
import hashlib
import requests
import random
import string

def check_password_strength(password):
    length_error = len(password) < 8
    lowercase_error = re.search(r"[a-z]", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    digit_error = re.search(r"\d", password) is None
    special_char_error = re.search(r"[!@#$%&*]", password) is None
    
    errors = {
        "Minimum 8 characters": length_error,
        "At least 1 lowercase letter": lowercase_error,
        "At least 1 uppercase letter": uppercase_error,
        "At least 1 digit": digit_error,
        "At least 1 special character (!@#$%&*)": special_char_error
        }
    
    if not any(errors.values()):
        return "Strong password", errors
    else:
        return "Weak password", errors
    
def check_pwned_password(password):
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        url= f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            response = requests.get(url)
            if response.status_code != 200:
                return "API ERROR"
        except:
            return "UNABLE TO REACH HIBP API"
        
        hashes = (line.split(":")for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return f"Found in data breaches {count} times!"
            
        return "Not found in known breaches"
        
def generate_password(length=12):
        characters = string.ascii_letters + string.digits + "!@#$%&*"
        return ''.join(random.choice(characters) for _ in range(length))
    
def run_checker():
        password = entry.get()
        
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password.")
            return
        
        strength_result, issues = check_password_strength(password)
        strength_text.set(strength_result)
        
        issues_text = "\n".join(f" - {k}" for k, v in issues.items() if v)
        issues_output.set(issues_text if issues_text else "All requirements met.")

        breach_result = check_pwned_password(password)
        breach_text.set(breach_result)

def use_generated():
        password = generate_password()
        entry.delete(0, tk.END)
        entry.insert(0, password)

app = tk.Tk()
app.title("Password Strength Checker")
app.geometry("400x400")
app.resizable(False, False)

tk.Label(app, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
entry_frame = tk.Frame(app)
entry_frame.pack(pady=5)

entry = tk.Entry(entry_frame, width=25, show='*', font=("Arial", 12))
entry.pack(side=tk.LEFT)


def toggle_password():
    if entry.cget('show') == '':
        entry.config(show='*')
        toggle_button.config(text='Show')
    else:
        entry.config(show='')
        toggle_button.config(text='Hide')

toggle_button = tk.Button(entry_frame, text='Show', command=toggle_password, width=5)
toggle_button.pack(side=tk.LEFT, padx=5)

tk.Button(app, text="Check Password", command=run_checker, bg="#4CAF50", fg="white").pack(pady=10)
tk.Button(app, text="Generate Strong Password", command=use_generated).pack()

strength_text = tk.StringVar()
issues_output = tk.StringVar()
breach_text = tk.StringVar()

tk.Label(app, textvariable=strength_text, font=("Arial", 12, "bold")).pack(pady=5)
tk.Label(app, textvariable=issues_output, wraplength=350, justify="left").pack(pady=5)
tk.Label(app, textvariable=breach_text, fg="red").pack(pady=5)

app.mainloop() 
        
        