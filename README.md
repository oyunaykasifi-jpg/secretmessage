# 🔒 SecretMessage

**SecretMessage** is a minimal, offline-friendly, client-side encryption tool for private text and optional photos.

It encrypts your content directly in the browser using **AES-256-GCM** and derives keys with **PBKDF2 (SHA-256)**.  
Your original content is processed on your device. It is **not uploaded to a server**, **not stored**, and **no account is required**.

---

## ✨ What It Does

- Encrypts **text** and an optional **photo** into a single encrypted block
- Works directly in the browser
- Supports offline-friendly usage with service worker caching
- Can be shared through WhatsApp, Telegram, Email, Instagram DM, Signal, Discord, and similar channels
- Lets users copy the encrypted block or download it as a file
- Includes a simple built-in key generator
- Does not use ads, tracking, or analytics

---

## 🔐 How It Works

1. Write your message
2. Optionally add a photo
3. Enter a key or generate one
4. Create the encrypted block
5. Share the encrypted block with the recipient
6. The recipient decrypts it using the same key

This model helps reduce plain-text exposure by encrypting content **before** it is sent through a messaging app, email, or direct message platform.

---

## 🧠 Security Details

- **Encryption:** AES-256-GCM
- **Key Derivation:** PBKDF2 (SHA-256)
- **Iterations:** 200,000
- **Salt Length:** 16 bytes
- **IV Length:** 12 bytes
- **Integrity Protection:** AES-GCM authentication
- **Payload Format:** `GSM1.<salt>.<iv>.<ct>` (Base64URL)

SecretMessage is designed so that encryption and decryption happen on the client side, inside the user's browser.

---

## 🛡️ Privacy Model

SecretMessage is built with a privacy-first model:

- No server-side message storage
- No user accounts
- No ad trackers
- No analytics
- No content logging
- No plaintext upload flow

Your encrypted block is something **you** choose to copy, save, or share.  
The project itself does not keep a copy of your readable content.

---

💡 Why Use SecretMessage?

SecretMessage is useful when a communication channel is convenient, but sending plain text would be a bad idea.

Examples include:

passwords and temporary access notes
sensitive relationship messages
client credentials
private photos
internal notes
recovery codes
information you do not want to appear in plain text in a copied thread, email chain, screenshot of the encrypted block, or accidental forward

It does not claim perfect security.
It adds a meaningful extra layer by making content unreadable before it travels through everyday platforms.

---

⚠️ Important Limitations

SecretMessage improves privacy, but it does not solve every problem.

Please keep these limits in mind:

If someone decrypts the message and then takes a screenshot, the decrypted content can still be captured
If the key is weak, security is weaker
If the encrypted block and the key are exposed together, privacy is reduced
If the device is compromised, local privacy may also be compromised
This tool does not replace good operational security habits

Best practice:
Do not share the key in the same place as the encrypted block if possible.

----

💻 Offline and Local Use

SecretMessage is designed to be offline-friendly.

After loading the app, core files can remain available through browser caching and service worker support.
The project files can also be saved to a computer and opened locally in a browser for personal offline use.

This makes it useful as a lightweight privacy tool even outside a constant internet connection.

---

☕ Support

If you want to support the project:

Bitcoin (SegWit):
bc1qw8g5fa82nj9eu6akr9wxx4gh4c5fxekm8dykgy

---

📂 Repository

GitHub repository:

https://github.com/oyunaykasifi-jpg/secretmessage

---

## 🌍 Supported Language Plan

The project is being prepared with a multilingual structure.

Planned languages:

- English
- Türkçe
- Español
- Português
- Français
- Deutsch
- العربية

The default language of the main project is **English**.

---

📜 License


MIT, Open-source license.

