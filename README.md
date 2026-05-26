# MRB Secure File Tool v2.1 🔒

A high-security file encryption utility featuring **Triple-Layer AES-256-GCM** encryption, hardened with **Scrypt** and **HKDF** key derivation.

## 🚀 Features
- **Triple Encryption:** Every file is encrypted three times sequentially with three different derived keys.
- **AEAD Security:** Uses AES-256-GCM to ensure both confidentiality and integrity.
- **Quantum-Resistant KDF:** Uses Scrypt (N=2^20) to protect against brute-force attacks.
- **Custom Key Encoding:** Enhanced base64-based key format for better readability and robustness.
- **Batch Processing:** Encrypt or decrypt entire directories with a visual progress bar.
- **Integrity Protection:** Outer HMAC-SHA3-256 tag to detect any tampering before decryption.

## 🛠 Installation

1. Clone the repository:
bash
   git clone https://github.com/AsTheySayMehrab/MRB-Secure-Tool.git
   cd MRB-Secure-Tool
   
2. Install dependencies:
       pip install -r requirements.txt
   
Usage
python secure_file_tool.py

### Workflow:
1. **Create Key:** Generates a new `.key` file. Keep this safe!
2. **Load Key:** Load an existing key into the session.
3. **Encrypt:** Select a file or folder to encrypt. Files will be saved with `.MRB` extension.
4. **Decrypt:** Select `.MRB` files to restore the original data.

## 🛡 Security Architecture
- **Encryption:** AES-GCM (Authenticated Encryption with Associated Data).
- **KDF Layer 1:** Scrypt (Memory-hard key stretching).
- **KDF Layer 2:** HKDF (HMAC-based Extract-and-Expand) for sub-key derivation.
- **Magic Header:** `MRB\x02` identifier.
- **IV Tweaking:** XOR-based IV tweaking for additional layer randomization.

## 👤 Author
- **Name:** Mehrab
- **GitHub:** [@AsTheySayMehrab](https://github.com/AsTheySayMehrab)

## ⚖ License
This project is licensed under the MIT License.

