# Online PGP Tool 🔒

A client-side, browser-based OpenPGP tool. This application allows you to securely generate keys, encrypt/decrypt messages, and manage your PGP identity directly in your web browser without sending sensitive data to a server.

It is built using standard web technologies (HTML, CSS, JS) and relies on the official [OpenPGP.js](https://openpgpjs.org/) library.

## Features

- **Generate Key Pairs:** Create RSA (up to 4096-bit) or ECC (Ed25519/Curve25519) key pairs.
- **Encrypt & Decrypt:** Securely exchange messages using public-key cryptography.
- **Sign & Verify:** Digitally sign messages to prove authenticity and verify others' signatures.
- **Key Management:** View fingerprint details, extract revocation certificates, and add subkeys (e.g., dedicated encryption subkeys).
- **Symmetric Encryption:** Encrypt and decrypt messages using just a password, without needing PGP keys.
- **Dark/Light Mode:** Toggle between themes for better readability.

## Security

- **Client-Side Only:** Your private keys, passwords, and messages are processed locally in your browser. Nothing is ever transmitted to a backend server.
- **Auto-Cleanup:** The tool automatically clears sensitive data (like generated keys and passwords) from memory after 10 minutes of inactivity to prevent accidental leaks on shared devices.
- **No Persistent Storage:** Sensitive data is never saved to `localStorage` or `sessionStorage`.

## How to Use

### 1. Generating Keys
Navigate to the **Encrypt / Decrypt** tab. Fill in your Name, Password, and select an Algorithm. Click "Generate keys". Your keys will be generated and temporarily stored in your browser session. 
*Note: Make sure to copy and securely back up your private key and revocation certificate!*

### 2. Encrypting a Message
Get the recipient's Public Key. Paste it into the "Encrypt Message" section, type your secret message, and click Encrypt. You can then copy the resulting PGP message and send it to them via any insecure channel.

### 3. Decrypting a Message
Paste your Private Key, enter its password, and paste the encrypted message. Click Decrypt to read the original text.

### 4. Symmetric Encryption (Password Only)
If you don't want to manage keys, use the **Encrypt with password** tab. Enter a strong passphrase and your message. The recipient will need the exact same passphrase to decrypt it.

## Running Locally

Because this is a static web application, you don't need a complex build setup.

1. Clone the repository:
   ```bash
   git clone https://github.com/Aliyaman/online-pgp-tool.git
   ```
2. Navigate to the project folder:
   ```bash
   cd online-pgp-tool
   ```
3. Open `index.html` in your favorite web browser. 

*(Optional) You can also use a simple local server if you prefer:*
```bash
npx serve .
# or
python3 -m http.server 8000
```

## License

This project is open-source. Please see the `LICENSE` file for more details.
