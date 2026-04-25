let currentPublicKey = "";
        let currentPrivateKey = "";

        async function generateKeys() {
            const name = document.getElementById('genName').value;
            const email = document.getElementById('genEmail').value;
            const passphrase = document.getElementById('genPassphrase').value;
            const btn = document.getElementById('btnGenerate');
            const errorDiv = document.getElementById('genError');
            const displayArea = document.getElementById('keyDisplayArea');

            if (!name || !email || !passphrase) {
                showError(errorDiv, "Missing info.");
                return;
            }

            errorDiv.style.display = 'none';
            btn.disabled = true;
            btn.innerText = "Generating...";

            try {
                const { privateKey, publicKey } = await openpgp.generateKey({
                    type: 'rsa', 
                    rsaBits: 2048, 
                    userIDs: [{ name, email }],
                    passphrase
                });

                currentPublicKey = publicKey;
                currentPrivateKey = privateKey;

                displayArea.style.display = 'block';
                document.getElementById('keySelector').value = 'public';
                switchKeyView();

            } catch (err) {
                showError(errorDiv, "Error: " + err.message);
            } finally {
                btn.disabled = false;
                btn.innerText = "Generate Keys";
            }
        }

        function switchKeyView() {
            const selection = document.getElementById('keySelector').value;
            document.getElementById('generatedKeyBox').value = (selection === 'public') ? currentPublicKey : currentPrivateKey;
            const copyBtn = document.getElementById('copyBtn');
            copyBtn.innerText = "📋 Copy to clipboard";
            copyBtn.classList.remove('success');
        }

        async function copyKeyToClipboard() {
            const keyBox = document.getElementById('generatedKeyBox');
            const copyBtn = document.getElementById('copyBtn');
            
            try {
                await navigator.clipboard.writeText(keyBox.value);
                
                const originalText = copyBtn.innerText;
                copyBtn.innerText = "Copied to clipboard! ✅";
                copyBtn.classList.add('success');
                
                setTimeout(() => {
                    copyBtn.innerText = originalText;
                    copyBtn.classList.remove('success');
                }, 2000);
                
            } catch (err) {
                console.error("Copy error:", err);
            }
        }

        async function encryptMsg() {
            const pubKeyArmored = document.getElementById('encPubKey').value;
            const messageText = document.getElementById('encMessage').value;
            const resultDiv = document.getElementById('encResult');

            try {
                const publicKey = await openpgp.readKey({ armoredKey: pubKeyArmored });
                const encrypted = await openpgp.encrypt({
                    message: await openpgp.createMessage({ text: messageText }),
                    encryptionKeys: publicKey
                });
                showResult(resultDiv, encrypted);
            } catch (err) {
                showResult(resultDiv, "Error: " + err.message, true);
            }
        }

        async function decryptMsg() {
            const privKeyArmored = document.getElementById('decPrivKey').value;
            const passphrase = document.getElementById('decPassphrase').value;
            const encryptedMessage = document.getElementById('decMessage').value;
            const resultDiv = document.getElementById('decResult');

            try {
                const privateKey = await openpgp.decryptKey({
                    privateKey: await openpgp.readPrivateKey({ armoredKey: privKeyArmored }),
                    passphrase
                });
                const message = await openpgp.readMessage({ armoredMessage: encryptedMessage });
                const { data: decrypted } = await openpgp.decrypt({ message, decryptionKeys: privateKey });
                showResult(resultDiv, "Decrypted Message:\n\n" + decrypted);
            } catch (err) {
                showResult(resultDiv, "Decryption error!: " + err.message, true);
            }
        }

        function showResult(element, text, isError = false) {
            element.innerText = text;
            element.style.display = 'block';
            element.style.borderColor = isError ? "#e74c3c" : "#1abc9c";
            element.style.backgroundColor = isError ? "#fdedec" : "#e8f8f5";
        }

        function showError(element, text) {
            element.innerText = text;
            element.style.display = 'block';
        }
