let currentPublicKey = "";
        let currentPrivateKey = "";
        let sensitiveDataTimer = null;

        function clearInputValue(id) {
            const el = document.getElementById(id);
            if (el && typeof el.value === 'string') {
                el.value = '';
            }
        }

        function clearResultPanel(id) {
            const el = document.getElementById(id);
            if (!el) {
                return;
            }
            el.innerText = '';
            el.style.display = 'none';
            el.style.borderColor = '';
            el.style.backgroundColor = '';
        }

        function clearSensitiveInputs() {
            clearInputValue('genName');
            clearInputValue('genEmail');
            clearInputValue('genPassphrase');
            clearInputValue('encPubKey');
            clearInputValue('encMessage');
            clearInputValue('decPassphrase');
            clearInputValue('decPrivKey');
            clearInputValue('decMessage');
            clearResultPanel('encResult');
            clearResultPanel('decResult');
            const encCopyBtn = document.getElementById('encCopyBtn');
            if (encCopyBtn) {
                encCopyBtn.style.display = 'none';
                encCopyBtn.innerText = '📋 Copy encrypted message';
                encCopyBtn.classList.remove('success');
            }
        }

        function clearGeneratedKeysFromMemory() {
            currentPublicKey = "";
            currentPrivateKey = "";
            const selector = document.getElementById('keySelector');
            const generatedKeyBox = document.getElementById('generatedKeyBox');
            if (generatedKeyBox) {
                generatedKeyBox.value = '';
            }
            if (selector) {
                selector.value = 'public';
            }
        }

        function scheduleSensitiveDataCleanup() {
            if (sensitiveDataTimer) {
                clearTimeout(sensitiveDataTimer);
            }
            sensitiveDataTimer = setTimeout(() => {
                clearSensitiveInputs();
                clearGeneratedKeysFromMemory();
            }, 10 * 60 * 1000);
        }

        function clearSensitiveDataNow(buttonId = null) {
            clearSensitiveInputs();
            clearGeneratedKeysFromMemory();
            if (buttonId) {
                const button = document.getElementById(buttonId);
                if (button) {
                    const originalText = button.innerText;
                    button.innerText = 'Cleared! ✅';
                    button.classList.add('success');
                    setTimeout(() => {
                        button.innerText = originalText;
                        button.classList.remove('success');
                    }, 1500);
                }
            }
        }

        function applyTheme(theme) {
            const isDark = theme === 'dark';
            document.body.classList.toggle('dark-mode', isDark);

            const themeBtn = document.getElementById('themeToggleBtn');
            if (themeBtn) {
                themeBtn.innerText = isDark ? '☀️' : '🌙';
            }
        }

        function initializeTheme() {
            const savedTheme = localStorage.getItem('theme');
            const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            const initialTheme = savedTheme || (prefersDark ? 'dark' : 'light');
            applyTheme(initialTheme);
        }

        function toggleTheme() {
            const isDark = document.body.classList.contains('dark-mode');
            const nextTheme = isDark ? 'light' : 'dark';
            applyTheme(nextTheme);
            localStorage.setItem('theme', nextTheme);
        }

        window.addEventListener('DOMContentLoaded', initializeTheme);

        async function generateKeys() {
            const name = document.getElementById('genName').value;
            const email = document.getElementById('genEmail').value;
            const passphrase = document.getElementById('genPassphrase').value;
            const rsaBits = Number.parseInt(document.getElementById('genRsaBits').value, 10) || 2048;
            const btn = document.getElementById('btnGenerate');
            const errorDiv = document.getElementById('genError');
            const displayArea = document.getElementById('keyDisplayArea');

            if (!name) {
                showError(errorDiv, "Name is required.");
                return;
            }
            if (!passphrase) {
                showError(errorDiv, "Password is required.");
                return;
            }

            errorDiv.style.display = 'none';
            btn.disabled = true;
            btn.innerText = "Generating...";

            try {
                const userID = { name };
                if (email) {
                    userID.email = email;
                }

                const keyOptions = {
                    type: 'rsa', 
                    rsaBits,
                    userIDs: [userID]
                };

                keyOptions.passphrase = passphrase;

                const { privateKey, publicKey } = await openpgp.generateKey(keyOptions);

                currentPublicKey = publicKey;
                currentPrivateKey = privateKey;
                document.getElementById('decPrivKey').value = privateKey;

                displayArea.style.display = 'block';
                document.getElementById('keySelector').value = 'public';
                switchKeyView();
                scheduleSensitiveDataCleanup();

            } catch (err) {
                showError(errorDiv, "Error: " + err.message);
            } finally {
                clearInputValue('genPassphrase');
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
            const copyBtn = document.getElementById('encCopyBtn');

            try {
                const publicKey = await openpgp.readKey({ armoredKey: pubKeyArmored });
                const encrypted = await openpgp.encrypt({
                    message: await openpgp.createMessage({ text: messageText }),
                    encryptionKeys: publicKey
                });
                showResult(resultDiv, encrypted);
                copyBtn.style.display = 'inline-block';
                copyBtn.innerText = "📋 Copy encrypted message";
                copyBtn.classList.remove('success');
            } catch (err) {
                showResult(resultDiv, "Error: " + err.message, true);
                copyBtn.style.display = 'none';
            }
        }

        async function copyEncryptedToClipboard() {
            const encryptedText = document.getElementById('encResult').innerText;
            const copyBtn = document.getElementById('encCopyBtn');

            if (!encryptedText || encryptedText.startsWith("Error:")) {
                return;
            }

            try {
                await navigator.clipboard.writeText(encryptedText);

                const originalText = copyBtn.innerText;
                copyBtn.innerText = "Copied to clipboard! ✅";
                copyBtn.classList.add('success');

                setTimeout(() => {
                    copyBtn.innerText = originalText;
                    copyBtn.classList.remove('success');
                }, 2000);
            } catch (err) {
                console.error("Copy encrypted message error:", err);
            }
        }

        function togglePasswordVisibility(inputId, buttonId) {
            const input = document.getElementById(inputId);
            const button = document.getElementById(buttonId);

            if (!input || !button) {
                return;
            }

            const isHidden = input.type === 'password';
            input.type = isHidden ? 'text' : 'password';
            button.innerText = isHidden ? 'Hide' : 'Show';
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
                scheduleSensitiveDataCleanup();
            } catch (err) {
                showResult(resultDiv, "Decryption error!: " + err.message, true);
            } finally {
                clearInputValue('decPassphrase');
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

        window.addEventListener('pagehide', () => {
            clearSensitiveInputs();
            clearGeneratedKeysFromMemory();
        });
