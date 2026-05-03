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
            clearInputValue('signPrivKey');
            clearInputValue('signPassphrase');
            clearInputValue('signPlainText');
            clearInputValue('verifyPubKey');
            clearInputValue('verifySignedCleartext');
            clearInputValue('symEncPass');
            clearInputValue('symPlain');
            clearInputValue('symCipher');
            clearInputValue('symDecPass');
            const genErr = document.getElementById('genError');
            if (genErr) {
                genErr.innerText = '';
                genErr.style.display = 'none';
            }
            clearResultPanel('encResult');
            clearResultPanel('decResult');
            clearResultPanel('signResult');
            clearResultPanel('verifyResult');
            clearResultPanel('symEncResult');
            clearResultPanel('symDecResult');
            resetCopyOutcomeButton('encCopyBtn', '📋 Copy encrypted message');
            resetCopyOutcomeButton('signCopyBtn', '📋 Copy signed message');
            resetCopyOutcomeButton('symEncCopyBtn', '📋 Copy ciphertext');
            resetCopyOutcomeButton('symDecCopyBtn', '📋 Copy decrypted text');
        }

        function resetCopyOutcomeButton(id, defaultLabel) {
            const btn = document.getElementById(id);
            if (!btn) {
                return;
            }
            btn.style.display = 'none';
            btn.innerText = defaultLabel;
            btn.classList.remove('success');
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

        const MAIN_TAB_IDS = ['enc-dec', 'sign-verify', 'symmetric'];
        const MAIN_TAB_PANEL_MAP = {
            'enc-dec': 'panel-enc-dec',
            'sign-verify': 'panel-sign-verify',
            'symmetric': 'panel-symmetric'
        };

        function switchMainTab(tabId) {
            if (!MAIN_TAB_IDS.includes(tabId)) {
                return;
            }
            MAIN_TAB_IDS.forEach((tid) => {
                const panel = document.getElementById(MAIN_TAB_PANEL_MAP[tid]);
                const btn = document.getElementById('tab-' + tid);
                const active = tid === tabId;
                if (panel) {
                    panel.classList.toggle('is-active', active);
                    panel.toggleAttribute('hidden', !active);
                }
                if (btn) {
                    btn.setAttribute('aria-selected', String(active));
                }
            });
        }

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

        async function copySignOutputToClipboard() {
            const text = document.getElementById('signResult').innerText;
            const copyBtn = document.getElementById('signCopyBtn');
            if (!text || text.startsWith('Error:')) {
                return;
            }
            try {
                await navigator.clipboard.writeText(text);
                const originalText = copyBtn.innerText;
                copyBtn.innerText = 'Copied to clipboard! ✅';
                copyBtn.classList.add('success');
                setTimeout(() => {
                    copyBtn.innerText = originalText;
                    copyBtn.classList.remove('success');
                }, 2000);
            } catch (err) {
                console.error('Copy signed message error:', err);
            }
        }

        async function copySymEncToClipboard() {
            const text = document.getElementById('symEncResult').innerText;
            const copyBtn = document.getElementById('symEncCopyBtn');
            if (!text || text.startsWith('Error:')) {
                return;
            }
            try {
                await navigator.clipboard.writeText(text);
                const originalText = copyBtn.innerText;
                copyBtn.innerText = 'Copied to clipboard! ✅';
                copyBtn.classList.add('success');
                setTimeout(() => {
                    copyBtn.innerText = originalText;
                    copyBtn.classList.remove('success');
                }, 2000);
            } catch (err) {
                console.error('Copy symmetric ciphertext error:', err);
            }
        }

        async function copySymDecToClipboard() {
            const raw = document.getElementById('symDecResult').innerText;
            const copyBtn = document.getElementById('symDecCopyBtn');
            if (!raw || raw.startsWith('Error:')) {
                return;
            }
            const text = raw.replace(/^Decrypted message:\s*\n+/i, '').trimStart();
            try {
                await navigator.clipboard.writeText(text);
                const originalText = copyBtn.innerText;
                copyBtn.innerText = 'Copied to clipboard! ✅';
                copyBtn.classList.add('success');
                setTimeout(() => {
                    copyBtn.innerText = originalText;
                    copyBtn.classList.remove('success');
                }, 2000);
            } catch (err) {
                console.error('Copy decrypted symmetric error:', err);
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

        async function signMessage() {
            const armoredPriv = document.getElementById('signPrivKey').value;
            const passphrase = document.getElementById('signPassphrase').value;
            const plain = document.getElementById('signPlainText').value;
            const resultDiv = document.getElementById('signResult');
            const copyBtn = document.getElementById('signCopyBtn');

            try {
                const privateKey = await openpgp.decryptKey({
                    privateKey: await openpgp.readPrivateKey({ armoredKey: armoredPriv }),
                    passphrase
                });
                const cleartext = await openpgp.createCleartextMessage({ text: plain });
                const signedArmored = await openpgp.sign({
                    message: cleartext,
                    signingKeys: privateKey,
                    format: 'armored'
                });
                showResult(resultDiv, signedArmored);
                copyBtn.style.display = 'inline-block';
                copyBtn.innerText = '📋 Copy signed message';
                copyBtn.classList.remove('success');
                scheduleSensitiveDataCleanup();
            } catch (err) {
                showResult(resultDiv, 'Error: ' + err.message, true);
                copyBtn.style.display = 'none';
            } finally {
                clearInputValue('signPassphrase');
            }
        }

        async function verifySignedMessage() {
            const pubArmor = document.getElementById('verifyPubKey').value;
            const signedArmor = document.getElementById('verifySignedCleartext').value;
            const resultDiv = document.getElementById('verifyResult');

            try {
                const publicKey = await openpgp.readKey({ armoredKey: pubArmor });
                const message = await openpgp.readCleartextMessage({ cleartextMessage: signedArmor });
                const verified = await openpgp.verify({
                    message,
                    verificationKeys: publicKey
                });
                if (!verified.signatures.length) {
                    throw new Error('No signatures found in message.');
                }
                await Promise.all(verified.signatures.map((sig) => sig.verified));
                showResult(resultDiv, 'Signature valid ✓\n\nMessage:\n\n' + verified.data);
            } catch (err) {
                showResult(resultDiv, 'Verification failed: ' + err.message, true);
            }
        }

        async function symmetricEncryptMsg() {
            const pass = document.getElementById('symEncPass').value;
            const text = document.getElementById('symPlain').value;
            const resultDiv = document.getElementById('symEncResult');
            const copyBtn = document.getElementById('symEncCopyBtn');

            if (!pass) {
                showResult(resultDiv, 'Error: passphrase is required.', true);
                copyBtn.style.display = 'none';
                return;
            }

            try {
                const encrypted = await openpgp.encrypt({
                    message: await openpgp.createMessage({ text }),
                    passwords: [pass],
                    format: 'armored'
                });
                showResult(resultDiv, encrypted);
                copyBtn.style.display = 'inline-block';
                copyBtn.innerText = '📋 Copy ciphertext';
                copyBtn.classList.remove('success');
                scheduleSensitiveDataCleanup();
            } catch (err) {
                showResult(resultDiv, 'Error: ' + err.message, true);
                copyBtn.style.display = 'none';
            }
        }

        async function symmetricDecryptMsg() {
            const pass = document.getElementById('symDecPass').value;
            const armor = document.getElementById('symCipher').value;
            const resultDiv = document.getElementById('symDecResult');
            const copyBtn = document.getElementById('symDecCopyBtn');

            if (!pass) {
                showResult(resultDiv, 'Error: passphrase is required.', true);
                copyBtn.style.display = 'none';
                return;
            }

            try {
                const message = await openpgp.readMessage({ armoredMessage: armor });
                const { data: decrypted } = await openpgp.decrypt({
                    message,
                    passwords: [pass]
                });
                showResult(resultDiv, 'Decrypted message:\n\n' + decrypted);
                copyBtn.style.display = 'inline-block';
                copyBtn.innerText = '📋 Copy decrypted text';
                copyBtn.classList.remove('success');
                scheduleSensitiveDataCleanup();
            } catch (err) {
                showResult(resultDiv, 'Decryption error: ' + err.message, true);
                copyBtn.style.display = 'none';
            } finally {
                clearInputValue('symDecPass');
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
