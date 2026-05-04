let currentPublicKey = "";
        let currentPrivateKey = "";
        let currentRevocationCertificate = "";
        let sensitiveDataTimer = null;

        function normalizeFingerprintHex(s) {
            return String(s).replace(/[\s:]/g, '').toUpperCase();
        }

        function formatFingerprintGroups(hexFingerprint) {
            const h = normalizeFingerprintHex(hexFingerprint);
            const pairs = h.match(/.{1,4}/g);
            return pairs ? pairs.join(' ') : h;
        }

        function getGenerateExpirySecondsOrThrow() {
            const preset = document.getElementById('genExpiryPreset').value;
            if (preset === '') {
                return undefined;
            }
            if (preset === 'custom') {
                const days = Number.parseInt(document.getElementById('genExpiryDays').value, 10);
                if (!Number.isFinite(days) || days <= 0) {
                    throw new Error('Choose a positive number of days for custom expiry.');
                }
                return days * 24 * 60 * 60;
            }
            const seconds = Number.parseInt(preset, 10);
            return Number.isFinite(seconds) ? seconds : undefined;
        }

        function toggleGenExpiryCustom() {
            const preset = document.getElementById('genExpiryPreset');
            const wrap = document.getElementById('genExpiryCustomWrap');
            if (!preset || !wrap) {
                return;
            }
            wrap.hidden = preset.value !== 'custom';
        }

        function toggleGenAlgorithmOptions() {
            const algo = document.getElementById('genAlgorithm')?.value ?? 'rsa';
            const rsaOpts = document.getElementById('rsaOptionsWrap');
            const rsaWrap = document.getElementById('rsaEncSubWrap');
            const isRsa = algo === 'rsa';
            if (rsaOpts) {
                rsaOpts.hidden = !isRsa;
            }
            if (rsaWrap) {
                rsaWrap.hidden = !isRsa;
            }
            if (!isRsa) {
                const chk = document.getElementById('genSeparateEncSubkey');
                if (chk) {
                    chk.checked = false;
                }
            }
            toggleRsaEncSubopts();
        }

        function toggleRsaEncSubopts() {
            const algo = document.getElementById('genAlgorithm')?.value;
            const chk = document.getElementById('genSeparateEncSubkey');
            const bitsWrap = document.getElementById('rsaEncSubBitsWrap');
            if (!chk || !bitsWrap) {
                return;
            }
            const show = algo === 'rsa' && chk.checked;
            bitsWrap.hidden = !show;
        }

        async function streamArmoredMaybeToText(data) {
            if (!data) {
                return '';
            }
            if (typeof data === 'string') {
                return data;
            }
            try {
                if (typeof data.getReader === 'function') {
                    const decoder = new TextDecoder();
                    const reader = data.getReader();
                    let assembled = '';
                    for (;;) {
                        const { done, value } = await reader.read();
                        if (done) {
                            break;
                        }
                        if (value instanceof Uint8Array) {
                            assembled += decoder.decode(value, { stream: true });
                        } else if (typeof value === 'string') {
                            assembled += value;
                        }
                    }
                    return assembled + decoder.decode();
                }
                if (data[Symbol.asyncIterator]) {
                    let out = '';
                    for await (const chunk of data) {
                        out += typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk);
                    }
                    return out;
                }
            } catch {
                /* fall through */
            }
            try {
                return String(data);
            } catch {
                return '';
            }
        }

        async function refreshKeyManagementUI(publicKeyArmored, revocationArmoredOrEmpty = null) {
            const sumEl = document.getElementById('subkeySummary');
            const fpEl = document.getElementById('keyFingerprintDisplay');
            const revokeSec = document.getElementById('revocationCertSection');
            try {
                const pk = await openpgp.readKey({ armoredKey: publicKeyArmored });
                const fp = pk.getFingerprint();
                fpEl.innerText = formatFingerprintGroups(fp);
                const cnt = pk.subkeys ? pk.subkeys.length : 0;
                sumEl.innerText = `${cnt} encryption/signing material subkey packet(s)`;
            } catch {
                fpEl.innerText = '—';
                sumEl.innerText = '';
            }
            if (typeof revocationArmoredOrEmpty === 'string' && revocationArmoredOrEmpty.trim()) {
                currentRevocationCertificate = revocationArmoredOrEmpty;
                document.getElementById('revocationCertBox').value = revocationArmoredOrEmpty;
                revokeSec.hidden = false;
            } else if (!currentRevocationCertificate) {
                document.getElementById('revocationCertBox').value = '';
                revokeSec.hidden = true;
            }
            updateKeyMgmtVisibility();
        }

        function updateKeyMgmtVisibility() {
            const hasKeys = !!(currentPublicKey && String(currentPublicKey).trim());
            const emptyEl = document.getElementById('keyMgmtEmptyState');
            const contentEl = document.getElementById('keyMgmtContent');
            if (!emptyEl || !contentEl) {
                return;
            }
            emptyEl.hidden = hasKeys;
            contentEl.hidden = !hasKeys;
        }

        function hideExtendedKeyPanels() {
            const revokeSec = document.getElementById('revocationCertSection');
            const revEl = document.getElementById('revocationCertBox');
            const fpDisp = document.getElementById('keyFingerprintDisplay');
            const sumEl = document.getElementById('subkeySummary');
            if (fpDisp) {
                fpDisp.innerText = '';
            }
            if (sumEl) {
                sumEl.innerText = '';
            }
            if (revEl) {
                revEl.value = '';
            }
            if (revokeSec) {
                revokeSec.hidden = true;
            }
            updateKeyMgmtVisibility();
        }

        function syncGeneratedKeyToWorkflowFields() {
            if (!currentPrivateKey || !String(currentPrivateKey).trim()) {
                return;
            }
            const decEl = document.getElementById('decPrivKey');
            const signEl = document.getElementById('signPrivKey');
            if (decEl) {
                decEl.value = currentPrivateKey;
            }
            if (signEl) {
                signEl.value = currentPrivateKey;
            }
            if (currentPublicKey && String(currentPublicKey).trim()) {
                const verifyPub = document.getElementById('verifyPubKey');
                if (verifyPub) {
                    verifyPub.value = currentPublicKey;
                }
            }
        }

        async function copySessionFingerprintHex() {
            const display = document.getElementById('keyFingerprintDisplay');
            if (!display) {
                return;
            }
            const raw = normalizeFingerprintHex(display.innerText);
            if (!raw) {
                return;
            }
            try {
                await navigator.clipboard.writeText(raw);
            } catch (err) {
                console.error(err);
            }
        }



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
            clearInputValue('fpVerifyArmoredPub');
            clearInputValue('inspectKeyArmored');
            clearInputValue('fpVerifyExpected');
            clearInputValue('addSubkeyPassphrase');
            clearInputValue('genExpiryDays');
            const chkSub = document.getElementById('genSeparateEncSubkey');
            if (chkSub) {
                chkSub.checked = false;
            }
            const expirySel = document.getElementById('genExpiryPreset');
            if (expirySel) {
                expirySel.value = '';
            }
            const algoSel = document.getElementById('genAlgorithm');
            if (algoSel) {
                algoSel.value = 'rsa';
            }
            toggleGenExpiryCustom();
            toggleGenAlgorithmOptions();
            const subErr = document.getElementById('subkeyExtendError');
            if (subErr) {
                subErr.innerText = '';
                subErr.style.display = 'none';
            }
            clearResultPanel('fpVerifyResult');
            clearResultPanel('inspectKeyResult');
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
            currentRevocationCertificate = "";
            hideExtendedKeyPanels();
            const selector = document.getElementById('keySelector');
            const generatedKeyBox = document.getElementById('generatedKeyBox');
            if (generatedKeyBox) {
                generatedKeyBox.value = '';
            }
            if (selector) {
                selector.value = 'public';
            }
            const kd = document.getElementById('keyDisplayArea');
            if (kd) {
                kd.style.display = 'none';
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

        window.addEventListener('DOMContentLoaded', () => {
            initializeTheme();
            toggleGenAlgorithmOptions();
            toggleGenExpiryCustom();
            updateKeyMgmtVisibility();
        });

        const MAIN_TAB_IDS = ['enc-dec', 'sign-verify', 'key-mgmt', 'symmetric'];
        const MAIN_TAB_PANEL_MAP = {
            'enc-dec': 'panel-enc-dec',
            'sign-verify': 'panel-sign-verify',
            'key-mgmt': 'panel-key-mgmt',
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
            const algo = document.getElementById('genAlgorithm').value;
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

            let expirySeconds;
            try {
                expirySeconds = getGenerateExpirySecondsOrThrow();
            } catch (expErr) {
                showError(errorDiv, "Error: " + expErr.message);
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
                    userIDs: [userID],
                    passphrase,
                    format: 'armored'
                };

                if (typeof expirySeconds === 'number' && expirySeconds > 0) {
                    keyOptions.keyExpirationTime = expirySeconds;
                }

                if (algo === 'rsa') {
                    const rsaBits = Number.parseInt(document.getElementById('genRsaBits').value, 10) || 2048;
                    keyOptions.type = 'rsa';
                    keyOptions.rsaBits = rsaBits;
                    const extraEnc = document.getElementById('genSeparateEncSubkey').checked;
                    if (extraEnc) {
                        const subBits = Number.parseInt(document.getElementById('genEncSubRsaBits').value, 10) || rsaBits;
                        keyOptions.subkeys = [{ rsaBits: subBits }];
                    }
                } else {
                    keyOptions.type = 'ecc';
                    keyOptions.curve = 'ed25519';
                }

                const result = await openpgp.generateKey(keyOptions);

                const pubArmor = await streamArmoredMaybeToText(result.publicKey);
                const privArmor = await streamArmoredMaybeToText(result.privateKey);
                const revArmor = await streamArmoredMaybeToText(result.revocationCertificate);

                currentPublicKey = pubArmor;
                currentPrivateKey = privArmor;
                document.getElementById('decPrivKey').value = privArmor;

                await refreshKeyManagementUI(currentPublicKey, revArmor);

                displayArea.style.display = 'block';
                document.getElementById('keySelector').value = 'public';
                switchKeyView();
                syncGeneratedKeyToWorkflowFields();
                scheduleSensitiveDataCleanup();

            } catch (err) {
                showError(errorDiv, "Error: " + err.message);
            } finally {
                clearInputValue('genPassphrase');
                btn.disabled = false;
                btn.innerText = "Generate keys";
            }
        }

        async function copyRevocationCertificate() {
            const box = document.getElementById('revocationCertBox');
            if (!box) {
                return;
            }
            const text = box.value.trim();
            if (!text) {
                return;
            }
            try {
                await navigator.clipboard.writeText(text);
            } catch (err) {
                console.error('Copy revocation:', err);
            }
        }

        function downloadRevocationCertificate() {
            const text = document.getElementById('revocationCertBox')?.value?.trim?.() ?? '';
            if (!text) {
                return;
            }
            const fpRaw = document.getElementById('keyFingerprintDisplay')?.innerText ?? '';
            const snippet = normalizeFingerprintHex(fpRaw).slice(0, 16).toLowerCase() || 'key';
            const blob = new Blob([text], { type: 'application/pgp-keys' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `revocation-${snippet}.asc`;
            a.click();
            URL.revokeObjectURL(a.href);
        }

        async function attachSubkeyToCurrentKeypair() {
            const errBox = document.getElementById('subkeyExtendError');
            if (errBox) {
                errBox.style.display = 'none';
                errBox.innerText = '';
            }
            if (!currentPrivateKey.trim()) {
                showError(errBox, 'Generate or load a key first.');
                return;
            }
            const pass = document.getElementById('addSubkeyPassphrase').value;
            const kind = document.getElementById('addSubkeyKind').value;
            const btn = document.getElementById('btnAddSubkey');
            btn.disabled = true;
            btn.innerText = 'Working…';

            try {
                const unlocked = await openpgp.decryptKey({
                    privateKey: await openpgp.readPrivateKey({ armoredKey: currentPrivateKey }),
                    passphrase: pass
                });
                let subOpts;
                switch (kind) {
                    case 'enc-rsa3072':
                        subOpts = { type: 'rsa', rsaBits: 3072, sign: false };
                        break;
                    case 'enc-rsa4096':
                        subOpts = { type: 'rsa', rsaBits: 4096, sign: false };
                        break;
                    case 'sig-rsa3072':
                        subOpts = { type: 'rsa', rsaBits: 3072, sign: true };
                        break;
                    case 'enc-cv25519':
                        subOpts = { type: 'curve25519' };
                        break;
                    default:
                        subOpts = { type: 'rsa', rsaBits: 3072, sign: false };
                }
                const extended = await unlocked.addSubkey(subOpts);
                const reencrypted = await openpgp.encryptKey({
                    privateKey: extended,
                    passphrase: pass
                });
                const privArmor = await streamArmoredMaybeToText(reencrypted.armor());
                const pubArmor = await streamArmoredMaybeToText(reencrypted.toPublic().armor());

                currentPrivateKey = privArmor;
                currentPublicKey = pubArmor;
                document.getElementById('decPrivKey').value = privArmor;

                switchKeyView();
                await refreshKeyManagementUI(currentPublicKey, null);
                syncGeneratedKeyToWorkflowFields();
                scheduleSensitiveDataCleanup();
            } catch (err) {
                showError(errBox, 'Cannot add subkey: ' + err.message);
            } finally {
                clearInputValue('addSubkeyPassphrase');
                btn.disabled = false;
                btn.innerText = 'Add subkey';
            }
        }

        async function inspectKeyDetails() {
            const armored = document.getElementById('inspectKeyArmored').value.trim();
            const out = document.getElementById('inspectKeyResult');

            if (!armored) {
                showResult(out, 'Error: Key armored block is required.', true);
                return;
            }

            try {
                const key = await openpgp.readKey({ armoredKey: armored });
                let output = "";

                output += "Type: " + (key.isPrivate() ? "Private Key" : "Public Key") + "\n";

                const fp = normalizeFingerprintHex(key.getFingerprint());
                output += "Fingerprint: " + formatFingerprintGroups(fp) + "\n";

                output += "Created: " + key.getCreationTime().toLocaleString() + "\n";

                try {
                    const exp = await key.getExpirationTime();
                    if (exp && exp !== Infinity && exp.getTime() !== Infinity) {
                        output += "Expires: " + exp.toLocaleString() + "\n";
                    } else {
                        output += "Expires: Never\n";
                    }
                } catch (e) {
                    output += "Expires: Unknown\n";
                }

                if (key.users && key.users.length > 0) {
                    output += "\nUser IDs:\n";
                    for (let i = 0; i < key.users.length; i++) {
                        let uidStr = "Unknown";
                        if (key.users[i].userID) {
                            uidStr = key.users[i].userID.userID || key.users[i].userID.name || JSON.stringify(key.users[i].userID);
                        }
                        output += "- " + uidStr + "\n";
                    }
                }

                showResult(out, output, false);
            } catch (err) {
                showResult(out, 'Error: ' + err.message, true);
            }
        }

        async function verifyFingerprintMatch() {
            const armored = document.getElementById('fpVerifyArmoredPub').value.trim();
            const expectedRaw = document.getElementById('fpVerifyExpected').value;
            const out = document.getElementById('fpVerifyResult');

            if (!armored || !expectedRaw.trim()) {
                showResult(out, 'Error: Public key armored block and expected fingerprint are required.', true);
                return;
            }

            try {
                const key = await openpgp.readKey({ armoredKey: armored });
                const computed = normalizeFingerprintHex(key.getFingerprint());
                const expected = normalizeFingerprintHex(expectedRaw);
                const ok = computed.length > 0 && computed === expected;
                const readable = formatFingerprintGroups(computed);
                if (ok) {
                    showResult(out, 'Match ✓\n\nFingerprint from key:\n' + readable, false);
                } else {
                    showResult(
                        out,
                        'Mismatch ✗\n\nFingerprint from pasted key:\n' + readable + '\n\nExpected (normalized):\n' + formatFingerprintGroups(expected),
                        true
                    );
                }
            } catch (err) {
                showResult(out, 'Error: ' + err.message, true);
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
