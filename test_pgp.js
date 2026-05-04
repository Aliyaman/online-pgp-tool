const openpgp = require('openpgp');

async function test() {
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'rsa',
        rsaBits: 2048,
        userIDs: [{ name: 'Test User', email: 'test@example.com' }]
    });

    const key = await openpgp.readKey({ armoredKey: publicKey });
    console.log("Fingerprint:", key.getFingerprint());
    console.log("Creation:", key.getCreationTime());
    try {
        console.log("Expiration:", await key.getExpirationTime());
    } catch(e) { console.log("Expiration error", e); }
    
    console.log("Users:", key.users.map(u => u.userID ? u.userID.userID : 'unknown'));
    console.log("isPrivate:", key.isPrivate());
    
    // what algorithm?
    console.log("algo:", key.getAlgorithmInfo ? key.getAlgorithmInfo() : "no getAlgorithmInfo");
}
test().catch(console.error);
