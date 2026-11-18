const crypto = require('crypto');

class CryptographicService {
  constructor() {
    this.aesKey = crypto.scryptSync(process.env.AES_SECRET || 'aes-master-key', 'salt', 32);
    this.desKey = crypto.scryptSync(process.env.DES_SECRET || 'des-master-key', 'salt', 8);
    this.rc4Key = crypto.scryptSync(process.env.RC4_SECRET || 'rc4-master-key', 'salt', 16);
  }

  encryptTier1(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), data: encrypted, cipher: 'AES-256-CBC' };
  }

  decryptTier1(encryptedData, ivHex) {
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  generateUserKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
  }

  // Wraps the symmetric key and bundles it with the IV into a single base64 string
  encryptSymmetricKeyForRecipient(symmetricKeyHex, ivHex, recipientPublicKeyPem) {
    const combinedPayload = JSON.stringify({ key: symmetricKeyHex, iv: ivHex });
    const buffer = Buffer.from(combinedPayload, 'utf8');
    const encryptedKey = crypto.publicEncrypt(
      {
        key: recipientPublicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      buffer
    );
    return encryptedKey.toString('base64');
  }

  // Unwraps the single combined package using the private key
  decryptSymmetricKeyWithPrivate(encryptedKeyBase64, userPrivateKeyPem) {
    const buffer = Buffer.from(encryptedKeyBase64, 'base64');
    const decryptedBuffer = crypto.privateDecrypt(
      {
        key: userPrivateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      buffer
    );
    return JSON.parse(decryptedBuffer.toString('utf8'));
  }
}

module.exports = CryptographicService;