const hex2buf = hexString => new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16))).buffer;
const buf2hex = bytes => [...new Uint8Array(bytes)].reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
const bufconcat = (buffer1, buffer2) => {
  const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set(new Uint8Array(buffer1), 0);
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
  return tmp.buffer;
};
const base64encode = arrayBuffer => btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
const base64encodeurlsafe = arrayBuffer => base64encode(arrayBuffer).replace(/\+/g, "-").replace(/\//g, "_");


const BLOCK_SIZE = 16;


class Multipass {
  constructor(secret, iv = null) {
    this.secret = secret;
    this.iv = iv ? hex2buf(iv) : crypto.getRandomValues(new Uint8Array(16));
    this.keys = null;
  }

  async encode(str) {
    await this.deriveKeys();
    const ciphertext = await this.encrypt(str);
    const signature = await this.sign(ciphertext);
    const tokenbuf = bufconcat(ciphertext, signature);
    const token = base64encodeurlsafe(tokenbuf);
    return token;
  }

  async deriveKeys() {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(this.secret))
    const rawEncryptionKey = hash.slice(0, BLOCK_SIZE)
    const rawSigningKey = hash.slice(BLOCK_SIZE, 32)
    const encryptionKey = await crypto.subtle.importKey(
      'raw',
      rawEncryptionKey,
      { name: 'AES-CBC' },
      true,
      ['encrypt', 'decrypt']
    );
    const signingKey = await crypto.subtle.importKey(
      'raw',
      rawSigningKey,
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign']
    );

    this.keys = {
      hash,
      rawEncryptionKey,
      rawSigningKey,
      encryptionKey,
      signingKey,
    }
  }

  async encrypt(str) {
    return bufconcat(this.iv, await crypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv: this.iv
      },
      this.keys.encryptionKey,
      new TextEncoder().encode(str)
    ));
  }

  async sign(buffer) {
    const signature = await crypto.subtle.sign(
      "HMAC",
      this.keys.signingKey,
      buffer
     );
    return signature;
  }
}
