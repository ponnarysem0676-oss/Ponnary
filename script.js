// script.js - Web Crypto interactive demo
// AES-GCM symmetric demo and RSA-OAEP asymmetric demo
// Note: This demo makes some keys extractable for educational purposes.

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- Helpers: base64 <-> ArrayBuffer ----
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ---- AES-GCM demo ----
let aesKey = null;

async function generateAesKey() {
  aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true, // extractable for demo
    ["encrypt", "decrypt"]
  );
  return aesKey;
}

async function encryptAes(plaintext) {
  if (!aesKey) throw new Error("AES key not set");
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV recommended
  const ptBuf = enc.encode(plaintext);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    ptBuf
  );
  return {
    ciphertext: arrayBufferToBase64(ct),
    iv: arrayBufferToBase64(iv.buffer)
  };
}

async function decryptAes(base64Ciphertext, base64Iv) {
  if (!aesKey) throw new Error("AES key not set");
  const ctBuf = base64ToArrayBuffer(base64Ciphertext);
  const ivBuf = base64ToArrayBuffer(base64Iv);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(ivBuf) },
    aesKey,
    ctBuf
  );
  return dec.decode(plainBuf);
}

// ---- RSA-OAEP demo ----
let rsaKeyPair = null;

async function generateRsaKeyPair() {
  rsaKeyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: "SHA-256"
    },
    true, // extractable for demo (public key extraction is fine)
    ["encrypt", "decrypt"]
  );
  return rsaKeyPair;
}

async function exportPublicKeyBase64(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return arrayBufferToBase64(spki);
}

async function importPublicKeyFromBase64(spkiBase64) {
  const spkiBuf = base64ToArrayBuffer(spkiBase64);
  return await crypto.subtle.importKey(
    "spki",
    spkiBuf,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

async function encryptRsa(publicKeyOrBase64, plaintext) {
  let pub;
  if (typeof publicKeyOrBase64 === "string") {
    pub = await importPublicKeyFromBase64(publicKeyOrBase64);
  } else {
    pub = publicKeyOrBase64;
  }
  const ptBuf = enc.encode(plaintext);
  const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, ptBuf);
  return arrayBufferToBase64(ct);
}

async function decryptRsa(base64Ciphertext) {
  if (!rsaKeyPair || !rsaKeyPair.privateKey) throw new Error("RSA key pair not set");
  const ctBuf = base64ToArrayBuffer(base64Ciphertext);
  const plainBuf = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaKeyPair.privateKey, ctBuf);
  return dec.decode(plainBuf);
}

// ---- DOM wiring ----
document.addEventListener("DOMContentLoaded", () => {
  // AES elements
  const aesGenBtn = document.getElementById("aes-gen");
  const aesEncryptBtn = document.getElementById("aes-encrypt");
  const aesDecryptBtn = document.getElementById("aes-decrypt");
  const aesPlain = document.getElementById("aes-plaintext");
  const aesCipher = document.getElementById("aes-ciphertext");
  const aesIv = document.getElementById("aes-iv");
  const aesDecrypted = document.getElementById("aes-decrypted");

  aesGenBtn.addEventListener("click", async () => {
    try {
      await generateAesKey();
      aesEncryptBtn.disabled = false;
      aesDecryptBtn.disabled = true;
      aesCipher.value = "";
      aesIv.value = "";
      aesDecrypted.value = "";
      alert("AES-256-GCM key generated (in-memory).");
    } catch (err) {
      alert("Error generating AES key: " + err.message);
    }
  });

  aesEncryptBtn.addEventListener("click", async () => {
    try {
      const pt = aesPlain.value;
      const { ciphertext, iv } = await encryptAes(pt);
      aesCipher.value = ciphertext;
      aesIv.value = iv;
      aesDecrypted.value = "";
      aesDecryptBtn.disabled = false;
    } catch (err) {
      alert("Encrypt error: " + err.message);
    }
  });

  aesDecryptBtn.addEventListener("click", async () => {
    try {
      const ct = aesCipher.value;
      const iv = aesIv.value;
      const decrypted = await decryptAes(ct, iv);
      aesDecrypted.value = decrypted;
    } catch (err) {
      alert("Decrypt error: " + err.message);
    }
  });

  // RSA elements
  const rsaGenBtn = document.getElementById("rsa-gen");
  const rsaEncryptBtn = document.getElementById("rsa-encrypt");
  const rsaDecryptBtn = document.getElementById("rsa-decrypt");
  const rsaPlain = document.getElementById("rsa-plaintext");
  const rsaPublic = document.getElementById("rsa-public");
  const rsaCipher = document.getElementById("rsa-ciphertext");
  const rsaDecrypted = document.getElementById("rsa-decrypted");

  rsaGenBtn.addEventListener("click", async () => {
    try {
      await generateRsaKeyPair();
      const pubB64 = await exportPublicKeyBase64(rsaKeyPair.publicKey);
      rsaPublic.value = pubB64;
      rsaEncryptBtn.disabled = false;
      rsaDecryptBtn.disabled = true;
      rsaCipher.value = "";
      rsaDecrypted.value = "";
      alert("RSA-2048 key pair generated (private key in-memory). Public key exported.");
    } catch (err) {
      alert("RSA generate error: " + err.message);
    }
  });

  rsaEncryptBtn.addEventListener("click", async () => {
    try {
      const pt = rsaPlain.value;
      const pubB64 = rsaPublic.value.trim();
      if (!pubB64) throw new Error("Public key not provided");
      const ct = await encryptRsa(pubB64, pt);
      rsaCipher.value = ct;
      rsaDecrypted.value = "";
      rsaDecryptBtn.disabled = false;
    } catch (err) {
      alert("RSA encrypt error: " + err.message);
    }
  });

  rsaDecryptBtn.addEventListener("click", async () => {
    try {
      const ct = rsaCipher.value.trim();
      if (!ct) throw new Error("No ciphertext present");
      const plain = await decryptRsa(ct);
      rsaDecrypted.value = plain;
    } catch (err) {
      alert("RSA decrypt error: " + err.message);
    }
  });
});
