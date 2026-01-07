```markdown
# Encryption & Decryption Demo (Browser)

What you have
- A static site with interactive demos for:
  - AES-GCM symmetric encryption (generate key, encrypt, decrypt)
  - RSA-OAEP asymmetric encryption (generate key pair, export public key, encrypt, decrypt)
- An embedded YouTube iframe placeholder — replace the <code>VIDEO_ID</code> in `index.html` with the ID of the video you want to show.

How to run
1. Save the files (`index.html`, `styles.css`, `script.js`, `README.md`) in a folder.
2. Serve the folder with a static server. Examples:
   - Python 3: `python3 -m http.server 8000` then open http://localhost:8000
   - Node (http-server): `npx http-server` then open the printed URL
3. Open the site in a modern browser (Chrome, Edge, Firefox). The Web Crypto API is required.

Security & limitations
- This demo is for learning only. Do NOT use it as-is for production secrets or on untrusted pages.
- The RSA demo encrypts small messages only. For large data use hybrid encryption:
  - Generate a random AES key, encrypt the data with AES-GCM, then encrypt the AES key with RSA public key.
- Browser implementations of Web Crypto are safe for many use cases, but keys stored only in memory are ephemeral (page refresh clears them).
- The code intentionally keeps keys extractable for demonstration (so public key can be exported). For real secret keys, avoid making them extractable and avoid sending them anywhere.

Replace the YouTube video
- In `index.html` find:
  ```html
  <iframe src="https://www.youtube.com/embed/VIDEO_ID"></iframe>
  ```
  Replace `VIDEO_ID` with the video id you want to embed.

Questions or changes
- Tell me if you want:
  - A downloadable demo ZIP
  - Example of hybrid encryption (AES key encryption with RSA)
  - Server-side demo (Node) showing key exchange and storage
```
