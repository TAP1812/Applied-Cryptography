"use strict";
/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const AES_GCM_IV_LENGTH = 12;


/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(kvs, hmacKey, aesKey, salt) {
    this.data = { 
      /* Store member variables that you intend to be public here
        (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
        (information that an adversary should NOT see). */
      kvs: kvs || {},  // HMAC(domain) -> { ciphertext, iv }
      hmacKey: hmacKey, // CryptoKey for HMAC
      aesKey: aesKey,   // CryptoKey for AES-GCM
      salt: salt        // Salt for PBKDF2  
    };
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const salt = await getRandomBytes(16);
    const { hmacKey, aesKey } = await Keychain.deriveKeys(password, salt);
    return new Keychain({}, hmacKey, aesKey, encodeBuffer(salt));
  }

  /**
    * Derives the HMAC and AES keys from the password and salt using PBKDF2.
    * @param {string} password The user's password.
    * @param {ArrayBuffer} salt The salt for PBKDF2.
    * @returns {Promise<{hmacKey: CryptoKey, aesKey: CryptoKey}>} The derived keys.
    */
  static async deriveKeys(password, salt) {
    const baseKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false, // extractable: false (PBKDF2 keys cannot be extractable)
      ["deriveKey"]
    );

    const hmacKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      baseKey,
      { name: "HMAC", hash: "SHA-256" },
      false, // extractable: false (derived keys usually non-extractable)
      ["sign", "verify"]
    );

    const aesKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false, // extractable: false (derived keys usually non-extractable)
      ["encrypt", "decrypt"]
    );

    return { hmacKey: hmacKey, aesKey: aesKey };
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    const parsed = JSON.parse(repr);
    const { salt, kvs } = parsed;

    if (trustedDataCheck) {
      const hashBuffer = await subtle.digest("SHA-256", stringToBuffer(repr)); // This implementation can prevent rollback attacks
      const hash = bufferToString(new Uint8Array(hashBuffer));
      if (hash !== trustedDataCheck) {
        throw new Error("Integrity check failed: SHA-256 checksum mismatch.");
      }
    }

    const { hmacKey, aesKey } = await Keychain.deriveKeys(password, decodeBuffer(salt));
    
    // Test decryption - This section performs decryption on the KVS entries to validate the password.
    for (const hmacValue in kvs) {
      if (kvs.hasOwnProperty(hmacValue)) {
        const { ciphertext, iv , tag} = kvs[hmacValue];
        try {
            const plaintextBuffer = await subtle.decrypt(
                { name: "AES-GCM", iv: decodeBuffer(iv) },
                aesKey, // Use the derived aesKey instead of this.secrets.aesKey
                decodeBuffer(ciphertext)
            );
            const paddedPlaintext = bufferToString(new Uint8Array(plaintextBuffer));
            // Remove PKCS#7 padding
            let plaintext = paddedPlaintext;
            let paddingLength = paddedPlaintext.charCodeAt(MAX_PASSWORD_LENGTH - 1);

            // Validate padding length (Crucial for security!)
            if (paddingLength > 0 && paddingLength <= MAX_PASSWORD_LENGTH) {
                let validPadding = true;
                for (let i = MAX_PASSWORD_LENGTH - paddingLength; i < MAX_PASSWORD_LENGTH; i++) {
                    if (paddedPlaintext.charCodeAt(i) !== paddingLength) {
                        validPadding = false;
                        break;
                    }
                }

                if (validPadding) {
                    plaintext = paddedPlaintext.substring(0, MAX_PASSWORD_LENGTH - paddingLength);
                } else {
                    plaintext = paddedPlaintext; // Or throw an error: "Invalid PKCS#7 padding detected!";
                }
            } else {
                // No valid padding found, assume the entire string is valid plaintext
                // In this specific case, the plaintext will be the max length (MAX_PASSWORD_LENGTH)
                // or the padding is wrong.  For security reasons, the decryption should probably fail
                plaintext = paddedPlaintext;  // Or throw an error: "Invalid PKCS#7 padding length!";
            }
            const tagBuffer = await subtle.digest(
              "SHA-256",
              Buffer.concat([stringToBuffer(plaintext), decodeBuffer(hmacValue)])
            );
        
            if (tag !== encodeBuffer(new Uint8Array(tagBuffer))) {
              throw new Error("Tag mismatch: Possible swap attack detected!");
            }

        } catch (error) {
          // If decryption fails for any entry, it indicates an incorrect password
          throw new Error("Incorrect password provided for keychain.");
        }
      }
    }

    return new Keychain(kvs, hmacKey, aesKey, salt);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    // Create a simple object to hold the data we want to serialize.  This is O(1).
    const dataToSerialize = {
      salt: this.secrets.salt,
      kvs: this.secrets.kvs, // KVS already in correct format (HMAC(domain) -> { ciphertext, iv })
    };

    // Serialize the data to a JSON string.  JSON.stringify is highly optimized. O(n) where n is number of entries in KVS.
    const jsonString = JSON.stringify(dataToSerialize);

    // Calculate the SHA-256 hash of the JSON string. The hashing algorithm is linear to the data size. O(m) where m is length of JSON string.
    const hashBuffer = await subtle.digest("SHA-256", stringToBuffer(jsonString));

    // Convert the hash buffer to a string.  O(1)
    const hash = bufferToString(new Uint8Array(hashBuffer));

    // Return the JSON string and the hash as an array. O(1)
    return [jsonString, hash];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    const hmacValue = await this.calculateHmac(name);
    const entry = this.secrets.kvs[hmacValue];

    if (!entry) {
      return null;
    }

    const { ciphertext, iv , tag} = entry; // Retrieve ciphertext and IV from KVS

    const plaintextBuffer = await subtle.decrypt(
      { name: "AES-GCM", iv: decodeBuffer(iv) },
      this.secrets.aesKey,
      decodeBuffer(ciphertext)
    );

    const paddedPlaintext = bufferToString(new Uint8Array(plaintextBuffer));

    // Remove PKCS#7 padding
    let plaintext = paddedPlaintext;
    let paddingLength = paddedPlaintext.charCodeAt(MAX_PASSWORD_LENGTH - 1);

    // Validate padding length (Crucial for security!)
    if (paddingLength > 0 && paddingLength <= MAX_PASSWORD_LENGTH) {
        let validPadding = true;
        for (let i = MAX_PASSWORD_LENGTH - paddingLength; i < MAX_PASSWORD_LENGTH; i++) {
            if (paddedPlaintext.charCodeAt(i) !== paddingLength) {
                validPadding = false;
                break;
            }
        }

        if (validPadding) {
            plaintext = paddedPlaintext.substring(0, MAX_PASSWORD_LENGTH - paddingLength);
        } else {
            plaintext = paddedPlaintext; // Or throw an error: "Invalid PKCS#7 padding detected!";
        }
    } else {
        // No valid padding found, assume the entire string is valid plaintext
        // In this specific case, the plaintext will be the max length (MAX_PASSWORD_LENGTH)
        // or the padding is wrong.  For security reasons, the decryption should probably fail
        plaintext = paddedPlaintext;  // Or throw an error: "Invalid PKCS#7 padding length!";
    }

    const tagBuffer = await subtle.digest(
      "SHA-256",
      Buffer.concat([stringToBuffer(plaintext), decodeBuffer(hmacValue)])
    );

    if (tag !== encodeBuffer(new Uint8Array(tagBuffer))) {
      throw new Error("Tag mismatch: Possible swap attack detected!");
    }

    return plaintext;
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    const hmacValue = await this.calculateHmac(name);
    const iv = await getRandomBytes(AES_GCM_IV_LENGTH);

    // PKCS#7 Padding
    const paddingLength = MAX_PASSWORD_LENGTH - value.length;
    let paddedValue = value;
    if (paddingLength > 0) {
      const paddingChar = String.fromCharCode(paddingLength); // Padding character is the padding length itself
      paddedValue += paddingChar.repeat(paddingLength);
    }
    else{
      throw new Error("Password is too long");
    }

    const ciphertextBuffer = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      this.secrets.aesKey,
      stringToBuffer(paddedValue)
    );

    // Calculate tag = SHA-256(HMAC(domain) + plaintext)
    // This implementation can prevent swap attacks
    const tagBuffer = await subtle.digest(
      "SHA-256",
      Buffer.concat([stringToBuffer(value), decodeBuffer(hmacValue)])
    );

    this.secrets.kvs[hmacValue] = {
      ciphertext: encodeBuffer(new Uint8Array(ciphertextBuffer)),
      iv: encodeBuffer(iv),
      tag: encodeBuffer(new Uint8Array(tagBuffer))
    };
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    const hmacValue = await this.calculateHmac(name);
    if (this.secrets.kvs[hmacValue]) {
      delete this.secrets.kvs[hmacValue];
      return true;
    }
    return false;
  };

  /**
    * Calculates the HMAC value for the given input string.
    * @param {string} input The input string.
    * @returns {Promise<string>} The HMAC value as a Base64 encoded string.
    */
  async calculateHmac(input) {
    const hmacBuffer = await subtle.sign(
      "HMAC",
      this.secrets.hmacKey,
      stringToBuffer(input)
    );
    return encodeBuffer(new Uint8Array(hmacBuffer));
  }
};

module.exports = { Keychain }
