'use strict'

/** ******* Imports ********/

const { subtle } = require('node:crypto').webcrypto
const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
    this.firstSender = true;
    this.notReceived = [];
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    // 1. Generate ElGamal key pair
    const keypairObject = await generateEG(); // Use generateEG() from lib.js

    // 2. Create certificate object
    const certificate = {
      username: username,
      publicKey: keypairObject.pub,
    };

    this.EGKeyPair = {
      publicKey: keypairObject.pub,
      privateKey: keypairObject.sec, 
    };

    return certificate;
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate);
    const verified = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if (verified) {
      this.certs[certificate.username] = certificate.publicKey;
    } else {
      throw new Error('Certificate verification failed');
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage (name, plaintext) {
    // 1. Get recipient's public key
    if (!this.certs.hasOwnProperty(name)) {
      throw new Error(`No certificate found for ${name}`);
    }
    const recipientPublicKey = this.certs[name];

    // 2. Check if a connection exists, if not, initialize it
    if (!this.conns[name]) {
      await this.initializeConnection(name, recipientPublicKey);
    }

    // 3. Perform DH Ratchet (if needed)
    // let dhPubKeyNew = null;
    // if (this.shouldPerformDHratchet(name)) {
    //   dhPubKeyNew = await this.performDHratchetAsSender(name);
    // }

    // 4. Get the current sending key
    const sendingKey = this.conns[name].sendingChain.key;

    // 5. Generate a random IV for message encryption
    const receiverIV = genRandomSalt();

    // 6. Encrypt sending key for the government and create header
    const { vGov, cGov, ivGov } = await this.encryptKeyForGovernment(await HMACtoAESKey(sendingKey, govEncryptionDataStr)); 
    const header = {
      vGov: vGov,
      cGov: cGov,
      ivGov: ivGov,
      receiverIV: receiverIV,
      messageNumber: this.conns[name].sendingChain.index,
    };

    // 7. Encrypt the message
    const ciphertext = await encryptWithGCM(await HMACtoAESKey(sendingKey, govEncryptionDataStr), plaintext, receiverIV, JSON.stringify(header));

    // 8. Increment the sending chain
    await this.incrementSendingChain(name);

    return [header, ciphertext];
  }

  
  /**
   * Initializes a new connection with another client.
   * @param {string} name The username of the other client.
   * @param {string} recipientPublicKey The ElGamal public key of the other client.
   */
  async initializeConnection (name, recipientPublicKey, firstSender = true) {
    this.firstSender = firstSender;

    // 1. Create the initial shared secret (using our private key and the recipient's public key)
    const sharedSecret = await computeDH(this.EGKeyPair.privateKey, recipientPublicKey);

    // 2. Create the initial Root Key and Sending, Receiving Key
    const [rootKey, temp1] = await HKDF(sharedSecret, sharedSecret, "init_rootKey");

    let [sendingKeyChain, receivingKeyChain] = await HKDF(rootKey, rootKey, "init_keyChains");
    if (!firstSender) {
      [receivingKeyChain, sendingKeyChain] = [sendingKeyChain, receivingKeyChain]
    }

    // 3. Store the connection
    this.conns[name] = {
      rootKey: rootKey,
      sendingChain: {
        key: sendingKeyChain,
        index: 0,
      },
      receivingChain: {
        key: receivingKeyChain,
        index: 0,
      },
    };
  }

  /**
   * Increments the sending chain.
   * @param {string} name The username of the recipient.
   */
  async incrementSendingChain (name) {
    this.conns[name].sendingChain.index += 1;
    const oldKey = this.conns[name].sendingChain.key;
    const [newKey, temp] = await HKDF(oldKey, oldKey, "new_key");
    this.conns[name].sendingChain.key = newKey;
  }

  /**
   * Encrypts the sending key for the government.
   * @param {CryptoKey} sendingKey The sending key.
   * @returns {Object} An object containing the encrypted sending key.
   */
  async encryptKeyForGovernment (sendingKeyChain) {
    // 1. Generate a random IV
    const ivGov = genRandomSalt();

    // 2. Export the sendingKeyChain as an ArrayBuffer
    const sendingKeyChainArrayBuffer = await subtle.exportKey("raw", sendingKeyChain);

    // 3. Compute shared secret with the goverment public key
    const sharedSecret = await computeDH(this.EGKeyPair.privateKey, this.govPublicKey);
    const hmacSharedSecret = await HMACtoAESKey(sharedSecret, govEncryptionDataStr);

    // 4. Encrypt the sending key with AES-GCM
    const cGov = await encryptWithGCM(hmacSharedSecret, sendingKeyChainArrayBuffer, ivGov);

    return {
      vGov: this.EGKeyPair.publicKey,
      cGov: cGov,
      ivGov: ivGov,
    };
  }

  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
   *
   * Return Type: string
   */
  async receiveMessage (name, [header, ciphertext]) {
    // 1. Get the sender's public key
    if (!this.certs.hasOwnProperty(name)) {
      throw new Error(`No certificate found for ${name}`);
    }
    const senderPublicKey = this.certs[name];

    // 2. Check if a connection exists, if not, initialize it
    if (!this.conns[name]) {
      await this.initializeConnection(name, senderPublicKey, false);
    }

    // 3. Perform DH Ratchet (if needed)
    // let dhPubKeyNew = null;
    // if (this.shouldPerformDHratchet(name)) {
    //   dhPubKeyNew = await this.performDHratchetAsReceiver(name);
    // }

    // 4. Get the current receiving key
    let receivingKey = this.conns[name].receivingChain.key;

    // 5. Get messageIndex then check if it is equal to current receivingChain.index. If not, increment receivingChain.key
    if (header.messageNumber > this.conns[name].receivingChain.index) {
      this.notReceived.push(this.conns[name].receivingChain.index);
      let currentReceivingIndex = this.conns[name].receivingChain.index;
      while (currentReceivingIndex < header.messageNumber) {
        let oldKey = receivingKey;
        let [newKey, temp] = await HKDF(oldKey, oldKey, "new_key");
        receivingKey = newKey;
        currentReceivingIndex += 1;
      }
    }
    else if (header.messageNumber < this.conns[name].receivingChain.index) {
      if (this.notReceived.includes(header.messageNumber)) {
        this.notReceived = this.notReceived.filter((index) => index !== header.messageNumber);
      }
      else{
        throw new Error('Replay attack detected');
      }
      let index = 0;
      const rootKey = this.conns[name].rootKey;
      let [sendingKeyChain, receivingKeyChain] = await HKDF(rootKey, rootKey, "init_keyChains");
      if (!this.firstSender) {
        [receivingKeyChain, sendingKeyChain] = [sendingKeyChain, receivingKeyChain]
      }
      while (index < header.messageNumber) {
        let oldKey = receivingKeyChain;
        let [newKey, temp] = await HKDF(oldKey, oldKey, "new_key");
        receivingKeyChain = newKey;
        index += 1;
      }
      receivingKey = receivingKeyChain;
    }

    // 6. Decrypt the message
    const plaintext = await decryptWithGCM(await HMACtoAESKey(receivingKey, govEncryptionDataStr), ciphertext, header.receiverIV, JSON.stringify(header));

    // 7. Update the receiving chain
    await this.incrementReceivingChain(name);

    return bufferToString(plaintext);
  }

  /**
   * Increments the receiving chain.
   * @param {string} name The username of the recipient.
   */
  async incrementReceivingChain (name) {
    this.conns[name].receivingChain.index += 1;
    const oldKey = this.conns[name].receivingChain.key;
    const [newKey, temp] = await HKDF(oldKey, oldKey, "new_key");
    this.conns[name].receivingChain.key = newKey;
  }
};

module.exports = {
  MessengerClient
}
