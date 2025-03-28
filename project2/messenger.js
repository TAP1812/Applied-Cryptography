'use strict';

/** Imports */
const { subtle } = require('node:crypto').webcrypto;
const {
  bufferToString,
  genRandomSalt,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  cryptoKeyToJSON,
  govEncryptionDataStr
} = require('./lib');

/** Implementation */
class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {};
    this.certs = {};
    this.EGKeyPair = {};
    this.firstSender = true;
    this.notReceived = [];
  }

  async generateCertificate(username) {
    const keypairObject = await generateEG();
    
    const certificate = {
      username,
      publicKey: keypairObject.pub,
    };

    this.EGKeyPair = {
      publicKey: keypairObject.pub,
      privateKey: keypairObject.sec,
    };

    return certificate;
  }

  async receiveCertificate(certificate, signature) {
    const certString = JSON.stringify(certificate);
    const verified = await verifyWithECDSA(this.caPublicKey, certString, signature);
    
    if (!verified) {
      throw new Error('Certificate verification failed');
    }
    
    this.certs[certificate.username] = certificate.publicKey;
  }

  async sendMessage(name, plaintext) {
    if (!this.certs[name]) {
      throw new Error(`No certificate found for ${name}`);
    }

    const recipientPublicKey = this.certs[name];
    
    if (!this.conns[name]) {
      await this.initializeConnection(name, recipientPublicKey);
    }

    const sendingKey = this.conns[name].sendingChain.key;
    const receiverIV = genRandomSalt();
    
    const govEncryption = await this.encryptKeyForGovernment(
      await HMACtoAESKey(sendingKey, govEncryptionDataStr)
    );

    const header = {
      vGov: govEncryption.vGov,
      cGov: govEncryption.cGov,
      ivGov: govEncryption.ivGov,
      receiverIV,
      messageNumber: this.conns[name].sendingChain.index,
    };

    const ciphertext = await encryptWithGCM(
      await HMACtoAESKey(sendingKey, govEncryptionDataStr),
      plaintext,
      receiverIV,
      JSON.stringify(header)
    );

    await this.incrementSendingChain(name);
    
    return [header, ciphertext];
  }

  async initializeConnection(name, recipientPublicKey, firstSender = true) {
    this.firstSender = firstSender;
    
    const sharedSecret = await computeDH(this.EGKeyPair.privateKey, recipientPublicKey);
    const [rootKey] = await HKDF(sharedSecret, sharedSecret, "init_rootKey");
    
    let [sendingKeyChain, receivingKeyChain] = await HKDF(rootKey, rootKey, "init_keyChains");
    
    if (!firstSender) {
      [receivingKeyChain, sendingKeyChain] = [sendingKeyChain, receivingKeyChain];
    }

    this.conns[name] = {
      rootKey,
      sendingChain: { key: sendingKeyChain, index: 0 },
      receivingChain: { key: receivingKeyChain, index: 0 },
    };
  }

  async incrementSendingChain(name) {
    this.conns[name].sendingChain.index += 1;
    const oldKey = this.conns[name].sendingChain.key;
    const [newKey] = await HKDF(oldKey, oldKey, "new_key");
    this.conns[name].sendingChain.key = newKey;
  }

  async encryptKeyForGovernment(sendingKeyChain) {
    const ivGov = genRandomSalt();
    const sendingKeyChainArrayBuffer = await subtle.exportKey("raw", sendingKeyChain);
    const sharedSecret = await computeDH(this.EGKeyPair.privateKey, this.govPublicKey);
    const hmacSharedSecret = await HMACtoAESKey(sharedSecret, govEncryptionDataStr);
    const cGov = await encryptWithGCM(hmacSharedSecret, sendingKeyChainArrayBuffer, ivGov);

    return {
      vGov: this.EGKeyPair.publicKey,
      cGov,
      ivGov,
    };
  }

  async receiveMessage(name, [header, ciphertext]) {
    if (!this.certs[name]) {
      throw new Error(`No certificate found for ${name}`);
    }

    const senderPublicKey = this.certs[name];
    
    if (!this.conns[name]) {
      await this.initializeConnection(name, senderPublicKey, false);
    }

    let receivingKey = await this.handleMessageOrder(name, header);
    
    const plaintext = await decryptWithGCM(
      await HMACtoAESKey(receivingKey, govEncryptionDataStr),
      ciphertext,
      header.receiverIV,
      JSON.stringify(header)
    );

    await this.incrementReceivingChain(name);
    
    return bufferToString(plaintext);
  }

  async handleMessageOrder(name, header) {
    let receivingKey = this.conns[name].receivingChain.key;
    const currentIndex = this.conns[name].receivingChain.index;

    if (header.messageNumber > currentIndex) {
      this.notReceived.push(currentIndex);
      let index = currentIndex;
      while (index < header.messageNumber) {
        const [newKey] = await HKDF(receivingKey, receivingKey, "new_key");
        receivingKey = newKey;
        index += 1;
      }
    } else if (header.messageNumber < currentIndex) {
      if (this.notReceived.includes(header.messageNumber)) {
        this.notReceived = this.notReceived.filter(index => index !== header.messageNumber);
      } else {
        throw new Error('Replay attack detected');
      }
      return await this.recomputeReceivingKey(name, header.messageNumber);
    }

    return receivingKey;
  }

  async recomputeReceivingKey(name, targetIndex) {
    const rootKey = this.conns[name].rootKey;
    let [sendingKeyChain, receivingKeyChain] = await HKDF(rootKey, rootKey, "init_keyChains");
    
    if (!this.firstSender) {
      [receivingKeyChain, sendingKeyChain] = [sendingKeyChain, receivingKeyChain];
    }
    
    let index = 0;
    while (index < targetIndex) {
      const [newKey] = await HKDF(receivingKeyChain, receivingKeyChain, "new_key");
      receivingKeyChain = newKey;
      index += 1;
    }
    
    return receivingKeyChain;
  }

  async incrementReceivingChain(name) {
    this.conns[name].receivingChain.index += 1;
    const oldKey = this.conns[name].receivingChain.key;
    const [newKey] = await HKDF(oldKey, oldKey, "new_key");
    this.conns[name].receivingChain.key = newKey;
  }
}

module.exports = { MessengerClient };