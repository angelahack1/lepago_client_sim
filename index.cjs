const dotenv = require('dotenv');
const crypto = require('crypto');
dotenv.config();
dotenv.config({ path: '.env.local', override: true }); 
const soap = require('soap');
const { MlKem1024 } = require('mlkem');
const fs = require('fs');
const { ProofOfWork } = require('./pow/proofofwork');

const {
  WSDL_SERVICE_PORT,
  EXECUTOR_URL,
} = process.env;

async function main() {
  try {
    const wsdlUrl = process.env.WSDL_SERVICE_PORT;
    const executorUrl = process.env.EXECUTOR_URL;
    console.log('executorUrl', executorUrl);
    console.log('wsdlUrl', wsdlUrl);
    var alias = '';
    if (!wsdlUrl) {
      console.error('Error: WSDL_SERVICE_PORT environment variable is not set.');
      process.exit(1);
    }

    console.log(`Loading WSDL from: ${wsdlUrl}`);
    const client = await soap.createClientAsync(wsdlUrl);
    console.log('SOAP client created successfully.');
    const description = client.describe();
    console.log('Service description:', JSON.stringify(description, null, 2));
    const kem = new MlKem1024();
    client.setEndpoint(executorUrl);

    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Reanimating <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    if (fs.existsSync('decryptedSharedSecret.txt') && fs.existsSync('privateKey.txt') && fs.existsSync('publicKey.txt') && fs.existsSync('idc.txt') && fs.existsSync('alias.txt')) {
      console.log('Reanimation detected');
      const decryptedSharedSecretReanimation = fs.readFileSync('decryptedSharedSecret.txt', 'utf8');
      const privateKeyReanimation = fs.readFileSync('privateKey.txt', 'utf8');
      const publicKeyReanimation = fs.readFileSync('publicKey.txt', 'utf8');
      const idcReanimation = fs.readFileSync('idc.txt', 'utf8');
      alias = fs.readFileSync('alias.txt', 'utf8');
      const unencodedDecryptedSharedSecret = Buffer.from(decryptedSharedSecretReanimation, 'base64');
      const unencodedPrivateKey = Buffer.from(privateKeyReanimation, 'base64');
      const unencodedPublicKey = Buffer.from(publicKeyReanimation, 'base64');
      console.log('Reanimation detected');
      console.log('decryptedSharedSecretReanimation: ', unencodedDecryptedSharedSecret);
      console.log('privateKeyReanimation: ', unencodedPrivateKey);
      console.log('publicKeyReanimation: ', unencodedPublicKey);
      console.log('idcReanimation: ', idcReanimation);

      console.log('Abput to connect...');
      const loginReqResp = await new Promise((resolve, reject) => {
      client.LepagoService.LepagoPort.loginReq({
        login_name: alias,
        idc: idcReanimation
      }, (err, result, rawResponse, soapHeader, rawRequest) => {
        console.error('An error occurred:', err);
        resolve(result);
      });
    });

    console.log('Login response status:', loginReqResp.status);
    console.log('Login response challenge:', loginReqResp.challenge);
    const proofOfWork = new ProofOfWork(loginReqResp.challenge, 4);
    const proofOfWorkResult = proofOfWork.mine();
    console.log('Proof of work result:', proofOfWorkResult);
    const unencodedProofOfWorkResult = Buffer.from(proofOfWorkResult.hash, 'hex');
    // Create an initialization vector (IV)
    const iv = crypto.randomBytes(16);
    // Create cipher using AES-256-GCM with the shared secret as key
    const cipher = crypto.createCipheriv('aes-256-gcm', unencodedDecryptedSharedSecret.slice(0, 32), iv);
    // Encrypt the proof of work hash
    const encryptedData = Buffer.concat([
      cipher.update(unencodedProofOfWorkResult),
      cipher.final()
    ]);
    // Get the authentication tag
    const authTag = cipher.getAuthTag();
    // Combine IV, encrypted data, and auth tag
    const cryptedHash = Buffer.concat([iv, encryptedData, authTag]).toString('base64');
    console.log('cryptedHash:', cryptedHash);
    //Send the ciphertext to the server
    const challengeRespAckStatus = await new Promise((resolve, reject) => {
      client.LepagoService.LepagoPort.challengeResp({
        idc: idcReanimation,
        crypted_hash: cryptedHash
      }, (err, result, rawResponse, soapHeader, rawRequest) => {
        if (err) {
          if (err.root && err.root.Envelope && err.root.Envelope.Body && err.root.Envelope.Body.Fault) {
            console.error('SOAP Fault:', JSON.stringify(err.root.Envelope.Body.Fault, null, 2));
            return reject(new Error(err.root.Envelope.Body.Fault.faultstring || 'SOAP Fault occurred'));
          }
          return reject(err);
        }
        resolve(result);
      });
    });
    console.log('Challenge response status:', challengeRespAckStatus);
    if (challengeRespAckStatus.status === 'OK') {
      console.log('Challenge response successful');
    } else {
      console.log('Challenge response failed');
    }
    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Not reanimating <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    } else {
      const [publicKey, privateKey] = await kem.generateKeyPair();
      console.log('ML-KEM key pair generated successfully');
      let publicKeyEncoded = Buffer.from(publicKey).toString('base64');
      let privateKeyEncoded = Buffer.from(privateKey).toString('base64');
      console.log(publicKeyEncoded);
      console.log(privateKeyEncoded);
      
      alias = 'cosapi';
      const loginRegResponse = await new Promise((resolve, reject) => {
      client.LepagoService.LepagoPort.loginReg({
        login_name: alias,
        public_key: publicKeyEncoded
      }, (err, result, rawResponse, soapHeader, rawRequest) => {
        if (err) {
          if (err.root && err.root.Envelope && err.root.Envelope.Body && err.root.Envelope.Body.Fault) {
            console.error('SOAP Fault:', JSON.stringify(err.root.Envelope.Body.Fault, null, 2));
            return reject(new Error(err.root.Envelope.Body.Fault.faultstring || 'SOAP Fault occurred'));
          }
          return reject(err);
        }
        resolve(result);
      });
    });

    console.log('Login response status:', loginRegResponse.status);
    console.log('Login response idc:', loginRegResponse.idc);
    console.log('Login response ciphertext:', loginRegResponse.ciphertext);
    console.log('Login response challenge:', loginRegResponse.challenge);
    const undecodedCipherText = Buffer.from(loginRegResponse.ciphertext, 'base64');
    const undecodedDecryptedSharedSecret = await kem.decap(undecodedCipherText, privateKey);  //Decrypt of ciphertext!!! -> sharedSecret.
    console.log('Decapsulation successful');
    console.log('UndecodedDecryptedSharedSecret (from encap) type:', typeof undecodedDecryptedSharedSecret, 'is Buffer?', Buffer.isBuffer(undecodedDecryptedSharedSecret), 'Length:', undecodedDecryptedSharedSecret ? undecodedDecryptedSharedSecret.length : 'N/A');
    let encodedDecryptedSharedSecret = Buffer.from(undecodedDecryptedSharedSecret).toString('base64');
    console.log('Encoded decrypted shared secret:', encodedDecryptedSharedSecret);

    const proofOfWork = new ProofOfWork(loginRegResponse.challenge, 4);
    const proofOfWorkResult = proofOfWork.mine();
    console.log('Proof of work result:', proofOfWorkResult);
    const unencodedProofOfWorkResult = Buffer.from(proofOfWorkResult.hash, 'hex');
    console.log('unencodedProofOfWorkResult:', unencodedProofOfWorkResult);

    //Write to files for reanimation..
    fs.writeFileSync('decryptedSharedSecret.txt', encodedDecryptedSharedSecret);
    fs.writeFileSync('privateKey.txt', privateKeyEncoded);
    fs.writeFileSync('publicKey.txt', publicKeyEncoded); 
    fs.writeFileSync('idc.txt', loginRegResponse.idc); 
    fs.writeFileSync('alias.txt', alias); 

     // Create an initialization vector (IV)
     const iv = crypto.randomBytes(16);
     // Create cipher using AES-256-GCM with the shared secret as key
     const cipher = crypto.createCipheriv('aes-256-gcm', undecodedDecryptedSharedSecret.slice(0, 32), iv);
     // Encrypt the proof of work hash
     const encryptedData = Buffer.concat([
       cipher.update(unencodedProofOfWorkResult),
       cipher.final()
     ]);
     // Get the authentication tag
     const authTag = cipher.getAuthTag();
     // Combine IV, encrypted data, and auth tag
     const cryptedHash = Buffer.concat([iv, encryptedData, authTag]).toString('base64');
     console.log('cryptedHash:', cryptedHash);
     //Send the ciphertext to the server
    const challengeRespAckStatus = await new Promise((resolve, reject) => {
      client.LepagoService.LepagoPort.challengeResp({
        idc: loginRegResponse.idc,
        crypted_hash: cryptedHash
      }, (err, result, rawResponse, soapHeader, rawRequest) => {
        if (err) {
          if (err.root && err.root.Envelope && err.root.Envelope.Body && err.root.Envelope.Body.Fault) {
            console.error('SOAP Fault:', JSON.stringify(err.root.Envelope.Body.Fault, null, 2));
            return reject(new Error(err.root.Envelope.Body.Fault.faultstring || 'SOAP Fault occurred'));
          }
          return reject(err);
        }
        resolve(result);
      });
    });
    console.log('Challenge response status:', challengeRespAckStatus);
    if (challengeRespAckStatus.status === 'OK') {
      console.log('Challenge response successful');
    } else {
      console.log('Challenge response failed');
    }
  }

  } catch (error) {
    console.error('An error occurred:', error.message);
    if (error.response) {
      console.error('Response Body:', error.response.body);
    }
  }
}

function decryptWithSharedSecret(encryptedData, sharedSecret) {
    // Convert base64 string back to buffer
    const encryptedBuffer = Buffer.from(encryptedData, 'base64');
    
    // Extract IV (first 16 bytes), encrypted data, and auth tag
    const iv = encryptedBuffer.slice(0, 16);
    const authTag = encryptedBuffer.slice(-16);
    const encryptedContent = encryptedBuffer.slice(16, -16);
    
    // Create decipher using AES-256-GCM
    const decipher = crypto.createDecipheriv('aes-256-gcm', sharedSecret.slice(0, 32), iv);
    decipher.setAuthTag(authTag);
    
    // Decrypt the data
    const decrypted = Buffer.concat([
        decipher.update(encryptedContent),
        decipher.final()
    ]);
    
    return decrypted;
}

// Example usage:
// const decryptedData = decryptWithSharedSecret(cryptedHash, unencodedSharedSecret);
// console.log('Decrypted data:', decryptedData.toString('hex'));

main();
