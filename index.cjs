const dotenv = require('dotenv');
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
      const unencodedSharedSecret = Buffer.from(decryptedSharedSecretReanimation, 'base64');
      const unencodedPrivateKey = Buffer.from(privateKeyReanimation, 'base64');
      const unencodedPublicKey = Buffer.from(publicKeyReanimation, 'base64');
      console.log('Reanimation detected');
      console.log('decryptedSharedSecretReanimation: ', decryptedSharedSecretReanimation);
      console.log('privateKeyReanimation: ', privateKeyReanimation);
      console.log('publicKeyReanimation: ', publicKeyReanimation);
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
    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Not reanimating <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    } else {
      const [publicKey, privateKey] = await kem.generateKeyPair();
      console.log('ML-KEM key pair generated successfully');
      let publicKeyEncoded = Buffer.from(publicKey).toString('base64');
      let privateKeyEncoded = Buffer.from(privateKey).toString('base64');
      console.log(publicKeyEncoded);
      console.log(privateKeyEncoded);
      
      alias = 'angelahack1';
      const loginRegResponse = await new Promise((resolve, reject) => {
      client.LepagoService.LepagoPort.loginReg({
        login_name: alias,
        pubkey: publicKeyEncoded
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
    const decryptedSharedSecret = await kem.decap(undecodedCipherText, privateKey);
    console.log('Decapsulation successful');
    console.log('DecryptedSharedSecret (from encap) type:', typeof decryptedSharedSecret, 'is Buffer?', Buffer.isBuffer(decryptedSharedSecret), 'Length:', decryptedSharedSecret ? decryptedSharedSecret.length : 'N/A');
    let encodedDecryptedSharedSecret = Buffer.from(decryptedSharedSecret).toString('base64');
    console.log('Encoded decrypted shared secret:', encodedDecryptedSharedSecret);

    const proofOfWork = new ProofOfWork(loginRegResponse.challenge, 4);
    const proofOfWorkResult = proofOfWork.mine();
    console.log('Proof of work result:', proofOfWorkResult);

    //Write to files for reanimation..
    fs.writeFileSync('decryptedSharedSecret.txt', encodedDecryptedSharedSecret);
    fs.writeFileSync('privateKey.txt', privateKeyEncoded);
    fs.writeFileSync('publicKey.txt', publicKeyEncoded); 
    fs.writeFileSync('idc.txt', loginRegResponse.idc); 
    fs.writeFileSync('proofOfWorkResult.txt', proofOfWorkResult);
    fs.writeFileSync('alias.txt', alias); 
  }

  } catch (error) {
    console.error('An error occurred:', error.message);
    if (error.response) {
      console.error('Response Body:', error.response.body);
    }
  }
}

main();
