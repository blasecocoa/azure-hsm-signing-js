const { DefaultAzureCredential } = require("@azure/identity");
const { CertificateClient } = require("@azure/keyvault-certificates");
const { KeyClient, CryptographyClient } = require("@azure/keyvault-keys");
require("dotenv").config();


class AzureHSMService {
  constructor() {
    this.credential = new DefaultAzureCredential();
    this.keyClient = new KeyClient(process.env.KEYVAULT_URI, this.credential);
  }

  async initialize(certificateName) {
    this.certificateName = certificateName;
    this.myWorkKey = await this.keyClient.getKey(certificateName);
    // console.log("key",this.myWorkKey.id);
    // console.log("Key is returned with name", this.myWorkKey.name, "and type", this.myWorkKey.keyType);
    this.cryptoClient = new CryptographyClient(this.myWorkKey.id, this.credential);
  }

  async sign(digest) {
    const signResult = await this.cryptoClient.sign("RS256", digest);
    // console.log("sign result: ", signResult.result);
    const verifyResult = await this.cryptoClient.verify("RS256", digest, signResult.result);
    return signResult.result;
  }

  async verify(algorithm,origDigest, signedDigest){
    const result = await this.cryptoClient.verify(algorithm,origDigest,signedDigest);
    console.log(`Verified the signature using the algorithm ${result.Algorithm}, with key:\n${result.keyID}.\n\nSignature is valid:\n${result.isValid}`);

  }
  async getPublicCertificate() {
    const certClient = new CertificateClient(process.env.KEYVAULT_URI, this.credential);
    const certResponse = await certClient.getCertificate(this.certificateName);
    return certResponse.cer;
  }

}

module.exports = AzureHSMService;
