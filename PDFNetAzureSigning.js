const fs = require('fs');
const { PDFNet } = require("@pdftron/pdfnet-node");
const AzureHSMService = require('./AzureHSMservice');


const { createHash } = require("crypto");
require("dotenv").config();

const pdfPath = process.env.PDF_PATH;
const outPath = process.env.OUTPUT_PDF_PATH;
const imgPath = process.env.IMG_PATH;
const certField = process.env.SIGNATURE_FIELD_NAME;
const digestalg = PDFNet.DigestAlgorithm.Type.e_SHA256;
const pades = true;

async function initializePDFNet() {
    try {
      await PDFNet.initialize(process.env.PDFNET_LICENSE_KEY);
      console.log('PDFNet initialized successfully.');
    } catch (error) {
      console.error('Error initializing PDFNet:', error);
      throw error; // Propagate the error if initialization fails
    }
  }


(async () => {
    try {
        await initializePDFNet();
        const azureHSMService = new AzureHSMService();
        await azureHSMService.initialize('pdfnetcert');
        console.log('AzureHSM Service intialized');
        const doc = await PDFNet.PDFDoc.createFromFilePath(pdfPath);
        doc.initSecurityHandler();

        const page1 = await doc.getPage(1);

        //Prepare PDF for signing
        const digsig_field = await doc.createDigitalSignatureField(certField);
        const widgetAnnot = await PDFNet.SignatureWidget.createWithDigitalSignatureField(doc, new PDFNet.Rect(143, 287, 219, 306), digsig_field);
        await page1.annotPushBack(widgetAnnot);

        //OPTIONAL: Add appearance for the signature
        const img = await PDFNet.Image.createFromFile(doc, imgPath);
        await widgetAnnot.createSignatureAppearance(img);

        //Create Signature Dictionary
        await digsig_field.createSigDictForCustomSigning(
            'Adobe.PPKLite',
            pades ? PDFNet.DigitalSignatureField.SubFilterType.e_ETSI_CAdES_detached : PDFNet.DigitalSignatureField.SubFilterType.e_adbe_pkcs7_detached,
            7500
          );

        //OPTIONAL: Add date and time to the signature
        const current_date = new PDFNet.Date();
        await current_date.setCurrentTime();
        await digsig_field.setSigDictTimeOfSigning(current_date);
        await doc.save(outPath, PDFNet.SDFDoc.SaveOptions.e_incremental);

        //Calculate the digest and retrieve the Public Cert from Azure Keyvault
        const pdf_digest = await digsig_field.calculateDigest(digestalg);
        const publicCert = await azureHSMService.getPublicCertificate();
        //console.log('got the cert)');
        const signer_cert = await PDFNet.X509Certificate.createFromBuffer(publicCert);
        const chain_certs = [signer_cert];
 
        const padesAtt = await PDFNet.DigitalSignatureField.generateESSSigningCertPAdESAttribute(signer_cert, digestalg);


        const signedAttrs = await PDFNet.DigitalSignatureField.generateCMSSignedAttributes(pdf_digest, padesAtt);
        const signedAttrsCopy = signedAttrs.slice(); // make a copy for PDFNet.DigitalSignatureField.generateCMSSignature()

        // Calculate the digest of the signedAttrs (i.e. not the PDF digest, this time).
        const hash = createHash("sha256");
        hash.update(signedAttrs);
        const signedAttrs_digest = hash.digest();
        //const signedAttrs_digest = await PDFNet.DigestAlgorithm.calculateDigest(digestalg, signedAttrs);

        //signing the digest of CMS attr w Azure key 
        const signature_value = await azureHSMService.sign(signedAttrs_digest);
        

        // Then, create ObjectIdentifiers for the algorithms you have used.
        // Here we use digest_algorithm_type (usually SHA256) for hashing, and RSAES-PKCS1-v1_5 (specified in the private key) for signing.
        const digest_algorithm_oid = await PDFNet.ObjectIdentifier.createFromDigestAlgorithm(digestalg);
        const signature_algorithm_oid = await PDFNet.ObjectIdentifier.createFromPredefined(PDFNet.ObjectIdentifier.Predefined.e_RSA_encryption_PKCS1);
        
        
        // Then, put the CMS signature components together.
        const cms_signature = await PDFNet.DigitalSignatureField.generateCMSSignature(signer_cert, chain_certs, digest_algorithm_oid, signature_algorithm_oid, signature_value, signedAttrsCopy);
        await doc.saveCustomSignature(cms_signature, digsig_field, outPath);
        console.log("Document has been signed and saved at", outPath);

        //OPTIONAL: Verify the sign
        //await azureHSMService.verify('RS256', signedAttrs_digest, signature_value);

    }

 catch (error) {
    console.error('Error:', error);
  } finally {
    await PDFNet.shutdown();
    console.log('PDFNet has been shut down.');
  }
  })();