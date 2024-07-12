## Azure HSM Signing JS

This repository is a sample for how to perform signing and verification of arbitrary data with [Azure KeyVault](https://azure.microsoft.com/en-us/services/key-vault/)

## Prerequisites

Before running this program, you must have a certificate set up in Azure keyvault and the following environment variables declared in .env file

```
KEYVAULT_URI="your-keyvault-url"
AZURE_TENANT_ID="your-azure-tenant-id"
AZURE_CLIENT_ID="your-azure-client-id"
AZURE_CLIENT_SECRET="your-client-secret-associated-with-azure-client-id"
AZURE_CERT_NAME="your-pdf-cert-name"


PDFNET_LICENSE_KEY="YOUR LICENSE KEY"
```
