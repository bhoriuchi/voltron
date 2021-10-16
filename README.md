# voltron
A simple offline CA that provides a way to share securely share the key passphrase

## How it works

Voltron works by using [certstrap](https://github.com/square/certstrap) as a library to generate a simple offline CA. However, Volton requires a passphrase to be set on the CA private key. The private key passphrase is never exposed directly. Instead, the passphrase is split into a configurable number of parts using the [HashiCorp Vault](https://github.com/hashicorp/vault/tree/main/shamir) implementation of [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing). In order to securely distribute these key parts, Voltron expects that a diverse group of "Trustees" each provide a public key to encrypt their allocated key part. This ensures each Trustee can only decrypt the key part they own.

Once the CA has been created, it can safely be stored offline. Trustees should also keep their secret key parts in a safe location

When a new certificate needs to be signed by the CA, Voltron is started in signing mode where it will generate an in-memory key pair and request ID for the signing request. The CSR, reqest ID, and in-memory public key are exported to a file that can be used by Trustees to approve the signing request. The Voltron process will stay active until enough trustee approval responses are submitted to recompose the passphrase for the CA's private key in order to complete the certificate singing process.

During a trustee approval, the trustee runs the `trustee approve` subcommand which will prompt the trustee for their key part. Once entered, this key part is encrypted with the public key provided in the request and exported to a response file that can be ingested by the active Voltron process.

## High level procedure

### Creating a CA

1. Create voltron config for the CA
2. Identify trustees and have trustees generate key-pairs `voltron trustee keygen`
3. Obtain public keys from trustees
4. Create the CA `voltron ca init`
5. Distribute encrypted keypart files (`*.enc.keypart`) to the appropriate trustees
6. Each trustee decrypts their key part `voltron trustee import-keypart` and stores it in a secure location
7. Store the CA cert, CRL, and encrypted private key in a secure location

### Signing a Request

1. Restore the CA cert, CRL, and encrypted private key to a location where voltron can be run
2. Run `voltron ca sign` with the CSR to start the signing process
3. Distribute the signing request file (`*.request.json`) to all trustees
4. Each trustee approves the request with `voltron trustee approve`
5. Trustees send back their generated response files
6. Response files are submitted by placing them into the response directory for voltron to consume
7. Once enough responses are processed to recompose the passphrase, the process will complete and the signed certificate will be exported
8. All key responses should be deleted/destroyed

### Manual fallback

1. Trustee's assemble the passphrase manually using their key parts
2. The passphrase is used to decrypt the CA key
3. Standard signing using a tool like OpenSSL can take place