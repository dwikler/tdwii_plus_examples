# Digital Certificates Folder

The `certs` folder contains all the necessary files and documentation related to the creation, management, and usage of **_digital certificates_** within the project. This folder represents the project's **_Public Key Infrastructure (PKI)_**.

It includes:

- **Digital Certificates**: All generated digital certificates, including root CA certificates and application entities certificates.

  - PEM files: Digital certificates in PEM format.
  - P12 files: Digital certificates in PKCS#12 format.

- **Private Keys**: Private keys associated with the digital certificates.

- **Configuration Files**: OpenSSL configuration files used for generating digital certificates and managing the PKI.

- **Documentation**: Markdown files explaining the purpose and usage of each file, as well as instructions for generating and managing digital certificates.

## Folder Structure

```
certs/
├── rootCA/
├── servers/
├   ├── worklistmanager/
└── clients
    ├── workitemcreator/
    ├── workitemperformer/
    └── workitemwatcher/
```

## Description

- **rootCA/**: Contains all files related to the root Certificate Authority.
- **servers/**: Contains folders with files related to server applications digital certificates.
- **clients/**: Contains folders with files related to client applications digital certificates.

This structure helps keep everything organized by entity, making it easy to find and manage the various components of your PKI setup.
