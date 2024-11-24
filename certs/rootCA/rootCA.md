# Root CA Directory

This directory contains the files related to the root Certificate Authority (CA).

## Contents

- **rootCA.key**: The private key for the root Certificate Authority (CA). This key is used to sign other certificates.

  It was generated using openSSL using the following command:

  ```zsh
  openssl genrsa -out rootCA.key 2048
  ```

  This key is not encrypted, which means it cannot be used for production use.
  An encrypted key can be generated using the option `-aes256` and typing a passphrase when prompted.

- **rootCA.cnf**: The OpenSSL configuration file used to generate the root CA certificate.

  It contains the necessary parameters describing the root CA of the PKI of a the fictional Springfield Hospital IT department. The hospital IT department is typically responsible for managing digital certificates.

- **rootCA.pem**: The root CA certificate. This is a self-signed certificate used to verify the authenticity of other certificates signed by the root CA.

  It was generated using openSSL using the following command:

  ```zsh
  openssl req -new -x509 -key rootCA.key -days 3650 -out rootCA.pem -config rootCA.cnf
  ```

  This command generated an X.509 self-signed root certificate for the Springfield General Hospital IT Department, valid for 10 years (3650 days), in the PEM format, which is a Base64-encoded format. To decode the certificate and display its contents in a human-readable format, use the following command:

  ```
  openssl x509 -in rootCA.pem -text -noout
  ```

- **rootCA.srl**: The serial number file for the root CA. It keeps track of the serial numbers of the certificates issued by the root CA..

Note: This is a very simple PKI setup and should not be used for production use. For a more secure setup of an internal root CA maintaining a PKI, please refer to the [OpenSSL CA documentation](https://openssl-ca.readthedocs.io/en/latest/index.html).
