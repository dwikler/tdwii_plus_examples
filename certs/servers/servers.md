# Servers Directory

This directory contains the files related to generation of the certificate of the Application Servers.

## Contents

Each subfolder in this directory contains the files related to the generation of the certificate of an Application Server.

Here is the list of the files for the Worklist Manager Server:

- **worklistmanager.key**: The private key for the Worklist Manager Server. This key is used to sign a request for a new certificate and to verify the authenticity of the Worklist Manager Server.

  It was generated using openSSL using the following command:

  ```zsh
  openssl genrsa -out worklistmanager.key 2048
  ```

  This key is not encrypted.

- **worklistmanager.cnf**: The OpenSSL configuration file used to generate the Worklist Manager Server certificate.

  It contains the necessary parameters describing the Server of the fictional Springfield Hospital Radiation Oncology department.

- **worklistmanager.csr**: The Worklist Manager Server certificate signing request. This request is used by the Worklist Manager Server to obtain a new certificate.

  It was generated using openSSL using the following command:

  ```zsh
  openssl req -new -key worklistmanager.key -out worklistmanager.csr -config worklistmanager.cnf
  ```

- **worklistmanager.pem**: The Worklist Manager Server certificate. This certificate is signed by our Root CA, which is a self-signed certificate authority. It is used by clients to verify the authenticity of the Worklist Manager Server.

  It was generated using openSSL using the following command ran from the project `certs/rootCA` directory:

  ```zsh
  openssl x509 -req -in ../servers/worklistmanager/worklistmanager.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out ../servers/worklistmanager/worklistmanager.pem -days 365 -extfile ../servers/worklistmanager/worklistmanager.cnf -extensions v3_req
  ```

  This command generated:

  - An X.509 certificate for the Worklist Manager Server of the Springfield General Hospital Radiation Oncology Department, valid for 1 years (365 days), in the PEM format.
  - A Serial number file, **rootCA.srl**, containing the next serial number to assign for the next certificate issued by the root CA.

Note: we preferred to use the .pem extension rather than the .crt extension which is another convention as it indicates the format of the file rather than its contents.
