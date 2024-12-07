# Clients Directory

This directory contains the files related to generation of the certificate of the client applications.

## Contents

Each subfolder in this directory contains the files related to the generation of the certificate of a client application.

Here is the list of the files for the Workitem Creator client application:

- **workitemcreator.key**: The private key for the Workitem Creator Client. This key is used to sign a request for a new certificate and to verify the authenticity of the Workitem Creator Client.

  It was generated using openSSL using the following command:

  ```zsh
  openssl genrsa -out workitemcreator.key 2048
  ```

  This key is not encrypted.

- **workitemcreator.cnf**: The OpenSSL configuration file used to generate the Workitem Creator Client certificate.

  It contains the necessary parameters describing the client application of the fictional Springfield Hospital Radiation Oncology department.

- **workitemcreator.csr**: The Workitem Creator Client certificate signing request. This request is used by the Workitem Creator Client to obtain a new certificate.

  It was generated using openSSL using the following command:

  ```zsh
  openssl req -new -key workitemcreator.key -out workitemcreator.csr -config workitemcreator.cnf
  ```

- **workitemcreator.pem**: The Workitem Creator Client certificate. This certificate is signed by our Root CA, which is a self-signed certificate authority. It is used by clients to verify the authenticity of the Workitem Creator Client.

  It was generated using openSSL using the following command ran from the project `certs/rootCA` directory:

  ```zsh
  openssl x509 -req -in ../clients/workitemcreator/workitemcreator.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out ../clients/workitemcreator/workitemcreator.pem -days 365 -extfile ../clients/workitemcreator/workitemcreator.cnf -extensions v3_req
  ```

  This command generated:

  - An X.509 certificate for the Workitem Creator client application of the Springfield General Hospital Radiation Oncology Department, valid for 1 years (365 days), in the PEM format.
  - A Serial number file, **rootCA.srl**, containing the next serial number to assign for the next certificate issued by the root CA.

Note: we preferred to use the .pem extension rather than the .crt extension which is another convention as it indicates the format of the file rather than its contents.
