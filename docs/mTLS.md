# tdwii_plus_examples with Secure Communications

DICOM defines how to use an encrypted TLS connection for the exchange of information using the DIMSE protocol.
In DICOM Part 15, Secure Transport Connection Profiles specifies requirements to establish TLS connections providing:

- strong encryption of the communication (TLS 1.2 and 1.3 most secure cypher suites)
- mutual authentication of the application entities (Mutual TLS)
- data integrity checks

The following scripts supports BCP 195 RFC 8996, 9325 TLS Secure Transport Connection Profile:

- upsscp.py
- ncreatescu.py
- upsfindscu.py
- nactionscu.py
- watchscu.py
- nevent_receiver.py
- nevent_sender.py

## mTLS Secure Communications

The [pynetdicom apps](https://pydicom.github.io/pynetdicom/dev/apps/index.html) do not support mTLS.  
[DCMTK Tools](https://support.dcmtk.org/docs/mod_dcmnet.html) do support mTLS but do not support UPS SOP Classes
[dcm4che Utilities](https://web.dcm4che.org/dcm4che-utilities) do support mTLS and UPS SOP Classes.

Disclaimer:
Users are responsible for ensuring that their use of encryption technologies complies with all applicable local, national, and international laws and regulations. The provider of this software assumes no liability for any misuse or non-compliance with legal requirements. Users should consult with legal counsel to understand their specific legal obligations related to the use of encryption in their jurisdiction.

## Public Key Infrastructure (PKI)

mTLS Secure Communications requires a **_Public Key Infrastructure (PKI)_** in order to create, manage and use **_digital certificates_**. This project provides a simple PKI and certificates in the `tdwii_plus_examples\certs` folder. Documentation is provided in [Digital Certificates Folder](../tdwii_plus_examples/certs/certs.md).

## Using upsscp.py script with mTLS to start a Worklist Manager Server

### Start the Server

```shell
python ./tdwii_plus_examples/upsscp.py -mtls -ca ./certs/rootCA/rootCA.pem \
-cert ./certs/clients/workitemperformer/workitemperformer.pem \
-key ./certs/clients/workitemperformer/workitemperformer.key \
--port 2762 \
--debug
```

Note: As DICOM Part 15 BCP 195 RFC 8996, 9325 TLS Secure Transport Connection Profile recommends the use of port number "2762 dicom-tls" for DICOM DIMSE protocol with TLS, using the `--port` is recommended:

### Configure the Server for mTLS

Alternatively, the [default configuration file](../tdwii_plus_examples/default.ini) can be modified to enable mTLS by default by setting `mutual_tls: true`
The paths to the CA certificate and Worklist Manager Server certificate and key files are also specified in the [default configuration file](../tdwii_plus_examples/default.ini)

- `ca_certificate:` _CA certificate PEM file path_
- `certificate` _Server certificate PEM file path_
- `private_key` _Server key PEM file path_

### Configure the Known Application Entities for mTLS

The [known application entities configuration file](../tdwii_plus_examples/ApplicationEntities.ini) contains the network information of peer DICOM applications so that the Worklist Manager Server can notify applications which subscribed for status update events notifications.
Each known application entity can be configured as using mTLS with their CA certificate to be used for authentication.

- `"mTLS":` _true_ or _false_
- `"CACertificate":` _CA certificate PEM file path_

## Using ncreatescu.py script with mTLS as a Workitem Creator Client

### Create a workitem

```shell
python ./tdwii_plus_examples/ncreatescu.py -mtls -ca ./certs/rootCA/rootCA.pem \
-cert ./certs/clients/workitemcreator/workitemcreator.pem \
-key ./certs/clients/workitemcreator/workitemcreator.key \
localhost 2762 <upsdicomfilepath> --debug
```

## Using upsfindscu.py script with mTLS as a Workitem Performer Client

### Query the Worklist Manager Server for workitems

```shell
python ./tdwii_plus_examples/upsfindscu.py -mtls -ca ./certs/rootCA/rootCA.pem \
-cert ./certs/clients/workitemperformer/workitemperformer.pem \
-key ./certs/clients/workitemperformer/workitemperformer.key \
-f ./ups_instances/1.2.840.113854.19.4.2017747596206021632.638223481578481915 \
-w \
localhost 2762
```

## Using the nactionscu.py script with mTLS as a Workitem Performer Client

### Claim a workitem

```shell
python ./tdwii_plus_examples/nactionscu.py -mtls -ca ./certs/rootCA/rootCA.pem \
-cert ./certs/clients/workitemperformer/workitemperformer.pem \
-key ./certs/clients/workitemperformer/workitemperformer.key \
-f <identifierfilepath> \
-w \
localhost 2762
```

## Using watchscu.py script with mTLS as a Workitem Watcher Client

### Subscribe to all workitems (global subscription)

```shell
python ./tdwii_plus_examples/watchscu.py -mtls -ca ./certs/rootCA/rootCA.pem \
-cert ./certs/clients/workitemwatcher/workitemwatcher.pem \
-key ./certs/clients/workitemwatcher/workitemwatcher.key \
localhost 2762
--port 2763
--debug
```

## Using neventreceiver.py script with mTLS as a Workitem Watcher Client

### Start the Notification Receiver Server

```shell
python ./tdwii_plus_examples/nevent_receiver.py -mtls \
-ca ./certs/rootCA/rootCA.pem \
-cert ./certs/clients/workitemperformer/workitemperformer.pem \
-key ./certs/clients/workitemperformer/workitemperformer.key
--port 2763
```

Note: Even if DICOM Part 15 BCP 195 RFC 8996, 9325 TLS Secure Transport Connection Profile recommends the use of port number "2762 dicom-tls" for DICOM DIMSE protocol with TLS, we choose here to use port number "2763 dicom-tls" for DICOM DIMSE protocol with TLS as 2762 dicom-tls is already used by the Worklist Manager Server.

### Configure the Server for mTLS

Alternatively, the [notification receiver configuration file](../tdwii_plus_examples/nevent_receiver_default.ini) can be modified to enable mTLS by default by setting `mutual_tls: true`
The paths to the CA certificate and Workitem Watcher Client (and Server) certificate and key files are also specified in the [notification receiver configuration file](../tdwii_plus_examples/nevent_receiver_default.ini)

- `ca_certificate:` _CA certificate PEM file path_
- `certificate` _Server certificate PEM file path_
- `private_key` _Server key PEM file path_

## Using nevent_sender.py script with mTLS as a Worklist Manager Server

### Send notifications

This script sends 3 notifications in a row, each of type UPS State Report with Input Readiness State "READY" and Procedure Step State 'SCHEDULING', 'IN PROGRESS' and "COMPLETED" respectively.

```shell
python ./tdwii_plus_examples/nevent_sender.py -mtls \
-ca ./certs/rootCA/rootCA.pem \
-cert ./certs/servers/worklistmanager/worklistmanager.pem \
-key ./certs/servers/worklistmanager/worklistmanager.key \
localhost 2763
```

## Using DCMTK apps with mTLS

Download and install the [DCMTK Tools](https://dcmtk.org/en/dcmtk/dcmtk-tools/).

### Verification Client (echoscu)

```shell
echoscu -v +tls ./certs/clients/workitemcreator/workitemcreator.key ./certs/clients/workitemcreator/workitemcreator.pem +cf ./certs/rootCA/rootCA.pem localhost 2762
```

Under Windows, download the DCMTK Tools OpenSSL based security extensions and use `echoscu-tls`

```shell
echoscu-tls -v +tls ./certs/clients/workitemcreator/workitemcreator.key ./certs/clients/workitemcreator/workitemcreator.pem +cf ./certs/rootCA/rootCA.pem localhost 2762
```

## Using dcm4che apps with mTLS

Download and install the [dcm4che Utilities](https://dcmtk.org/en/dcmtk/dcmtk-tools/).

### Generate PKCS#12 keystore and truststore.

dcm4che is a Java application and its java.security package does not natively support PEM format for certificates and private keys. Java does support the proprietary JKS (Java KeyStore) format and the standard PKCS#12 format.

In the Java terminology, a PKCS#12 file is referred to as a **keystore** and can contain 2 types of entries: keys and/or certificates.
A key entry contains both the private key and the certificate.
A certificate entry contains only the certificate and is generally used for storing the certificate of a trusted CA.
A PKCS#12 **keystore** file containing only certificate entries is a **truststore**.

dcm4che utilities expects **keystore** and **truststore** files to be specified in the command line or to be present in the dcm4che `certs` folder as the defaults `cacerts.p12` and `key.p12` files.

- Create the **keystore** from the workitemcreator PEM certificate and private key

  ```zsh
  openssl pkcs12 -export -in workitemcreator.pem -inkey workitemcreator.key -out workitemcreator.p12 -passout pass:
  ```

- Create the **truststore** from the rootCA PEM certificate

  In the case of a trustore, including the private key is not required nor recommended. Using openssl without a private key does not lead to a valid truststore and the Java keytool CLI must be used instead.

  ```zsh
  keytool -import -keystore rootCA.p12 -file rootCA.pem -alias springfieldgenCA
  ```

  - enter a password (6 character or more) for the truststore (twice). "secret" was used as for dcm4che default keystores in the `certs` folder.
  - type yes when prompted to trust this certificate.

  Verify the truststore:

  ```zsh
  keytool -list -keystore rootCA.p12
  ```

  - enter password when prompted

### Verification Client (storescu)

- Launch the dcm4che Verification Client

  ```shell
  storescu -c UPSSCP@localhost:2762 --key-store ./certs/clients/workitemcreator/workitemcreator.p12 --trust-store ./certs/rootCA/rootCA.p12 --key-store-pass="" --trust-store-pass="secret" -b DCM4CHE@localhost --tls-cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  ```

  Notes:

  - Make sure to use dcm4che storescu instead of DCMTK or pynetdicom storescu implementations.
  - If errors occur, activate Java networking low level classes debug to get detailed logs of the TLS handshake.

    ```zsh
    export JAVA_OPTS="-Djavax.net.debug=all"
    ```
