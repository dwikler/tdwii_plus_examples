# tdwii_plus_examples with Secure Communications

Support for the 

DICOM defines how to use an encrypted TLS connection for the exchange of information using the DIMSE protocol.
In DICOM Part 15, Secure Transport Connection Profiles specifies requirements to establish TLS connections providing:
- strong encryption of the communication (TLS 1.2 and 1.3 most secure cypher suites)
- mutual authentication of the application entities (Mutual TLS)
- data integrity checks 

The following tools supports BCP 195 RFC 8996, 9325 TLS Secure Transport Connection Profile:
- Worklist Manager Server (upsscp.py)
- Workitem Creator Client (ncreatescu.py)

[DCMTK Tools](https://support.dcmtk.org/docs/mod_dcmnet.html) and [dcm4che Utilities](https://web.dcm4che.org/dcm4che-utilities) support mTLS.

Disclaimer:
Users are responsible for ensuring that their use of encryption technologies complies with all applicable local, national, and international laws and regulations. The provider of this software assumes no liability for any misuse or non-compliance with legal requirements. Users should consult with legal counsel to understand their specific legal obligations related to the use of encryption in their jurisdiction.

## Public Key Infrastructure (PKI) 

mTLS Secure Communications requires a **_Public Key Infrastructure (PKI)_** in order to create, manage and use **_digital certificates_**. This project provides a simple PKI and certificates in the `tdwii_plus_examples\certs` folder. Documentation is provided in [Digital Certificates Folder](../tdwii_plus_examples/certs/certs.md).

## Using the Worklist Manager Server (upsscp.py) with mTLS

### Start the Server with the `-mtls` option

in `tdwii_plus_examples/`
```shell
python upsscp.py -mtls --debug
```

Note: As DICOM Part 15 BCP 195 RFC 8996, 9325 TLS Secure Transport Connection Profile recommends the use of port number "2762 dicom-tls" for DICOM DIMSE protocol with TLS, using the `--port` is recommended:

```shell
python upsscp.py -mtls --port 2762 --debug
```

### Configure the Server for mTLS

Alternatively, the [configuration file](../tdwii_plus_examples/default.ini) can be modified to enable mTLS by default by setting `mutual_tls: false`
The paths to the CA certificate and Worklist Manager Server certificate and key files are also specified in the [configuration file](../tdwii_plus_examples/default.ini) and can be overriden in the command line arguments:

* `-ca`     _CA certificate PEM file path_
* `-cert`   _Server certificate PEM file path_
* `-key`    _Server key PEM file path_

## Using the Workitem Creator Client (ncreatescu.py) with mTLS

### Start the Client with mTLS options

in `tdwii_plus_examples/`
```shell
python ncreatescu.py -mtls -ca ./certs/rootCA/rootCA.pem \
-cert ./certs/clients/workitemcreator/workitemcreator.pem \
-key ./certs/clients/workitemcreator/workitemcreator.key \
localhost 2762 ./ups_instances/<upsdicomfilename> --debug
```

## Using DCMTK apps with mTLS

Download and install the [DCMTK Tools](https://dcmtk.org/en/dcmtk/dcmtk-tools/).

### Verification Client (echoscu)

in `tdwii_plus_examples/`
```shell
echoscu -v +tls ./certs/clients/workitemcreator/workitemcreator.key ./certs/clients/workitemcreator/workitemcreator.pem +cf ./certs/rootCA/rootCA.pem localhost 2762
```

Under Windows, download the DCMTK Tools OpenSSL based security extensions and use `echoscu-tls`
```shell
echoscu-tls -v +tls ./certs/clients/workitemcreator/workitemcreator.key ./certs/clients/workitemcreator/workitemcreator.pem +cf ./certs/rootCA/rootCA.pem localhost 2762
```