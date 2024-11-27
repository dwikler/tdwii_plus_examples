#!/usr/bin/env python
"""A Verification, Storage and Query/Retrieve SCP application."""

import argparse
import os
import sys
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from configparser import ConfigParser
from pathlib import Path

import pydicom.config
from pynetdicom import (
    AE,
    ALL_TRANSFER_SYNTAXES,
    UnifiedProcedurePresentationContexts,
    _config,
    _handlers,
    evt,
)
from pynetdicom.apps.common import setup_logging
from pynetdicom.sop_class import Verification
from pynetdicom.utils import set_ae
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tdwii_plus_examples import upsdb
from tdwii_plus_examples.handlers import (
    handle_echo,
    handle_find,
    handle_naction,
    handle_ncreate,
    handle_nget,
    handle_nset,
)

# Use `None` for empty values
pydicom.config.use_none_as_empty_text_VR_value = True
# Don't log identifiers
_config.LOG_RESPONSE_IDENTIFIERS = False


# Override the standard logging handlers
def _dont_log(event):
    pass


# _handlers._send_c_find_rsp = _dont_log
_handlers._send_c_get_rsp = _dont_log
_handlers._send_c_move_rsp = _dont_log
_handlers._send_c_store_rq = _dont_log
_handlers._recv_c_store_rsp = _dont_log


__version__ = "1.1.0"


def _log_config(config, logger):
    """Log the configuration settings.

    Parameters
    ----------
    logger : logging.Logger
        The application's logger.
    """
    logger.debug("Configuration settings")
    app = config["DEFAULT"]
    aet, port, pdu = app["ae_title"], app["port"], app["max_pdu"]
    logger.debug(f"  AE title: {aet}, Port: {port}, Max. PDU: {pdu}")
    logger.debug("  Timeouts:")
    acse, dimse = app["acse_timeout"], app["dimse_timeout"]
    network = app["network_timeout"]
    logger.debug(f"    ACSE: {acse}, DIMSE: {dimse}, Network: {network}")
    mtls = config.getboolean('DEFAULT', 'mutual_tls')
    if mtls:
        ca_cert, key, cert = app["ca_certificate"], app["private_key"], app["certificate"]
        logger.debug("  Mutual TLS enabled")
        logger.debug(f"    CA: {ca_cert}")
        logger.debug(f"    Certificate: {cert}, Private Key: {key}")
    else:
         logger.debug("  Mutual TLS disabled")

    logger.debug(f"  Storage directory: {app['instance_location']}")
    logger.debug(f"  Database location: {app['database_location']}")

    if config.sections():
        logger.debug("  Move destinations: ")
    else:
        logger.debug("  Move destinations: none")

    for ae_title in config.sections():
        addr = config[ae_title]["address"]
        port = config[ae_title]["port"]
        logger.debug(f"    {ae_title}: ({addr}, {port})")

    logger.debug("")


def clean(db_path, instance_path, logger):
    """Remove all entries from the database and delete the corresponding
    stored instances.

    Parameters
    ----------
    db_path : str
        The database path to use with create_engine().
    instance_path : str
        The instance storage path.
    logger : logging.Logger
        The application logger.

    Returns
    -------
    bool
        ``True`` if the storage directory and database were both cleaned
        successfully, ``False`` otherwise.
    """
    engine = create_engine(db_path)
    with engine.connect() as conn:  # noqa: F841
        Session = sessionmaker(bind=engine)
        session = Session()
        query_success = True
        try:
            fpaths = [ii.filename for ii in session.query(upsdb.Instance).all()]
        except Exception as exc:
            logger.error("Exception raised while querying the database")
            logger.exception(exc)
            session.rollback()
            query_success = False
        finally:
            session.close()

        if not query_success:
            return False

        storage_cleaned = True
        for fpath in fpaths:
            try:
                os.remove(os.path.join(instance_path, fpath))
            except Exception as exc:
                logger.error(f"Unable to delete the instance at '{fpath}'")
                logger.exception(exc)
                storage_cleaned = False

        if storage_cleaned:
            logger.info("Storage directory cleaned successfully")
        else:
            logger.error("Failed to clean storage directory")

        database_cleaned = False
        try:
            upsdb.clear(session)
            database_cleaned = True
            logger.info("Database cleaned successfully")
        except Exception as exc:
            logger.error("Failed to clean the database")
            logger.exception(exc)
            session.rollback()
        finally:
            session.close()

        return database_cleaned and storage_cleaned


def _setup_argparser():
    """Setup the command line arguments"""
    # Description
    parser = argparse.ArgumentParser(
        description=(
            "The upsscp application implements a Service Class Provider (SCP) "
            "for the Verification and Unified Procedure Step (UPS) Service "
            "Classes."
        ),
        usage="upsscp [options]",
    )

    # General Options
    gen_opts = parser.add_argument_group("General Options")
    gen_opts.add_argument("--version", help="print version information and exit", action="store_true")
    output = gen_opts.add_mutually_exclusive_group()
    output.add_argument(
        "-q",
        "--quiet",
        help="quiet mode, print no warnings and errors",
        action="store_const",
        dest="log_type",
        const="q",
    )
    output.add_argument(
        "-v",
        "--verbose",
        help="verbose mode, print processing details",
        action="store_const",
        dest="log_type",
        const="v",
    )
    output.add_argument(
        "-d",
        "--debug",
        help="debug mode, print debug information",
        action="store_const",
        dest="log_type",
        const="d",
    )
    gen_opts.add_argument(
        "-ll",
        "--log-level",
        metavar="[l]",
        help=("use level l for the logger (critical, error, warn, info, debug)"),
        type=str,
        choices=["critical", "error", "warn", "info", "debug"],
    )
    fdir = os.path.abspath(os.path.dirname(__file__))
    fpath = os.path.join(fdir, "default.ini")
    gen_opts.add_argument(
        "-c",
        "--config",
        metavar="[f]ilename",
        help="use configuration file f",
        default=fpath,
    )

    net_opts = parser.add_argument_group("Networking Options")
    net_opts.add_argument(
        "--port",
        help="override the configured TCP/IP listen port number",
    )
    net_opts.add_argument(
        "-aet",
        "--ae-title",
        metavar="[a]etitle",
        help="override the configured AE title",
    )
    net_opts.add_argument(
        "-ta",
        "--acse-timeout",
        metavar="[s]econds",
        help="override the configured timeout for ACSE messages",
    )
    net_opts.add_argument(
        "-td",
        "--dimse-timeout",
        metavar="[s]econds",
        help="override the configured timeout for DIMSE messages",
    )
    net_opts.add_argument(
        "-tn",
        "--network-timeout",
        metavar="[s]econds",
        help="override the configured timeout for the network",
    )
    net_opts.add_argument(
        "-pdu",
        "--max-pdu",
        metavar="[n]umber of bytes",
        help="override the configured max receive pdu to n bytes",
    )
    net_opts.add_argument(
        "-ba",
        "--bind-address",
        metavar="[a]ddress",
        help="override the configured address of the network interface to listen on",
    )
    net_opts.add_argument(
        "-mtls",
        "--mutual-tls",
        metavar="[m]TLS",
        help="override the configured use of Mutual TLS (mTLS) secure communication",
    )
    net_opts.add_argument(
        "-ca",
        "--ca-certificate",
        metavar="[c]a",
        help="override the configured CA certificate",
    )
    net_opts.add_argument(
        "-key",
        "--private-key",
        metavar="[k]ey",
        help="override the configured private key",
    )
    net_opts.add_argument(
        "-cert",
        "--certificate",
        metavar="[c]ert",
        help="override the configured certificate",
    )
        
    db_opts = parser.add_argument_group("Database Options")
    db_opts.add_argument(
        "--database-location",
        metavar="[f]ile",
        help="override the location of the database using file f",
        type=str,
    )
    db_opts.add_argument(
        "--instance-location",
        metavar="[d]irectory",
        help=("override the configured instance storage location to directory d"),
        type=str,
    )
    db_opts.add_argument(
        "--clean",
        help=("remove all entries from the database and delete the " "corresponding stored instances"),
        action="store_true",
    )

    return parser.parse_args()


def main(args=None):
    """Run the application."""
    if args is not None:
        sys.argv = args

    args = _setup_argparser()

    if args.version:
        print(f"upsscp.py v{__version__}")
        sys.exit()

    APP_LOGGER = setup_logging(args, "upsscp")
    APP_LOGGER.debug(f"upsscp.py v{__version__}")
    APP_LOGGER.debug("")

    APP_LOGGER.debug("Using configuration from:")
    APP_LOGGER.debug(f"  {args.config}")
    APP_LOGGER.debug("")
    config = ConfigParser()
    config.read(args.config)

    if args.ae_title:
        config["DEFAULT"]["ae_title"] = args.ae_title
    if args.port:
        config["DEFAULT"]["port"] = args.port
    if args.max_pdu:
        config["DEFAULT"]["max_pdu"] = args.max_pdu
    if args.acse_timeout:
        config["DEFAULT"]["acse_timeout"] = args.acse_timeout
    if args.dimse_timeout:
        config["DEFAULT"]["dimse_timeout"] = args.dimse_timeout
    if args.network_timeout:
        config["DEFAULT"]["network_timeout"] = args.network_timeout
    if args.bind_address:
        config["DEFAULT"]["bind_address"] = args.bind_address
    if args.mutual_tls:
        config["DEFAULT"]["mutual_tls"] = args.mutual_tls
    if args.ca_certificate:
        config["DEFAULT"]["ca_certificate"] = args.ca_certificate
    if args.private_key:
        config["DEFAULT"]["private_key"] = args.private_key
    if args.certificate:
        config["DEFAULT"]["certificate"] = args.certificate
    if args.database_location:
        config["DEFAULT"]["database_location"] = args.database_location
    if args.instance_location:
        config["DEFAULT"]["instance_location"] = args.instance_location

    # Log configuration settings
    _log_config(config, APP_LOGGER)
    app_config = config["DEFAULT"]

    dests = {}
    for ae_title in config.sections():
        dest = config[ae_title]
        # Convert to bytes and validate the AE title
        ae_title = set_ae(ae_title, "ae_title", False, False)
        dests[ae_title] = (dest["address"], dest.getint("port"))

    # Use default or specified configuration file
    current_dir = os.path.abspath(os.path.dirname(__file__))
    instance_dir = os.path.join(current_dir, app_config["instance_location"])
    db_path = os.path.join(current_dir, app_config["database_location"])
    # The path to the database
    db_path = f"sqlite:///{db_path}"
    upsdb.create(db_path)

    # Clean up the database and storage directory
    if args.clean:
        response = input(
            "This will delete all instances from both the storage directory "
            "and the database. Are you sure you wish to continue? [yes/no]: "
        )
        if response != "yes":
            sys.exit()

        if clean(db_path, instance_dir, APP_LOGGER):
            sys.exit()
        else:
            sys.exit(1)

    # Try to create the instance storage directory
    os.makedirs(instance_dir, exist_ok=True)

    ae = AE(app_config["ae_title"])
    ae.maximum_pdu_size = app_config.getint("max_pdu")
    ae.acse_timeout = app_config.getfloat("acse_timeout")
    ae.dimse_timeout = app_config.getfloat("dimse_timeout")
    ae.network_timeout = app_config.getfloat("network_timeout")

    # Add supported presentation contexts
    # Verification SCP
    ae.add_supported_context(Verification, ALL_TRANSFER_SYNTAXES)

    # # Storage SCP - support all transfer syntaxes
    # for cx in AllStoragePresentationContexts:
    #     ae.add_supported_context(
    #         cx.abstract_syntax, ALL_TRANSFER_SYNTAXES, scp_role=True, scu_role=False
    #     )

    # # Query/Retrieve SCP
    # ae.add_supported_context(PatientRootQueryRetrieveInformationModelFind)
    # ae.add_supported_context(PatientRootQueryRetrieveInformationModelMove)
    # ae.add_supported_context(PatientRootQueryRetrieveInformationModelGet)
    # ae.add_supported_context(StudyRootQueryRetrieveInformationModelFind)
    # ae.add_supported_context(StudyRootQueryRetrieveInformationModelMove)
    # ae.add_supported_context(StudyRootQueryRetrieveInformationModelGet)

    # Unified Procedure Step SCP
    for cx in UnifiedProcedurePresentationContexts:
        ae.add_supported_context(cx.abstract_syntax, ALL_TRANSFER_SYNTAXES, scp_role=True, scu_role=False)

    APP_LOGGER.info(f"Configured for instance_dir = {instance_dir}")
    # Set our handler bindings
    handlers = [
        (evt.EVT_C_ECHO, handle_echo, [args, APP_LOGGER]),
        (evt.EVT_C_FIND, handle_find, [instance_dir, db_path, args, APP_LOGGER]),
        # (evt.EVT_C_GET, handle_get, [db_path, args, APP_LOGGER]),
        # (evt.EVT_C_MOVE, handle_move, [dests, db_path, args, APP_LOGGER]),
        # (evt.EVT_C_STORE, handle_store, [instance_dir, db_path, args, APP_LOGGER]),
        (evt.EVT_N_GET, handle_nget, [db_path, args, APP_LOGGER]),
        (evt.EVT_N_ACTION, handle_naction, [instance_dir, db_path, args, APP_LOGGER]),
        (evt.EVT_N_CREATE, handle_ncreate, [instance_dir, db_path, args, APP_LOGGER]),
        # (evt.EVT_N_EVENT_REPORT, handle_nevent, [db_path, args, APP_LOGGER]),
        (evt.EVT_N_SET, handle_nset, [db_path, args, APP_LOGGER]),
    ]

    # Configure mTLS secure communication
    ssl_cx = None
    if config.getboolean('DEFAULT', 'mutual_tls'):
        ca_cert = app_config["ca_certificate"]
        key, cert = app_config["private_key"], app_config["certificate"]
        try:
            # Create the SSLContext
            APP_LOGGER.debug(f"Creating SSL Context")
            ssl_cx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

            # Load the CA certificate
            ca_cert_path = Path(ca_cert).resolve()
            APP_LOGGER.debug(f"Loading Root CA certificate from {ca_cert_path}")
            with open(ca_cert_path, "rb") as pem_file:
                pem_data = pem_file.read()
                cert_info = x509.load_pem_x509_certificate(pem_data)
                APP_LOGGER.debug(f"CA certificate content:")
                APP_LOGGER.debug("  Subject: %s", cert_info.subject)
                APP_LOGGER.debug("  Issuer: %s", cert_info.issuer)
                APP_LOGGER.debug("  Validity Period: Not Before: %s, Not After: %s", cert_info.not_valid_before_utc, cert_info.not_valid_after_utc)
            ssl_cx.load_verify_locations(cafile=ca_cert_path)

            # Activate mutual TLS (mTLS) mode, requiring client certificates for authentication
            APP_LOGGER.debug(f"Activated mutual authentication")
            ssl_cx.verify_mode = ssl.CERT_REQUIRED
            
            # Load our certificate and private key
            cert_path, key_path = Path(cert).resolve(), Path(key).resolve()
            APP_LOGGER.debug(f"Loading our certificate from {cert_path}")
            with open(cert_path, "rb") as pem_file:
                pem_data = pem_file.read()
                cert_info = x509.load_pem_x509_certificate(pem_data)
                APP_LOGGER.debug(f"Our certificate content:")
                APP_LOGGER.debug("  Subject: %s", cert_info.subject)
                APP_LOGGER.debug("  Issuer: %s", cert_info.issuer)
                APP_LOGGER.debug("  Validity Period: Not Before: %s, Not After: %s", cert_info.not_valid_before_utc, cert_info.not_valid_after_utc)
            APP_LOGGER.debug(f"Loading our private key from {key_path}")
            with open(key_path, "rb") as pem_file:
                pem_data = pem_file.read()
            try:
                private_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
                key_type = type(private_key).__name__.replace("PrivateKey", "")
                APP_LOGGER.debug("Our private key is %s-%s", key_type, private_key.key_size) 
            except Exception as e:
                APP_LOGGER.error("Invalid private key: %s", e)
                exit(1)  
            ssl_cx.load_cert_chain(certfile=cert, keyfile=key)

            # Set the minimum and maximum TLS version
            APP_LOGGER.debug("Setting minimum TLS version to TLS 1.2")
            ssl_cx.minimum_version = ssl.TLSVersion.TLSv1_2
            APP_LOGGER.debug("Setting maximum TLS version to TLS 1.3")
            ssl_cx.maximum_version = ssl.TLSVersion.TLSv1_3
            
            APP_LOGGER.info("mTLS secure connection configuration successful")
        except (ssl.SSLError, IOError) as e:
            APP_LOGGER.error(f"Error creating mTLS secure connection configuration: {e}")
            exit(1)

    # Listen for incoming association requests
    ae.start_server((app_config["bind_address"], app_config.getint("port")), evt_handlers=handlers, ssl_context=ssl_cx)


if __name__ == "__main__":
    main()
