import argparse
import logging
import os
import sys

from tdwii_plus_examples.standard.ups_attribute_model import UPSAttributeModel

# Configure the logger at the module level
logger = logging.getLogger(os.path.basename(sys.argv[0]))

fdir = os.path.abspath(os.path.dirname(__file__))
REF_DIR = os.path.join(fdir, "../../ref")
UPS_PS3_4_CC_2_5_FILE = os.path.join(REF_DIR, "PS3_4_CC.2.5.html")
UPS_REQ_URL = "https://dicom.nema.org/medical/dicom/current/output/chtml/part04/sect_CC.2.5.html"
UPS_REQ_TABLE_ID = "table_CC.2.5-3"


def find_project_root(current_path, marker_file="pyproject.toml"):
    """
    Finds the project root directory by looking for the presence of a marker
    file (default is 'pyproject.toml') in the directory tree.

    Parameters:
    ----------
        current_path (str): The current path to start searching from.
        marker_file (str, optional): The file name to look for in each directory.
            Defaults to 'pyproject.toml'.
    Returns:
    -------
        str: The path to the project root directory if found, otherwise None.
    """
    while current_path != os.path.dirname(current_path):
        if marker_file in os.listdir(current_path):
            return current_path
        current_path = os.path.dirname(current_path)
    return None


def setup_logging(log_level=logging.DEBUG):
    # Set the logs directory at the top level of the project
    current_script_dir = os.path.dirname(__file__)
    project_root = find_project_root(current_script_dir)
    if project_root is None:
        raise RuntimeError("Project root not found. Make sure 'pyproject.toml' exists at the top level of your project.")

    logs_path = os.path.join(project_root, "logs")
    if not os.path.exists(logs_path):
        os.makedirs(logs_path)

    # Configure log level
    logger.setLevel(log_level)

    # Create a console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # Create a file handler with UTF-8 encoding
    logfile_name = os.path.join(logs_path, "extract_ups_attr_req.log")
    file_handler = logging.FileHandler(logfile_name, encoding="utf-8")
    file_handler.setLevel(log_level)

    # Create formatters and add them to handlers
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add handlers to the logger
    if not logger.handlers:
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)


def configure_logging(args):
    log_level = logging.WARNING
    if args.verbose:
        log_level = logging.INFO
    elif args.debug:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.ERROR
    setup_logging(log_level)


def main():
    parser = argparse.ArgumentParser(description="DICOM UPS Attributes Requirements parser.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (info level)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output (debug level)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress all output (quiet mode)")
    parser.add_argument("-ta", "--table", action="store_true", help="Print requirements as a flat ASCII table")
    parser.add_argument("-tr", "--tree", action="store_true", help="Print attributes as an ASCII tree")
    parser.add_argument("-c", "--colorize", action="store_true", help="Colorize the ASCII output by level of nesting")
    parser.add_argument("-i", "--include-depth", type=int, default=0, help="Recursion depth for including referenced tables")
    parser.add_argument(
        "-di",
        "--dimse",
        type=str,
        choices=["N-CREATE", "N-SET", "N-GET", "C-FIND", "FINAL"],
        default=None,
        help="Select DIMSE Service",
    )
    parser.add_argument(
        "-r",
        "--role",
        type=str,
        choices=["SCU", "SCP"],
        default=None,
        help="Select Role of DIMSE Service User (requires --dimse to be set)",
    )
    args = parser.parse_args()

    if args.role is not None and not args.dimse:
        parser.error("--role requires --dimse to be set")

    configure_logging(args)

    # attribute_model = DICOMAttributeModel(logger=logger, additional_columns_attributes=[(2, "ncreate"), (3, "nset")])
    attribute_model = UPSAttributeModel(include_depth=args.include_depth, logger=logger)
    attribute_model.select_dimse(args.dimse)
    attribute_model.select_role(args.role)

    if args.tree:
        attribute_model.print_tree(colorize=args.colorize)
    if args.table:
        attribute_model.print_table(colorize=args.colorize)


if __name__ == "__main__":
    main()
