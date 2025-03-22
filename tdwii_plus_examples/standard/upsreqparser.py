import argparse
import logging
import os
import sys
from tdwii_plus_examples.standard.dicom_attribute_model import DICOMAttributeModel

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


def _find_include_id(tr_elements):
    target_found = False
    for tr in tr_elements:
        first_td = tr.find('td')
        if first_td and first_td.get_text(strip=True) == '>Output Information Sequence':
            logger.debug("Target <tr> found")
            target_found = True
            break

    if target_found:
        tr = tr.find_next('tr')
        first_td = tr.find('td')
        if first_td and first_td.get_text(strip=True).startswith('>Include'):
            logger.debug("Next <tr> with required starting value found")
            return first_td.find('a')['id']

    return None


def patch_output_info(attribute_model, dom, table_id):
    outputinfoseq_include_id = find_outputinfoseq_include(attribute_model, dom, table_id)
    if not outputinfoseq_include_id:
        logger.warning("Include ID not found")
        return

    element = dom.find(id=outputinfoseq_include_id).find_parent()
    span_element = element.find('span', class_='italic')
    if span_element:
        for child in span_element.children:
            if isinstance(child, str) and '>Include' in child:
                new_text = child.replace('>Include', '>>Include')
                child.replace_with(new_text)


def find_outputinfoseq_include(attribute_model, dom, table_id):
    table = attribute_model.get_table(dom, table_id)
    if not table:
        return None

    logger.debug(f"Table with id {table_id} found")
    tr_elements = table.find_all('tr')
    include_id = _find_include_id(tr_elements)

    if include_id is None:
        logger.debug("No matching <tr> found")

    return include_id


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
    parser.add_argument("-i", "--include-depth", type=int, default=0, help="Recursion depth for including referenced tables")

    args = parser.parse_args()

    configure_logging(args)

    attribute_model = DICOMAttributeModel(logger=logger, additional_columns_attributes=[(2, "ncreate"), (3, "nset")])
    if not os.path.exists(UPS_PS3_4_CC_2_5_FILE):
        file_path = attribute_model.download_xhtml(UPS_REQ_URL, UPS_PS3_4_CC_2_5_FILE)
    else:
        file_path = UPS_PS3_4_CC_2_5_FILE
    dom = attribute_model.read_xhtml_dom(file_path)

    patch_output_info(attribute_model, dom, UPS_REQ_TABLE_ID)

    # dom = attribute_model.patch_text_in_element(dom, outputinfoseq_include_id, old_text, f">{old_text}")
    attribute_model.parse_table(dom, UPS_REQ_TABLE_ID, include_depth=args.include_depth)
    attribute_model.print_tree()
    attribute_model.print_table()

    json_file_path = f"{os.path.splitext(UPS_PS3_4_CC_2_5_FILE)[0]}.json"
    attribute_model.save_as_json(json_file_path)


if __name__ == "__main__":
    main()
