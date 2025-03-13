#!/usr/bin/env python3

import os
import json
import yaml
from datetime import datetime
import logging

# Logging Setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Locate the graphql_templates.yaml configuration file
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEBUG_FOLDER = os.path.join(ROOT_DIR, "debug", "imported_nautobot_data")
GRAPHQL_FILE = os.path.join(SCRIPT_DIR, "config/graphql_templates.yaml")

# Load all GraphQL templates once at startup
try:
    with open(GRAPHQL_FILE, "r", encoding="utf-8") as f:
        gql_templates = yaml.safe_load(f)
except FileNotFoundError:
    logger.error(f"GraphQL templates file not found at {GRAPHQL_FILE}")
    raise
except yaml.YAMLError as e:
    logger.error(f"Invalid YAML in '{GRAPHQL_FILE}': {e}")
    raise


def collect_nautobot_data(connect, debug=False):
    """
    Connect to Nautobot, retrieve VM data, return as a Python dict in memory.
    If debug=True, also writes imported_nautobot_data/nautobot_vms_{timestamp}.json
    """

    # Use the query from YAML
    vms_graphql_filter = gql_templates["collect_nautobot_data"]
    ntb_vms = connect.get_graphql_info(graphql_filter=vms_graphql_filter).json()

    if debug:
        os.makedirs(DEBUG_FOLDER, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"nautobot_vms_{ts}.json"
        outpath = os.path.join(DEBUG_FOLDER, fname)
        try:
            with open(outpath, "w", encoding="utf-8") as file_to_save:
                json.dump(ntb_vms, file_to_save, indent=4)
            logger.info(f"Debug data saved: {outpath}")
        except IOError as error:
            logger.error(f"Failed to write debug history to {outpath}: {str(error)}")
        except json.JSONEncodeError as error:
            logger.error(f"Failed to encode diff data as JSON for debug history: {str(error)}")
        except Exception as error:
            logger.error(f"Unexpected error writing debug history: {str(error)}")

    return ntb_vms


def collect_nautobot_data_by_vcenter(connect, vcenter_name, debug=False):
    """
    Retrieve VM data from Nautobot filtered by the specified vCenter name.

    Args:
        connect: Nautobot connection instance
        vcenter_name (str): vCenter name to filter by
        debug (bool, optional): When True, save retrieved data to debug folder. Defaults to False.

    Returns:
        dict: VM data from Nautobot filtered by vCenter name
    """

    # Format the GraphQL query with the vcenter_name as a filter parameter
    vms_graphql_filter = gql_templates["collect_nautobot_data_by_vcenter"] % vcenter_name
    ntb_vms = connect.get_graphql_info(graphql_filter=vms_graphql_filter).json()

    if debug:
        os.makedirs(DEBUG_FOLDER, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"{vcenter_name}_nautobot_vms_{ts}.json"
        outpath = os.path.join(DEBUG_FOLDER, fname)

        try:
            with open(outpath, "w", encoding="utf-8") as file_to_save:
                json.dump(ntb_vms, file_to_save, indent=4)
            logger.info(f"[get_nautobot_vms] (debug) Wrote Nautobot data => {outpath}")
        except IOError as error:
            logger.error(f"Failed to write debug history to {outpath}: {str(error)}")
        except json.JSONEncodeError as error:
            logger.error(f"Failed to encode diff data as JSON for debug history: {str(error)}")
        except Exception as error:
            logger.error(f"Unexpected error writing debug history: {str(error)}")

    return ntb_vms


def collect_vcenter_clusters(connect):
    """
    Retrieve all cluster data from Nautobot.

    Args:
        connect: Nautobot connection instance

    Returns:
        dict: All cluster data from Nautobot
    """

    # Use the clusters query from YAML
    cluster_graphql_filter = gql_templates["collect_vcenter_clusters"]
    ntb_clusters = connect.get_graphql_info(graphql_filter=cluster_graphql_filter).json()

    return ntb_clusters


def collect_vcenter_datacenters(connect):
    """
    Retrieve all datacenter (cluster group) data from Nautobot.

    Args:
        connect: Nautobot connection instance

    Returns:
        dict: All datacenter data from Nautobot
    """

    # Use the datacenters query from YAML
    datacenter_graphql_filter = gql_templates["collect_vcenter_datacenters"]
    ntb_datacenters = connect.get_graphql_info(graphql_filter=datacenter_graphql_filter).json()

    return ntb_datacenters
