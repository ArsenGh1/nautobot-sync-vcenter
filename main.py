#!/usr/bin/env python3
"""
main.py

A script to collect VM information from multiple vCenter servers and
compare or synchronize it with data in Nautobot.

Default Behavior:
----------------
If no arguments are provided (and --dry-run isn't set), the script automatically
synchronizes data to Nautobot without prompting for confirmation.

Options:
--------
--safe / -s:
    Prompts the user ("Y/y") to confirm synchronization before making any changes.

--dry-run / -d:
    Performs the vCenter data collection and comparison steps, but does not make
    any changes (sync) to Nautobot.

--debug:
    Enables debug mode, which saves intermediate artifacts to disk (CSV/YAML).

--help / -h:
    Shows all available arguments with their descriptions and exits.
"""

import argparse
import csv
import getpass
import logging
import os
import sys
import yaml
import concurrent.futures
from pathlib import Path

# Local/Custom Imports
from compare_nautobot_vsphere import compare_nautobot_vsphere
import nautobot.config_nautobot as config_nautobot
from nautobot.get_nautobot_vms import (
    collect_nautobot_data_by_vcenter,
    collect_vcenter_clusters,
    collect_vcenter_datacenters
)

from nautobot.nautobot_SDK import nautobot

# Import from the new vmware_collector module
from vmware_collector import (
    gather_vm_info_in_memory,
    gather_dc_cluster_info
)

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Load and parse YAML configuration files safely
def load_yaml_file(filepath: Path):
    try:
        with filepath.open("r", encoding="utf-8") as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}. Please ensure it is present.")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse {filepath}. Invalid YAML syntax. Error: {e}")
        sys.exit(1)


# Identify root directory based on script location
ROOT_DIR = Path(__file__).resolve().parent

# Paths to YAML configuration files
env_file = ROOT_DIR / "settings.yaml"
custom_fields_file = ROOT_DIR / "nautobot" / "config" / "custom_fields.yaml"

# Load the YAML files using the helper function
env_data = load_yaml_file(env_file)
custom_fields_data = load_yaml_file(custom_fields_file)

# Extract vCenter auth type
use_env_for_vcenter = env_data.get("USE_ENV_FOR_VCENTER_CREDENTIALS", False)

# Extract Nautobot URL
NTB_URL = env_data["NAUTOBOT_URL"]

# Check environment variable first for Nautobot token
NTB_TOKEN = os.getenv("NAUTOBOT_TOKEN")

if not NTB_TOKEN:
    # Load settings.yaml if env var is not set
    NTB_TOKEN = env_data.get("NAUTOBOT_TOKEN")
    if not NTB_TOKEN:
        logger.error("NAUTOBOT_TOKEN not found in environment or settings.yaml. Please set it and try again.")
        sys.exit(1)
    else:
        logger.info("Using NAUTOBOT_TOKEN from settings.yaml.")
else:
    logger.info("Using NAUTOBOT_TOKEN from environment variable.")

# Custom fields loaded from a dedicated YAML file
CUSTOM_FIELDS = custom_fields_data["ntb_custom_fields"]
DEFAULT_VCENTERS = env_data["vCenters"]
CLUSTER_TYPE = env_data["CLUSTER_TYPE"]

# Define the output directory relative to the project root
OUTPUT_DIR = ROOT_DIR / "debug" / "imported_data_vcenter"

# Establish connection to Nautobot API
connect = nautobot(Token=NTB_TOKEN, URL=NTB_URL)


def get_args():
    """
    Parse and return CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="Collect VM info from vCenter(s) and compare to Nautobot.",
        add_help=False
    )
    parser.add_argument(
        '-h', '--help',
        action='help',
        default=argparse.SUPPRESS,
        help="Show this help message and exit."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode: save intermediate artifacts to disk."
    )
    parser.add_argument(
        "-s", "--safe",
        action="store_true",
        help="Run in 'safe' mode, prompting before making any changes to Nautobot."
    )
    parser.add_argument(
        "-d", "--dry-run",
        action="store_true",
        help="Run in 'dry-run' mode; gather and compare data but do not sync."
    )
    return parser.parse_args()


def get_vcenter_credentials(env_var_for_vcenter=False):
    """Retrieve vCenter credentials from environment variables or user input."""

    if env_var_for_vcenter:
        username = os.getenv("VCENTER_USERNAME")
        password = os.getenv("VCENTER_PASSWORD")
        if not username or not password:
            logger.error("VCENTER_USERNAME or VCENTER_PASSWORD not set in environment.")
            sys.exit(1)
        logger.info("Using vCenter credentials from environment variables.")
    else:
        logger.info("Using manually entered vCenter credentials.")
        username = input("Enter vCenter username: ")
        password = getpass.getpass("Enter vCenter password: ")
    return username, password


def write_debug_files_for_vcenter(vcenter_name, vcenter_data_dict):
    """
    If debug is enabled, write CSV and YAML files for the provided vCenter data.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    csv_rows = []
    yaml_key = f"{vcenter_name}_vms"
    yaml_data = {yaml_key: []}

    for uuid, vm_info in vcenter_data_dict.items():
        vm_name = vm_info["name"]
        powered_on = vm_info["powered_on"]
        datacenter_name = vm_info["datacenter_name"]
        cluster_name = vm_info["cluster_name"]

        # Gather VM IP addresses for CSV/YAML output
        all_ips = []
        for ni in vm_info["network_interfaces"]:
            for iface in ni["interfaces"]:
                all_ips.extend(iface["ip_addresses"])
        ip_str = ", ".join(sorted(all_ips)) if all_ips else "N/A"

        # Use "Unknown" for missing port groups to ensure CSV compatibility
        all_pg = [ni["port_group"] for ni in vm_info["network_interfaces"] if ni["port_group"]]
        port_groups_csv = ", ".join(all_pg) if all_pg else "N/A"

        # Prepare row for CSV
        csv_rows.append([
            vm_name,
            datacenter_name,
            cluster_name,
            uuid,
            ip_str,
            port_groups_csv
        ])

        # Prepare data for YAML
        yaml_data[yaml_key].append({
            "name": vm_name,
            "uuid": uuid,
            "powered_on": powered_on,
            "datacenter_name": datacenter_name,
            "cluster_name": cluster_name,
            "network_interfaces": vm_info["network_interfaces"]
        })

    # Write CSV file
    csv_path = OUTPUT_DIR / f"{vcenter_name}.csv"
    try:
        with open(csv_path, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["VM Name", "Datacenter", "Cluster", "UUID", "IPv4 (CIDR)", "Port Groups"]
            )
            writer.writerows(csv_rows)
        logger.info(f"[DEBUG] Wrote CSV: {csv_path.as_posix()}")
    except Exception as error_to_log:
        logger.error(f"[ERROR] writing CSV: {error_to_log}")

    # Write YAML file
    yaml_path = OUTPUT_DIR / f"{vcenter_name}.yaml"
    try:
        with open(yaml_path, "w", encoding="utf-8") as yf:
            yaml.dump(yaml_data, yf, sort_keys=False)
        logger.info(f"[DEBUG] Wrote YAML: {yaml_path.as_posix()}")
    except Exception as error_to_log:
        logger.error(f"[ERROR] writing YAML: {error_to_log}")


def write_debug_merged_yaml(all_vcenters_data):
    """
    In debug mode, create merged YAML file with data from all vCenters
    """
    merged_yaml = {"all_vcenters": {}}

    for vc_name, vc_dict in all_vcenters_data.items():
        key = f"{vc_name}_vms"
        merged_yaml["all_vcenters"][key] = []
        for uuid, vm_info in vc_dict.items():
            merged_yaml["all_vcenters"][key].append({
                "name": vm_info["name"],
                "uuid": uuid,
                "powered_on": vm_info["powered_on"],
                "datacenter_name": vm_info["datacenter_name"],
                "cluster_name": vm_info["cluster_name"],
                "network_interfaces": vm_info["network_interfaces"]
            })

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    merged_file_path = OUTPUT_DIR / "all_vcenters_merged.yaml"
    try:
        with open(merged_file_path, "w", encoding="utf-8") as mf:
            yaml.dump(merged_yaml, mf, sort_keys=False)
        logger.info(f"[DEBUG] Wrote merged YAML -> {merged_file_path.as_posix()}")
    except Exception as error_to_log:
        logger.error(f"[ERROR] writing merged YAML: {error_to_log}")

    return merged_file_path


def collect_vcenter_data(vcenters, username, password, debug_mode):
    """
    Collect VM data from all specified vCenters in parallel.

    Args:
        vcenters (list): List of vCenter configurations.
        username (str): vCenter username.
        password (str): vCenter password.
        debug_mode (bool): Whether to write debug files.

    Returns:
        dict: Mapping of vCenter names to their collected data.
    """
    vcenter_data_map = {}
    # Use ThreadPoolExecutor to collect data from multiple vCenters concurrently

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Create futures for concurrent vCenter data collection
        future_map = {executor.submit(gather_vm_info_in_memory, vc['url'], username, password): vc['name'] for vc in vcenters}
        for fut in concurrent.futures.as_completed(future_map):
            vc_name = future_map[fut]
            vc_dict = fut.result()
            if vc_dict:
                vcenter_data_map[vc_name] = vc_dict
                if debug_mode:
                    # Write debug files if debug mode is enabled
                    write_debug_files_for_vcenter(vcenter_name=vc_name, vcenter_data_dict=vc_dict)
            else:
                logger.warning(f"Skipping vCenter '{vc_name}' due to empty data.")
    return vcenter_data_map


def sync_vcenter_data(vcenter_name, vsphere_data, cluster_type, debug_mode, safe_mode, dry_run):
    """
    Handle synchronization for a single vCenter: create missing cluster groups/clusters,
    compare data, and sync to Nautobot.

    Args:
        vcenter_name (str): vCenter hostname.
        vsphere_data (dict): Collected vSphere data for this vCenter.
        cluster_type (str): Cluster type for Nautobot.
        debug_mode (bool): Enable debug logging and file output.
        safe_mode (bool): Prompt for confirmation before syncing.
        dry_run (bool): Skip actual syncing.

    Returns:
        dict or None: Warnings from sync (or empty dict), or None if syncing is skipped due to errors.
    """
    dc_clusters = gather_dc_cluster_info(vsphere_data)

    # Collect existing Nautobot data for cluster groups and clusters
    datacenters = [dc["name"] for dc in collect_vcenter_datacenters(connect)["data"]["cluster_groups"]]
    clusters = [c["name"] for c in collect_vcenter_clusters(connect)["data"]["clusters"]]

    # Create missing cluster groups
    for dc in dc_clusters["datacenters"]:
        if dc not in datacenters:
            logger.info(f"Creating cluster group '{dc}'...")
            if not dry_run:
                if not config_nautobot.config_ntb_cluster_group(dc, vcenter_name):
                    logger.error(f"Failed to create cluster group '{dc}' for vCenter '{vcenter_name}'.")
                    return None  # Skip syncing for this vCenter
            else:
                logger.info(f"DRY RUN: Would create '{dc}'.")

    # Create missing clusters
    for cluster in dc_clusters["clusters"]:
        if cluster not in clusters:
            logger.info(f"Creating cluster '{cluster}'...")
            if not dry_run:
                if not config_nautobot.config_ntb_cluster(
                        cluster, cluster_type, dc_clusters["cluster_to_datacenter"][cluster], vcenter_name
                ):
                    logger.error(f"Failed to create cluster '{cluster}' for vCenter '{vcenter_name}'.")
                    return None  # Skip syncing for this vCenter
            else:
                logger.info(f"DRY RUN: Would create '{cluster}'.")

    # Collect Nautobot VM data for comparison
    nautobot_data = collect_nautobot_data_by_vcenter(connect, vcenter_name, debug_mode)

    # Compare vSphere data with Nautobot data
    diff, comp_file = compare_nautobot_vsphere(
        vsphere_data=vsphere_data,
        nautobot_data=nautobot_data,
        vcenter_name=vcenter_name,
        debug_mode=debug_mode
    )
    logger.info(f"Comparison for {vcenter_name} -> {comp_file}")

    if dry_run:
        # Log what would be done in dry-run mode
        logger.info(f"DRY RUN: For vCenter '{vcenter_name}', would add {len(diff.get('add', []))}, update {len(diff.get('update', []))}, delete {len(diff.get('delete', []))} VMs.")
        return {}

    if safe_mode:
        # Prompt user for confirmation in safe mode
        user_input = input(f"Sync '{vcenter_name}' (view {comp_file})? [Y/y]: ")
        if user_input.lower() != "y":
            logger.info(f"User canceled sync for '{vcenter_name}'.")
            return {}

    # Sync vSphere VM data into Nautobot
    logger.info(f"Syncing data for '{vcenter_name}'...")
    warnings = config_nautobot.config_vms(vcenter_name=vcenter_name, data_to_config=diff, safe_mode=safe_mode, debug_mode=debug_mode)
    return warnings or {}


def process_syncing(debug_mode, safe_mode, dry_run, vcenter_user, vcenter_password):
    """
    Orchestrate the multi-vCenter synchronization process.

    Args:
        debug_mode (bool): Enable debug logging and file output.
        safe_mode (bool): Prompt for confirmation before syncing.
        dry_run (bool): Skip actual syncing.
        vcenter_user (str): vCenter username
        vcenter_password (str): vCenter password
    """
    vcenter_data_map = collect_vcenter_data(DEFAULT_VCENTERS, vcenter_user, vcenter_password, debug_mode)
    if not vcenter_data_map:
        logger.error("No valid vCenter data collected. Exiting.")
        sys.exit(1)

    if not config_nautobot.ensure_nautobot_prerequisites(CLUSTER_TYPE, CUSTOM_FIELDS, dry_run, debug_mode):
        sys.exit(1)

    all_warnings = {}
    error_vcenters = []
    for vc_host, vc_data in vcenter_data_map.items():
        warnings = sync_vcenter_data(vcenter_name=vc_host, vsphere_data=vc_data, cluster_type=CLUSTER_TYPE, debug_mode=debug_mode, safe_mode=safe_mode, dry_run=dry_run)
        if warnings is None:
            error_vcenters.append(vc_host)
        else:
            all_warnings.update(warnings)

    if debug_mode and vcenter_data_map:
        write_debug_merged_yaml(vcenter_data_map)

    # Summarize results of synchronization
    total_vcenters = len(vcenter_data_map)
    processed_vcenters = total_vcenters - len(error_vcenters)
    logger.info(f"Processed {processed_vcenters} out of {total_vcenters} vCenters successfully.")
    if error_vcenters:
        logger.warning(f"Encountered errors with {len(error_vcenters)} vCenters: {', '.join(error_vcenters)}")
    if all_warnings:
        logger.warning(f"Warning objects to review: {all_warnings}")

    logger.info("Script execution complete")


def main():
    """
    Main entry point for the script.
    """
    args = get_args()
    debug_mode = args.debug
    safe_mode = args.safe
    dry_run = args.dry_run

    if safe_mode and dry_run:
        logger.error("You can't use both --safe and --dry-run at the same time.")
        sys.exit()

    # Indicate the mode(s)
    logger.info(
        "Running script with the following modes:"
        f" debug={debug_mode}, safe={safe_mode}, dry_run={dry_run}"
    )

    # Get vCenter credentials
    vcenter_user, vcenter_password = get_vcenter_credentials(env_var_for_vcenter=use_env_for_vcenter)

    process_syncing(debug_mode, safe_mode, dry_run, vcenter_user, vcenter_password)


if __name__ == "__main__":
    main()