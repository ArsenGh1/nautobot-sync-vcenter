#!/usr/bin/env python3
"""
A script for configuring Nautobot objects (VMs, interfaces, IP addresses)
based on data collected from vCenter and diffed in the main vm_info workflow.
"""

import sys
import json
import logging
from datetime import datetime
import os
import ipaddress

import yaml

# Local/Custom Imports
from .nautobot_SDK import nautobot

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global Warnings Dictionary
warning_dict = {
    "duplicate_ips": [],
    "vm_warnings": [],
    "vm_interface_warnings": [],
    "vm_ip_to_int_warnings": [],
    "duplicate_vm_id": []
}

# Locate and load the settings.yaml configuration file
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(SCRIPT_DIR, "../settings.yaml")

try:
    with open(ENV_FILE, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)
except FileNotFoundError:
    logger.error(f"{ENV_FILE} file not found. Please ensure it is present in the project root.")
    sys.exit(1)
except yaml.YAMLError as e:
    logger.error(f"Failed to parse {ENV_FILE}. Invalid YAML syntax. Error: {e}")
    sys.exit(1)

# Extract Nautobot URL
NTB_URL = data["NAUTOBOT_URL"]

# Check environment variable first for Nautobot token
NTB_TOKEN = os.getenv("NAUTOBOT_TOKEN")

if not NTB_TOKEN:
    # Load settings.yaml if env var is not set
    NTB_TOKEN = data.get("NAUTOBOT_TOKEN")
    if not NTB_TOKEN:
        logger.error("NAUTOBOT_TOKEN not found in environment or settings.yaml. Please set it and try again.")
        sys.exit(1)


connect = nautobot(Token=NTB_TOKEN, URL=NTB_URL)


class NautobotSyncError(Exception):
    """
    Raised when a critical synchronization error occurs, requiring an early exit
    or higher-level handling in the caller.
    """
    pass


def is_field_configured(existing_field, desired_field):
    """
    Check if an existing custom field in Nautobot matches our desired specification.

    :param existing_field: Data structure from Nautobot describing the current field.
    :param desired_field: Our desired custom field definition (dict).
    :return: True if the field’s keys, type, and content_types match.
    """
    key_matches = existing_field.get("key") == desired_field.get("key")
    type_matches = existing_field.get("type", {}).get("value") == desired_field.get("type")
    content_types_matches = all(
        item in existing_field["content_types"] for item in desired_field["content_types"]
    )
    return key_matches and type_matches and content_types_matches


def configure_custom_field(field, debug=False):
    """
    Ensure custom field is present and correctly configured in Nautobot.
    Creates it if missing, or validates if it already exists.

    :param field: Desired custom field definition (dict).
    :param debug: If True, logs extra info about creation steps.
    :return: True if field is correctly in place, False on error.
    """
    response = connect.get_custom_fields(custom_field_name=field["label"])
    count = response.get("count", 0)

    if count == 0:
        if debug:
            logger.info(f"Creating custom field: {field['label']}")
        create_resp = connect.config_custom_field(custom_field_data=field)
        if create_resp.status_code == 201:
            logger.info(f"Custom field {field['label']} created successfully.")
            return True
        else:
            logger.error(f"Failed to create {field['label']}. Error: {create_resp}")
            return False
    elif count == 1:
        existing_field = response["results"][0]
        if is_field_configured(existing_field, field):
            if debug:
                logger.info(f"{field['label']} custom field has already configured in nautobot.")
            return True
        else:
            logger.error(
                f"{field['label']} exists but with a mismatched configuration. Please review manually or delete and re-run the script.")
            return False
    else:
        logger.error(f"Multiple {field['label']} fields found. Please check manually and remove duplicates.")
        return False


def handle_custom_fields(custom_fields, debug=False):
    """
    Loop over a list of desired custom fields and ensure each is configured.

    :param custom_fields: A list of custom-field dicts describing each needed field.
    :param debug: If True, logs extra info during creation steps.
    :return: True if all fields are configured, False if any fail.
    """
    all_configured = True
    for field in custom_fields:
        if not configure_custom_field(field, debug=debug):
            all_configured = False

    if all_configured:
        logger.info("All custom fields are properly configured.")
    else:
        logger.error("Some custom fields are not configured as expected. Please review the messages above.")
    return all_configured


def handle_ntb_cluster_type(ntb_cluster_type):
    """
    Ensure a specified cluster type exists in Nautobot, create it if not found.

    :param ntb_cluster_type: Name of the cluster type to verify/create.
    :return: True if exists or was created successfully, False on error.
    """
    get_cluster_type_info = connect.get_cluster_type(cluster_type=ntb_cluster_type)
    if get_cluster_type_info["count"] == 1:
        return True

    logger.info(f"Cluster Type {ntb_cluster_type} doesn't exists in Nautobot, we should create it")
    cluster_type_data = {
        "name": ntb_cluster_type,
        "description": "This cluster type has created automatically",
    }
    config_cluster_type = connect.create_cluster_type(cluster_type_data=cluster_type_data)
    if config_cluster_type.status_code == 201:
        logger.info(f"Cluster type {ntb_cluster_type} has created successfully")
        return True
    else:
        logger.error(f"{config_cluster_type} - {config_cluster_type.json()}")
        return False


def ensure_nautobot_prerequisites(cluster_type, custom_fields, dry_run, debug_mode):
    """
    Ensure Nautobot has the required cluster type and custom fields.

    Args:
        cluster_type (str): Cluster type to check/create.
        custom_fields (dict): Custom fields to check/create.
        dry_run (bool): Whether to skip changes.
        debug_mode (bool): Enable debug logging.

    Returns:
        bool: True if successful or dry-run, False if prerequisites fail.
    """
    if dry_run:
        logger.info("DRY RUN: Skipping Nautobot prerequisite checks.")
        return True
    if not handle_ntb_cluster_type(ntb_cluster_type=cluster_type):
        logger.error("Failed to check/create cluster type.")
        return False
    if not handle_custom_fields(custom_fields=custom_fields, debug=debug_mode):
        logger.error("Failed to check/create custom fields.")
        return False
    return True


def get_network_prefix(ip_str):
    """
    Utility to parse 'ip_str' (which might be '10.10.10.10/24' or just '10.10.10.10')
    and return the canonical network, e.g. '10.10.10.0/24'.

    If there's no mask, assume /32.

    :param ip_str: The IP string, possibly with or without a CIDR mask.
    :return: e.g., "10.10.10.0/24""
    """
    if "/" not in ip_str:
        try:
            ip_obj = ipaddress.ip_interface(ip_str + "/32")
        except ValueError:
            # If that fails, likely IPv6 => assume /128
            ip_obj = ipaddress.ip_interface(ip_str + "/128")
    else:
        ip_obj = ipaddress.ip_interface(ip_str)

    # ip_obj.network is something like IPv4Network('10.10.10.0/24')
    return str(ip_obj.network)


def create_ip_and_prefix_if_needed(int_ip, uuid_mappings, prefix_cache, debug_mode=False):
    """
    Ensure the prefix and IP exist in Nautobot for a given IP (w/ mask). If the prefix
    is missing, it is created. If the IP is missing, it is also created.

    :param int_ip: The IP address string (with or without mask).
    :param uuid_mappings: Contains 'status' mappings for 'Active' or other statuses.
    :param prefix_cache: In-memory dict used to cache newly created or found prefixes.
    :param debug_mode: Whether to log extra debug messages.
    :return: (was_created, ip_id_or_none)
      • was_created (bool): True if a new IP was created, False if it existed or failed.
      • ip_id_or_none: The UUID of the IP in Nautobot or None if creation failed.
    """
    # Derive the canonical prefix from int_ip
    prefix_key = get_network_prefix(int_ip)

    # Ensure IP prefix exists in Nautobot; create if missing
    if prefix_key not in prefix_cache:
        # First we will try to get the exact prefix from nautobot
        check_exact_prefix = connect.get_exact_prefix(prefix=prefix_key)
        if check_exact_prefix["count"] == 1:
            pref = check_exact_prefix["results"][0]
            prefix_cache[prefix_key] = {
                "found": True,
                "id": pref["id"],
                "namespace": pref["namespace"]["id"]
            }
        else:
            # If the exact prefix not there, we will try to get broader prefix
            # and log a warning about it
            logger.warning(f"Couldn't find the exact prefix` {prefix_key} in Nautobot")
            check_broader_prefix = connect.get_prefixes(prefix_key)
            if check_broader_prefix["count"] > 0:
                # Broader prefix found. Not ideal, but we will go further
                logger.info(f"{int_ip} IP address will be created under {check_broader_prefix['results'][0]['prefix']} prefix")
                pref = check_broader_prefix["results"][0]
                prefix_cache[prefix_key] = {
                    "found": True,
                    "id": pref["id"],
                    "namespace": pref["namespace"]["id"]
                }
            else:
                logger.warning(f"No exact or broader prefix found for {prefix_key}; new subnet will be created")
                if debug_mode:
                    logger.info(f"The subnet {prefix_key} does not exists. We will create it.")
                try:
                    req_namespace = connect.get_namespace_id("Global")
                    if req_namespace["count"] != 1:
                        logger.error(f"We got multiple Global namespace output for some reason. So {prefix_key} prefix creation has failed")
                        return False, None
                except NautobotAPIError as ntb_error:
                    logger.error(f"Error: {ntb_error}")
                    logger.error(f"We couldn't get Global namespace id, so {prefix_key} prefix creation has failed")
                    return False, None
                global_namespace_id = req_namespace["results"][0]["id"]
                prefix_parameters = {
                    "prefix": prefix_key,
                    "description": "Created automatically",
                    "status": uuid_mappings['status']["Active"],
                    "namespace": global_namespace_id,
                    "type": "network"
                }
                resp = connect.create_prefix(prefix_parameters)
                if resp.status_code == 201:
                    created_obj = resp.json()
                    if debug_mode:
                        logger.info(f"Prefix {prefix_key} created successfully.")
                    prefix_cache[prefix_key] = {
                        "found": True,
                        "id": created_obj["id"],
                        "namespace": created_obj["namespace"]["id"]
                    }
                else:
                    logger.error(
                        f"Failed to create prefix {prefix_key} (status {resp.status_code})."
                    )
                    prefix_cache[prefix_key] = {"found": False, "id": None, "namespace": None}

    # If prefix wasn't found/created, bail out
    if not prefix_cache[prefix_key]["found"]:
        return False, None

    # Now we have the prefix & namespace. Create the IP address.
    ip_addr_namespace = prefix_cache[prefix_key]["namespace"]
    ip_address_parameters = {
        "address": int_ip,
        "description": "Created automatically",
        "status": uuid_mappings['status']["Active"],
        "namespace": ip_addr_namespace
    }
    create_resp = connect.create_ip_address(ip_address_parameters=ip_address_parameters)

    if create_resp.status_code == 201:
        new_ip = create_resp.json()
        if debug_mode:
            logger.info(f"Created new IP {int_ip}")
        return True, new_ip.get("id")
    elif create_resp.status_code == 400:
        logger.warning(f"Attempted to create IP {int_ip} but got 400. It may already exist or invalid input.")
        return False, None
    else:
        logger.error(f"Failed to create IP {int_ip}. Status code: {create_resp.status_code}")
        return False, None


def config_ntb_cluster_group(ntb_cluster_group, vcenter_name):
    """
    Create a cluster group in Nautobot.

    :param ntb_cluster_group: The name of the cluster group to create.
    :param vcenter_name: Name of the vCenter for custom_fields.
    :return: True if creation succeeded, False if not.
    """
    cluster_group_data = {
        "name": ntb_cluster_group,
        "description": "This cluster group has created automatically",
        "custom_fields": {
            "vcenter": vcenter_name
        }
    }
    create_cluster_group = connect.create_cluster_group(cluster_group_data=cluster_group_data)

    if create_cluster_group.status_code == 201:
        logger.info(f"Cluster Group {ntb_cluster_group} has created successfully")
        return True
    else:
        logger.error(f"{ntb_cluster_group} - {create_cluster_group.json()}")
        return False


def config_ntb_cluster(ntb_cluster, ntb_cluster_type, ntb_cluster_group, vcenter_name):
    """
    Ensure a cluster type exists, then create a cluster.

    :param ntb_cluster: The cluster name.
    :param ntb_cluster_type: The cluster type name (must exist).
    :param ntb_cluster_group: The cluster group name (must exist).
    :param vcenter_name: vCenter name.
    :return: True if creation succeeded, or it already existed, False otherwise.
    """

    try:
        cluster_type_id = connect.get_cluster_type(cluster_type=ntb_cluster_type, cluster_type_id=True)
    except NautobotAPIError as ntb_error:
        logger.error(f"Error: {ntb_error}")
        logger.error("We couldn't find the cluster type id")
        return False

    ntb_cluster_group_id = connect.get_cluster_group_id(cluster_group=ntb_cluster_group)["results"][0]["id"]

    cluster_data = {
        "name": ntb_cluster,
        "cluster_type": cluster_type_id,
        "cluster_group": ntb_cluster_group_id,
        "custom_fields": {
            "vcenter": vcenter_name
        }
    }
    create_cluster = connect.create_cluster(cluster_data=cluster_data)
    if create_cluster.status_code == 201:
        logger.info(f"Cluster {ntb_cluster} has created successfully")
        return True
    else:
        logger.error(f"{ntb_cluster} - {create_cluster.json()}")
        return False


def gather_unique_fields(vms):
    """
    Gather unique cluster names and status names from a list of VM dictionaries.

    :param list[dict] vms: The list of VM dicts (e.g. from vms_to_add["create"]).
    :return: A dictionary containing sets of unique clusters and statuses.
    :rtype: dict
    """
    unique_mappings = {
        'clusters': set(),
        'statuses': set()
    }

    # Default status is "Active" unless explicitly offline
    unique_mappings['statuses'].add("Active")

    for vm in vms:
        cluster_name = vm.get('cluster_name')
        if cluster_name:
            unique_mappings['clusters'].add(cluster_name)

        # If 'powered_on' is True, the VM is considered "Active".
        # Otherwise (e.g., if it's suspended or powered off), it is labeled "Offline".
        status_name = "Active" if vm.get('powered_on') else "Offline"
        unique_mappings['statuses'].add(status_name)

    return unique_mappings


def fetch_uuids_from_nautobot(unique_mappings):
    """
    Given sets of cluster names and statuses, fetch their corresponding Nautobot UUIDs.

    :param unique_mappings: dict with 'clusters' and 'statuses' sets.
    :return: dict containing 'cluster' and 'status' subdicts, mapping names to UUIDs.
    :raises NautobotSyncError: If any item is missing in Nautobot.
    """
    uuid_mappings = {
        'cluster': {},
        'status': {}
    }

    # Fetch cluster UUIDs
    for cluster_name in unique_mappings['clusters']:
        if not cluster_name:
            continue
        try:
            response = connect.get_cluster_info(cluster_name=cluster_name)
            results = response.get("results", [])
            if not results:
                error_msg = f"No results returned for cluster '{cluster_name}' in Nautobot!"
                logger.error(error_msg)
                raise NautobotSyncError(error_msg)

            cluster_info = results[0]
            uuid_mappings['cluster'][cluster_name] = {
                'self': cluster_info["id"],
                'datacenter': cluster_info["cluster_group"]["id"]
            }
        except (KeyError, IndexError) as exc:
            error_msg = f"Cluster '{cluster_name}' not found or invalid response: {exc}"
            logger.error(error_msg)
            raise NautobotSyncError(error_msg)

    # Fetch status UUIDs
    for status_name in unique_mappings['statuses']:
        try:
            response = connect.get_status_info(status_name=status_name)
            results = response.get("results", [])
            if not results:
                error_msg = f"No results returned for status '{status_name}' in Nautobot!"
                logger.error(error_msg)
                raise NautobotSyncError(error_msg)

            status_info = results[0]
            uuid_mappings['status'][status_name] = status_info["id"]
        except (KeyError, IndexError) as exc:
            error_msg = f"Status '{status_name}' not found or invalid response: {exc}"
            logger.error(error_msg)
            raise NautobotSyncError(error_msg)

    return uuid_mappings


def transform_vms(vm_list, uuid_mappings):
    """
    Convert human-readable data (cluster_name, powered_on, etc.)
    into Nautobot UUIDs for cluster/datacenter/status, etc.

    :param vm_list: A list of VMs in raw form (with cluster_name, powered_on).
    :param uuid_mappings: A dict of {'cluster': {...}, 'status': {...}} from fetch_uuids_from_nautobot.
    :return: A list of processed VMs, each containing cluster UUID and status UUID.
    """
    processed_vms = []
    for vm in vm_list:
        cluster_name = vm.get('cluster_name')
        if not cluster_name:
            logger.warning(f"Skipping VM {vm.get('uuid')} - missing 'cluster_name'.")
            continue

        # Derive status from powered_on
        status_name = "Active" if vm.get('powered_on') else "Offline"

        processed_vm = {
            'uuid': vm.get('uuid'),
            'name': vm.get('name'),
            'cluster': uuid_mappings['cluster'][cluster_name]['self'],
            'datacenter': uuid_mappings['cluster'][cluster_name]['datacenter'],
            'status': uuid_mappings['status'][status_name],
            'interfaces': []
        }

        # Process network interfaces
        for net_int in vm.get('network_interfaces', []):
            processed_interface = {
                'port_group': net_int['port_group'],
                'macs': [],
                'ips': []
            }
            for iface in net_int.get('interfaces', []):
                mac_addr = iface.get('mac_address')
                if mac_addr:
                    processed_interface['macs'].append(mac_addr)
                ip_list = iface.get('ip_addresses', [])
                for ip in ip_list:
                    processed_interface['ips'].append(ip)
            processed_vm['interfaces'].append(processed_interface)

        processed_vms.append(processed_vm)

    return processed_vms


def create_vms_in_nautobot(processed_vms, vcenter):
    """
    Create the VMs in Nautobot. Returns a list of interface data for further creation,
    and how many VMs were actually created successfully.

    :param list[dict] processed_vms: List of VM dicts already mapped to Nautobot UUIDs.
    :param str vcenter: vCenter name to store as a custom field.
    :return: (interface_list, created_vm_count)
    """
    processed_interface_list = []
    created_vm_count = 0

    # Timestamp for the last vCenter sync (custom field)
    today_str = datetime.now().strftime("%Y-%m-%d")

    for vm in processed_vms:

        vm_payload = {
            'name': vm['name'],
            'cluster': vm['cluster'],
            'status': vm['status'],
            "custom_fields": {
                "vm_uuid": vm['uuid'],
                "vcenter": vcenter,
                "last_vcenter_sync": today_str
            }
        }

        # Create the VM in Nautobot
        created_vm = connect.create_vm(vm_json=vm_payload).json()

        vm_id = created_vm.get("id")
        if not vm_id:
            logger.error(f"Failed to create VM: {vm['name']}. Response: {created_vm}")
            continue

        created_vm_count += 1  # Successfully created a VM

        # Prepare interface creation payloads
        for vm_int in vm["interfaces"]:
            processed_interface_list.append({
                'port_group': vm_int['port_group'],
                'macs': vm_int['macs'],
                'ips': vm_int['ips'],
                'parent_vm_id': vm_id
            })

    return processed_interface_list, created_vm_count


def create_vm_interfaces(interface_list, uuid_mappings, warning_dict_f, debug_mode=False):
    """
    Create VM interfaces in Nautobot, handle IP existence checks (duplicate, etc.),
    create new IPs if needed (with prefix caching), and build a map of what IPs go on which interfaces.

    :param list interface_list: Each item describes a VM interface and includes 'parent_vm_id', 'macs', 'ips'.
    :param dict uuid_mappings: Contains cluster/status mappings (needed for IP status).
    :param dict warning_dict_f: Global warnings dict to populate with any discovered issues.
    :param bool debug_mode: Flag to enable extra logging.
    :return: (processed_vm_int_to_ip, created_interface_count, created_ip_count)
    :rtype: (list, int, int)
    """
    processed_vm_int_to_ip = []
    created_interface_count = 0
    created_ip_count = 0

    # Cache to avoid re-checking the same prefix for multiple IPs in the same subnet
    prefix_cache = {}

    for vm_interface in interface_list:
        try:
            interface_status = uuid_mappings['status']["Active"]
        except KeyError:
            interface_status = uuid_mappings['status']["Offline"]

        # Skip VM interfaces without port group information (usually powered-off VMs)
        if vm_interface['port_group'] is None:
            continue

        vm_int_payload = {
            'name': vm_interface['port_group'],
            'virtual_machine': vm_interface['parent_vm_id'],
            'status': interface_status,
            'mac_address': vm_interface['macs'][0] if vm_interface['macs'] else ""
        }

        created_vm_int = connect.create_vm_interface(vm_int_json=vm_int_payload).json()
        created_vm_int_id = created_vm_int.get("id")

        if not created_vm_int_id:
            logger.error(
                f"Failed to create interface '{vm_interface['port_group']}' "
                f"for VM ID {vm_interface['parent_vm_id']}."
            )
            continue

        created_interface_count += 1

        # Check, create, and associate IP addresses for each interface
        for int_ip in vm_interface['ips']:
            # Check if the IP (with mask) already exists
            existing_ip_resp = connect.get_addresses(ip_address_and_mask=int_ip)
            ip_and_subnet_exist = existing_ip_resp.get("count", 0)

            # If no results with that IP+mask, try IP alone (then remove it if we need to re-create)
            if ip_and_subnet_exist == 0:
                get_ip_addr = connect.get_addresses(ip_address=int_ip)
                ip_addr_exist = get_ip_addr.get("count", 0)
                results = get_ip_addr.get("results", [])
                if ip_addr_exist == 1 and results:
                    addr_uuid = results[0]["id"]
                    if debug_mode:
                        logger.info(f"Deleting {results[0]['display']} to create a new one => {int_ip}")
                    delete_ip = connect.delete_addresses(uuid=addr_uuid)
                    if delete_ip.status_code != 204:
                        logger.error(f"Deletion of {results[0]['display']} failed")

            # Verify if IP address with subnet mask exists after possible deletion
            existing_ip_resp = connect.get_addresses(ip_address_and_mask=int_ip)
            ip_count = existing_ip_resp.get("count", 0)
            results = existing_ip_resp.get("results", [])

            if ip_count == 1 and results:
                ip_info = results[0]
                ip_addr_id = ip_info["id"]

                # Check if IP is already attached
                if ip_info.get("vm_interfaces"):
                    # Already attached to another interface => warn
                    warning_dict_f["vm_ip_to_int_warnings"].append({
                        "virtual_machine": vm_interface['parent_vm_id'],
                        "ip_address": int_ip,
                        "comment": f"{int_ip} is already attached to another VM interface."
                    })
                    # We still link it up in our list
                    processed_vm_int_to_ip.append({
                        "vm_interface_id": created_vm_int_id,
                        "vm_interface_ip_id": ip_addr_id,
                        "parent_vm_id": vm_interface['parent_vm_id']
                    })
                else:
                    # OK to attach
                    processed_vm_int_to_ip.append({
                        "vm_interface_id": created_vm_int_id,
                        "vm_interface_ip_id": ip_addr_id,
                        "parent_vm_id": vm_interface['parent_vm_id']
                    })

            elif ip_count > 1:
                # Duplicate IP found
                warning_dict_f["duplicate_ips"].append({
                    "virtual_machine": vm_interface['parent_vm_id'],
                    "ip_address": int_ip
                })

            else:
                # IP doesn't exist => create it (with prefix caching)
                was_created, new_ip_id = create_ip_and_prefix_if_needed(
                    int_ip, uuid_mappings, prefix_cache, debug_mode=debug_mode
                )
                if new_ip_id:
                    if was_created:
                        created_ip_count += 1
                    processed_vm_int_to_ip.append({
                        "vm_interface_id": created_vm_int_id,
                        "vm_interface_ip_id": new_ip_id,
                        "parent_vm_id": vm_interface['parent_vm_id']
                    })
                else:
                    # Could not create IP => skip or log
                    logger.error(f"Could not create IP {int_ip} for interface {created_vm_int_id}")

    return processed_vm_int_to_ip, created_interface_count, created_ip_count


def create_and_assign_ips(ip_to_int_list, debug_mode=False):
    """
    Attach IPs to VM interfaces and set a primary IP for the VM if it doesn't already have one.

    :param list ip_to_int_list: List of dicts with 'vm_interface_id', 'vm_interface_ip_id', and 'parent_vm_id'.
    :param bool debug_mode: Flag for extra logging.
    :return: (attached_ip_count, assigned_primary_ip_count)
    :rtype: (int, int)
    """
    logger.info("Attaching IPs to interfaces and assigning primary IPs if needed...")
    attached_ip_count = 0
    assigned_primary_ip_count = 0

    for ip_to_int in ip_to_int_list:
        vm_int_ip_json = {
            "vm_interface": ip_to_int["vm_interface_id"],
            "ip_address": ip_to_int["vm_interface_ip_id"],
            "is_primary": True
        }
        attach_ip_to_int_resp = connect.attach_vm_interface_to_ip(vm_int_ip_json=vm_int_ip_json)

        if attach_ip_to_int_resp.status_code == 201:
            attached_ip_count += 1
        else:
            logger.error(
                f"Failed to attach IP {ip_to_int['vm_interface_ip_id']} "
                f"to interface {ip_to_int['vm_interface_id']} (VM ID: {ip_to_int['parent_vm_id']})."
            )
            continue

        # Check and assign primary IPv4 if missing
        vm_data = connect.get_vm_info(vm_id=ip_to_int['parent_vm_id'])

        if vm_data.get("primary_ip4") is None:
            ip_to_vm_payload = {
                "primary_ip4": ip_to_int['vm_interface_ip_id']
            }
            attach_ip_to_vm_resp = connect.attach_vm_to_ipv4(
                vm_id=ip_to_int['parent_vm_id'],
                vm_attach_ipv4_json=ip_to_vm_payload
            )
            if attach_ip_to_vm_resp.status_code == 200 and attach_ip_to_vm_resp.json().get("primary_ip4"):
                assigned_primary_ip_count += 1
                if debug_mode:
                    logger.info(
                        f"Assigned primary IPv4 address to VM {ip_to_int['parent_vm_id']}."
                    )
            else:
                logger.error(
                    f"Failed to assign primary IP {ip_to_int['vm_interface_ip_id']} "
                    f"to VM {ip_to_int['parent_vm_id']}."
                )

    return attached_ip_count, assigned_primary_ip_count


def compare_vm_fields_and_build_payload(vm):
    """
    Compare old/new VM fields and interface/IP data to identify changed properties.

    :param dict vm: VM data structure containing both old and new fields, plus vsphere_interfaces/nautobot_interfaces.
    :return: Dict describing the changes or an empty dict if none.
    :rtype: dict
    """
    result = {}
    vm_uuid = vm.get("uuid")

    # Check for differences in key VM attributes
    fields_to_check = ["name", "datacenter_name", "cluster_name", "powered_on"]
    vm_fields_changed = {}
    for field in fields_to_check:
        old_field = f"old_{field}"
        new_val = vm.get(field)
        old_val = vm.get(old_field)
        if new_val != old_val:
            vm_fields_changed[field] = {
                "old": old_val,
                "new": new_val
            }

    # Compare interfaces from vsphere vs nautobot
    vsphere_int = vm.get("vsphere_interfaces", [])
    nautobot_int = vm.get("nautobot_interfaces", [])

    interfaces_changed = []
    ips_changed = []

    def flatten_interfaces(iface_list):
        """
        Convert the nested array structure into a dict keyed by (port_group, mac_address),
        mapping each to a set of IP addresses.
        """
        flat = {}
        for iface_block in iface_list:
            pg = iface_block.get("port_group")
            for subif in iface_block.get("interfaces", []):
                mac = subif.get("mac_address") or "UNKNOWN_MAC"
                ip_list = subif.get("ip_addresses", [])
                flat[(pg, mac)] = set(ip_list)
        return flat

    vsphere_flat = flatten_interfaces(vsphere_int)
    nautobot_flat = flatten_interfaces(nautobot_int)

    vs_keys = set(vsphere_flat.keys())
    nt_keys = set(nautobot_flat.keys())

    # New or removed interfaces
    new_interfaces = vs_keys - nt_keys
    removed_interfaces = nt_keys - vs_keys

    for nk in new_interfaces:
        interfaces_changed.append({
            "port_group": nk[0],
            "mac_address": nk[1],
            "comment": "Interface is new in vSphere, absent in Nautobot"
        })
    for rk in removed_interfaces:
        interfaces_changed.append({
            "port_group": rk[0],
            "mac_address": rk[1],
            "comment": "Interface is present in Nautobot, absent in vSphere"
        })

    # Compare IP sets for common interfaces
    common_keys = vs_keys & nt_keys
    for ck in common_keys:
        vs_ips = vsphere_flat[ck]
        nt_ips = nautobot_flat[ck]
        if vs_ips != nt_ips:
            removed_ips = sorted(list(nt_ips - vs_ips))  # in Nautobot, not in vSphere
            added_ips = sorted(list(vs_ips - nt_ips))  # in vSphere, not in Nautobot
            ips_changed.append({
                "port_group": ck[0],
                "mac_address": ck[1],
                "added_ips": added_ips,
                "removed_ips": removed_ips,
                "comment": "IP addresses differ"
            })

    # Construct payload for VM only if differences exist
    if vm_fields_changed or interfaces_changed or ips_changed:
        result["uuid"] = vm_uuid
        if vm_fields_changed:
            result["vm_fields_changed"] = vm_fields_changed
        if interfaces_changed:
            result["interfaces_changed"] = interfaces_changed
        if ips_changed:
            result["ips_changed"] = ips_changed

    return result


def handle_vm_interface_deletion(vm_id, debug_mode=False):
    """
    We call this function if there is a change with VM interface.
    If the VM had no interface to delete we will ignore it.
    Remove all VM interfaces (and their attachments) for a given VM in Nautobot.

    :param str vm_id: The Nautobot VM ID.
    :param bool debug_mode: Whether to log extra info.
    """
    existing_interfaces_resp = connect.get_vm_interface(vm_id=vm_id)
    existing_interfaces = existing_interfaces_resp.get("results", [])

    if not existing_interfaces:
        return

    for iface in existing_interfaces:
        iface_id = iface["id"]
        iface_name = iface["name"]
        if debug_mode:
            logger.info(f"Deleting interface '{iface_name}' from VM {vm_id}.")
        del_resp = connect.delete_vm_interface(vm_interface_id=iface_id)
        if del_resp.status_code not in [200, 204]:
            logger.error(f"Failed to delete interface {iface_id} for VM {vm_id}.")


def edit_nautobot_object(update_list, vcenter_name, debug_mode=False):
    """
    Update existing VMs in Nautobot with any changed fields (name, cluster, status, etc.).
    Re-creates interfaces from vSphere data if the interface set is different.

    :param update_list: The 'update' portion of the diff, describing changed VMs.
    :param vcenter_name: The name of the vCenter, used to find the correct VM if duplicates exist.
    :param debug_mode: If True, logs extra details during updates.
    """
    if not update_list:
        logger.info("No VMs to update.")
        return

    # Gather unique fields (clusters, statuses) in case they changed
    unique = gather_unique_fields(update_list)
    uuid_mappings = fetch_uuids_from_nautobot(unique)

    processed_int_list = []  # We'll rebuild interfaces from vsphere_interfaces

    # Timestamp for the last vCenter sync (custom field)
    today_str = datetime.now().strftime("%Y-%m-%d")

    for vm_item in update_list:
        vm_uuid = vm_item["uuid"]

        # Use vCenter name along with VM UUID to uniquely identify VMs, handling migrations between vCenters
        vm_info = connect.get_nautobot_vm_id(vm_uuid_custom=vm_uuid, vcenter_name=vcenter_name)
        count_found = vm_info["count"]

        # Resolve cases of duplicate VM UUIDs in Nautobot
        if count_found > 1 and vm_item["powered_on"] is False:
            logger.info(f"Skipping VM {vm_item['name']} because it seems to be an SRM clone (powered off).")
            warning_dict["duplicate_vm_id"].append({
                "vm_id": vm_uuid,
                "vm_name": vm_item["name"],
                "comment": "VM duplicate uuid"
            })
            continue
        elif count_found > 1:
            # Another scenario: multiple VMs with the same vcenter UUID
            warning_dict["duplicate_vm_id"].append({
                "vm_id": vm_uuid,
                "vm_name": vm_item["name"],
                "comment": "VM duplicate uuid"
            })
            # Attempt to pick the correct VM with the matching status
            powered_on = vm_item["powered_on"]
            status_name = "Active" if powered_on else "Offline"
            status_id = uuid_mappings["status"][status_name]

            vm_id = None
            for i in range(count_found):
                if vm_info["results"][i]["status"]["id"] == status_id:
                    vm_id = vm_info["results"][i]["id"]
                    break
            if not vm_id:
                # fallback to first result if we can't find a match
                vm_id = vm_info["results"][0]["id"]
        else:
            # Normal case, single result
            vm_id = vm_info["results"][0]["id"]

        if not vm_id:
            logger.error(f"VM {vm_uuid} not found in Nautobot; cannot update.")
            continue

        # 2) Patch global fields
        payload = {"custom_fields": {"last_vcenter_sync": today_str}}
        # Because we also need to update custom fields for last_vcenter_sync:

        if "name" in vm_item:  # implies name changed
            payload["name"] = vm_item["name"]
        if "cluster_name" in vm_item:
            cluster_name = vm_item["cluster_name"]
            cluster_uuid = uuid_mappings["cluster"][cluster_name]["self"]
            payload["cluster"] = cluster_uuid
        if "powered_on" in vm_item:
            powered_on = vm_item["powered_on"]
            status_name = "Active" if powered_on else "Offline"
            payload["status"] = uuid_mappings["status"][status_name]

        # Patch all VM attributes due to interface changes; optimize in future updates
        if payload:
            if debug_mode:
                logger.info(f"Patching VM {vm_uuid} with {payload}")
            patch_resp = connect.update_vm_fields(vm_id, payload)
            if patch_resp.status_code not in [200, 201, 204]:
                logger.error(f"Failed to patch VM {vm_uuid}, status {patch_resp.status_code}")

        # 3) If vsphere_interfaces changed, we recreate them
        if "vsphere_interfaces" in vm_item:
            if debug_mode:
                logger.info(f"Interfaces differ for VM {vm_uuid}, re-creating them.")

            handle_vm_interface_deletion(vm_id, debug_mode=debug_mode)

            for net_int in vm_item["vsphere_interfaces"]:
                port_group = net_int.get("port_group")
                macs = []
                ips = []
                for sub_if in net_int.get("interfaces", []):
                    if sub_if.get("mac_address"):
                        macs.append(sub_if["mac_address"])
                    ips.extend(sub_if.get("ip_addresses", []))

                processed_int_list.append({
                    "port_group": port_group,
                    "macs": macs,
                    "ips": ips,
                    "parent_vm_id": vm_id
                })

    # 4) Create interfaces + IPs for everything that changed
    if processed_int_list:
        logger.info("Creating/re-creating VM interfaces for updated VMs ...")
        (processed_vm_int_to_ip, interface_count, new_ip_count) = create_vm_interfaces(
            processed_int_list, uuid_mappings, warning_dict, debug_mode=debug_mode
        )
        (attached_ip_count, assigned_primary_ip_count) = create_and_assign_ips(
            processed_vm_int_to_ip, debug_mode=debug_mode
        )
        logger.info(
            f"Updated {interface_count} interfaces, created {new_ip_count} new IPs, "
            f"attached {attached_ip_count} IPs, assigned primary IP to {assigned_primary_ip_count} VM(s)."
        )

    if any(warning_dict.values()) and debug_mode:
        logger.warning(f"Warnings found during update execution: {warning_dict}")


def create_nautobot_object(vm_list_to_create, vcenter_name, debug_mode=False):
    """
    Overall pipeline for creating new VMs, interfaces, and IP assignments in Nautobot.

    :param list[dict] vm_list_to_create: The 'create' portion of diff data.
    :param str vcenter_name: Name of the vCenter (stored as a custom field).
    :param bool debug_mode: Extra logging if True.
    """
    # 1. Gather cluster/status fields
    unique_mappings = gather_unique_fields(vm_list_to_create)

    # 2. Fetch UUIDs from Nautobot
    uuid_mappings = fetch_uuids_from_nautobot(unique_mappings)

    # 3. Transform VM data with those UUIDs
    processed_vms = transform_vms(vm_list_to_create, uuid_mappings)

    # 4a. Create VMs, gather interface data
    logger.info(f"Creating VMs with vCenter name '{vcenter_name}'.")
    processed_interface_list, vm_count = create_vms_in_nautobot(
        processed_vms, vcenter_name
    )

    # 4b. Create VM interfaces
    processed_vm_int_to_ip, interface_count, new_ip_count = create_vm_interfaces(
        processed_interface_list, uuid_mappings, warning_dict, debug_mode=debug_mode
    )

    # 4c. Attach IPs and assign primary IP
    attached_ip_count, assigned_primary_ip_count = create_and_assign_ips(
        processed_vm_int_to_ip, debug_mode=debug_mode
    )

    if any(warning_dict.values()) and debug_mode:
        logger.warning(f"Warnings found during create execution: {warning_dict}")

    # Summary
    logger.info("----- PROCESS SUMMARY (CREATE) -----")
    logger.info(f"Created {vm_count} VM(s)")
    logger.info(f"Created {interface_count} interface(s)")
    logger.info(f"Created {new_ip_count} new IP address(es)")
    logger.info(f"Attached {attached_ip_count} IP address(es) to interfaces")
    logger.info(f"Assigned primary IP to {assigned_primary_ip_count} VM(s)")
    logger.info("----- CREATE COMPLETED SUCCESSFULLY -----")


def decommission_nautobot_vm(vm_list_to_decommission, vcenter_name):
    """
    In 'safe mode' we decommission VMs (rather than hard-delete):
    - Mark them with a 'Decommissioning' status
    - Clear 'vm_uuid' and 'vcenter' custom fields

    :param vm_list_to_decommission: The VMs to decommission (list of dicts).
    :param vcenter_name: vCenter name to identify the correct VM.
    """
    if not vm_list_to_decommission:
        logger.info("No VMs To delete (decommission).")
        return

    # Get 'Decommissioning' status ID from Nautobot
    decommission_id = connect.get_status_info(status_name="Decommissioning")["results"][0]["id"]

    # Timestamp for the last vCenter sync (custom field)
    today_str = datetime.now().strftime("%Y-%m-%d")

    for vm in vm_list_to_decommission:
        vm_id = ""
        vm_info = connect.get_nautobot_vm_id(vm_uuid_custom=vm["uuid"], vcenter_name=vcenter_name)
        for vm_found in vm_info["results"]:
            if vm["name"] == vm_found["name"]:
                vm_id = vm_found["id"]
                continue

        if not vm_id:
            logger.warning(
                f"VM '{vm}' has a UUID that is already present in Nautobot under a different name. Handle manually."
            )
            continue

        # Build the patch payload to mark it decommissioned
        vm_payload = {
            'status': decommission_id,
            "custom_fields": {
                "vm_uuid": '',
                "vcenter": '',
                "last_vcenter_sync": today_str
            }
        }
        update_the_vm = connect.update_vm_fields(vm_id=vm_id, vm_data_payload=vm_payload)
        if update_the_vm.status_code not in [200, 201, 204]:
            logger.error(f"Failed to decommission VM {vm['uuid']}, status {update_the_vm.status_code}")
        else:
            logger.info(f"VM '{vm['name']}' has been decommissioned.")


def delete_nautobot_vm(vm_list_to_delete, vcenter_name, debug_mode=None):
    """
    Hard-delete each VM from Nautobot (used when safe mode is off).

    :param list[dict] vm_list_to_delete: The 'inactive' portion of diff data.
    :param str debug_mode: Optional debug mode.
    :param str vcenter_name: Name of the vCenter.
    """
    if not vm_list_to_delete:
        logger.info("No VMs To delete.")
        return

    for vm in vm_list_to_delete:
        vm_id = ""
        vm_info = connect.get_nautobot_vm_id(vm_uuid_custom=vm["uuid"], vcenter_name=vcenter_name)
        if vm_info["count"] == 0:
            logger.warning(f"Couldn't find VM {vm['name']}")
            continue
        for vm_found in vm_info["results"]:
            if vm["name"] == vm_found["name"]:
                vm_id = vm_found["id"]
                continue

        if not vm_id:
            logger.warning(
                f"VM '{vm}' has a UUID that is already present in Nautobot under a different name. Handle manually."
            )
            continue

        delete_the_vm = connect.delete_virtual_machine(vm_id=vm_id)
        if delete_the_vm.status_code not in [200, 201, 204]:
            logger.error(f"Failed to delete VM {vm['uuid']}, status {delete_the_vm.status_code}")
        else:
            if debug_mode:
                logger.info(f"VM '{vm['name']}' has been deleted.")


def config_vms(vcenter_name, data_to_config, safe_mode=False, debug_mode=False):
    """
    Main function to process VMs (create, update, decommission) in Nautobot.
    Called from vm_info (the main script) with the relevant data.

    :param str vcenter_name: Name of the vCenter (for custom field).
    :param dict data_to_config: The diff data, typically with keys 'inactive', 'create', 'update'.
    :param bool debug_mode: Whether to log debug details.
    :param bool safe_mode: Whether to use safe mode or not.
    :return: The global warning_dict containing any warnings generated.
    :rtype: dict
    """
    try:

        # 1. Decommission any VMs that appear 'inactive'
        if "inactive" in data_to_config and data_to_config["inactive"]:
            logger.info(
                f"The following VMs will be removed from Nautobot:\n"
                f"{data_to_config['inactive']} "
            )
            # If we are using safe mode, instead of deleting VMs we will just make their
            # status to decommission
            if safe_mode:
                logger.info("Safe mode is on, so decommission process will take place")
                decommission_nautobot_vm(
                    vm_list_to_decommission=data_to_config["inactive"],
                    vcenter_name=vcenter_name
                )
            # In standard mode we are going to delete inactive VMs
            else:
                logger.info("Safe mode is off, so we will delete VMs")
                delete_nautobot_vm(vm_list_to_delete=data_to_config["inactive"],
                                   vcenter_name=vcenter_name,
                                   debug_mode=debug_mode)

        # 2. Create new VMs
        if "create" in data_to_config and data_to_config["create"]:
            create_nautobot_object(
                data_to_config["create"],
                vcenter_name=vcenter_name,
                debug_mode=debug_mode
            )

        # 3. Update existing VMs
        if "update" in data_to_config and data_to_config["update"]:
            edit_nautobot_object(
                data_to_config["update"],
                vcenter_name=vcenter_name,
                debug_mode=debug_mode
            )

    except NautobotSyncError as error_to_log:
        logger.error("A NautobotSyncError occurred: %s", error_to_log)
        sys.exit(1)
    except Exception as error_to_log:
        logger.exception(f"An unexpected error occurred in config_vms(): {error_to_log}")
        sys.exit(2)

    return warning_dict
