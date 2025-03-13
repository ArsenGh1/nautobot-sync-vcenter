#!/usr/bin/env python3
"""
Compare VM data from vSphere with Nautobot, returning diffs
for creating, decommissioning (inactive), or updating VMs.
"""

import os
import json
from datetime import datetime
from pathlib import Path
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def convert_nautobot_data_to_dict(nautobot_raw):
    """
    Reformat Nautobot VM data into dict keyed by VM UUID for easy comparison
    """
    data = {}
    vms_list = nautobot_raw.get("data", {}).get("virtual_machines", [])

    for vm in vms_list:
        custom_fields = vm.get("_custom_field_data", {})
        uuid = custom_fields.get("vm_uuid")
        if not uuid:
            continue

        status_name = vm.get("status", {}).get("name", "Unknown")

        # Map "active" status in Nautobot to VM being powered on
        powered_on = (status_name.lower() == "active")

        cluster = vm.get("cluster", {}) or {}
        cluster_group = cluster.get("cluster_group", {}) or {}
        datacenter_name = cluster_group.get("name", "UnknownDC")
        cluster_name = cluster.get("name", "UnknownCluster")

        # Build network_interfaces from Nautobot's interfaces
        network_interfaces = []
        for iface in vm.get("interfaces", []):
            ip_addresses = []
            for ip_data in iface.get("ip_addresses", []):
                address = ip_data.get("address")
                if address:
                    ip_addresses.append(address)

            mac_addr = iface.get("mac_address") or "UNKNOWN_MAC"
            network_interfaces.append({
                "port_group": iface.get("name") or "NautobotInterface",
                "interfaces": [
                    {
                        "mac_address": mac_addr.lower(),
                        "ip_addresses": ip_addresses
                    }
                ]
            })

        data[uuid] = {
            "name": vm.get("name"),
            "uuid": uuid,
            "powered_on": powered_on,
            "datacenter_name": datacenter_name,
            "cluster_name": cluster_name,
            "network_interfaces": network_interfaces
        }

    return data


def canonicalize_net_ifaces(interface_list):
    """
    Turn a network_interfaces list into a dict keyed by (port_group, mac_address),
    each value is a set of IP addresses. This helps compare vsphere vs. Nautobot.
    """
    normalized = {}

    for net_block in interface_list:
        pg = net_block.get("port_group", "UNKNOWN_PG")
        for sub_if in net_block.get("interfaces", []):
            mac = sub_if.get("mac_address", "UNKNOWN_MAC")

            # Use sets to collect IP addresses, ignoring duplicates and order
            ips = set(sub_if.get("ip_addresses", []))
            normalized[(pg, mac)] = normalized.get((pg, mac), set()) | ips

    return normalized


def build_diff(vsphere_dict, nautobot_dict):
    """
    Compare vSphere vs. Nautobot dictionaries, returning a diff with
    "create", "inactive", and "update" lists.
    """
    vs_uuids = set(vsphere_dict.keys())
    nb_uuids = set(nautobot_dict.keys())

    create_uuids = vs_uuids - nb_uuids
    inactive_uuids = nb_uuids - vs_uuids
    common_uuids = vs_uuids & nb_uuids

    create_list = []
    inactive_list = []
    update_list = []

    # 1) CREATE => in vSphere but not Nautobot
    for uuid in create_uuids:
        vm = vsphere_dict[uuid]
        create_list.append({
            "uuid": uuid,
            "name": vm["name"],
            "datacenter_name": vm["datacenter_name"],
            "cluster_name": vm["cluster_name"],
            "powered_on": vm["powered_on"],
            "network_interfaces": vm["network_interfaces"]
        })

    # 2) INACTIVE => in Nautobot but not vSphere
    for uuid in inactive_uuids:
        vm = nautobot_dict[uuid]
        inactive_list.append({
            "uuid": uuid,
            "name": vm["name"]
        })

    # 3) UPDATE => in both, but fields or interfaces differ
    for uuid in common_uuids:
        vs_vm = vsphere_dict[uuid]
        nb_vm = nautobot_dict[uuid]

        name_diff = (vs_vm["name"] != nb_vm["name"])
        dc_diff = (vs_vm["datacenter_name"] != nb_vm["datacenter_name"])
        cluster_diff = (vs_vm["cluster_name"] != nb_vm["cluster_name"])
        power_diff = (vs_vm["powered_on"] != nb_vm["powered_on"])

        vs_iface_dict = canonicalize_net_ifaces(vs_vm["network_interfaces"])
        nb_iface_dict = canonicalize_net_ifaces(nb_vm["network_interfaces"])
        nif_diff = (vs_iface_dict != nb_iface_dict)

        if not any([name_diff, dc_diff, cluster_diff, power_diff, nif_diff]):
            continue

        update_entry = {"uuid": uuid}

        # If interfaces differ, include all vSphere data to fully update VM interfaces in Nautobot
        if nif_diff:
            update_entry.update({
                "vsphere_interfaces": vs_vm["network_interfaces"],
                "name": vs_vm["name"],
                "old_name": nb_vm["name"],
                "datacenter_name": vs_vm["datacenter_name"],
                "old_datacenter_name": nb_vm["datacenter_name"],
                "cluster_name": vs_vm["cluster_name"],
                "old_cluster_name": nb_vm["cluster_name"],
                "powered_on": vs_vm["powered_on"],
                "old_powered_on": nb_vm["powered_on"]
            })
            update_list.append(update_entry)
            continue

        if name_diff:
            update_entry["name"] = vs_vm["name"]
            update_entry["old_name"] = nb_vm["name"]
        if dc_diff:
            update_entry["datacenter_name"] = vs_vm["datacenter_name"]
            update_entry["old_datacenter_name"] = nb_vm["datacenter_name"]
        if cluster_diff:
            update_entry["cluster_name"] = vs_vm["cluster_name"]
            update_entry["old_cluster_name"] = nb_vm["cluster_name"]
        if power_diff:
            update_entry["powered_on"] = vs_vm["powered_on"]
            update_entry["old_powered_on"] = nb_vm["powered_on"]

        update_list.append(update_entry)

    return {
        "create": create_list,
        "inactive": inactive_list,
        "update": update_list
    }


def compare_nautobot_vsphere(vsphere_data, nautobot_data, vcenter_name, debug_mode=False):
    """
    Compare vSphere data to Nautobot data and write diffs to a JSON file.
    Returns (diff, filepath).
    """
    # Convert Nautobot VM data into a format compatible with vsphere_data dict
    nautobot_dict = convert_nautobot_data_to_dict(nautobot_data)

    # Normalize vSphere data structure to match expected schema
    vsphere_dict = {}
    for uuid, vm_info in vsphere_data.items():
        # Normalize vSphere data, using defaults for missing fields
        vsphere_dict[uuid] = {
            "name": vm_info.get("name"),
            "uuid": vm_info.get("uuid", uuid),
            "powered_on": vm_info.get("powered_on", False),
            "datacenter_name": vm_info.get("datacenter_name", "UnknownDC"),
            "cluster_name": vm_info.get("cluster_name", "UnknownCluster"),
            "network_interfaces": vm_info.get("network_interfaces", []),
        }

    diff = build_diff(vsphere_dict, nautobot_dict)

    OUTPUT_DIR = Path("debug/data_comparison")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_file = OUTPUT_DIR / f"{vcenter_name}.json"

    # For the main output file
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(diff, f, indent=2)
        logger.info(f"Comparison results -> {out_file}")
    except IOError as e:
        logger.error(f"Failed to write comparison results to {out_file}: {str(e)}")
    except json.JSONEncodeError as e:
        logger.error(f"Failed to encode diff data as JSON: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error writing comparison results: {str(e)}")

    # If debug mode is enabled, we store data comparison details in history directory
    # and mention timestamp in its name

    if debug_mode:
        OUTPUT_DIR_HISTORY = Path("debug/data_comparison/history")
        os.makedirs(OUTPUT_DIR_HISTORY, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file_debug = OUTPUT_DIR_HISTORY / f"{vcenter_name}_{timestamp}.json"

        try:
            with open(out_file_debug, "w", encoding="utf-8") as f:
                json.dump(diff, f, indent=2)
            logger.info(f"Debug history saved -> {out_file_debug}")
        except IOError as e:
            logger.error(f"Failed to write debug history to {out_file_debug}: {str(e)}")
        except json.JSONEncodeError as e:
            logger.error(f"Failed to encode diff data as JSON for debug history: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error writing debug history: {str(e)}")

    return diff, out_file
