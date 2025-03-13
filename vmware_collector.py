#!/usr/bin/env python3
"""
vmware_collector.py

Contains functions for connecting to vCenter and gathering VM information in memory,
plus some vSphere-related helper functions (e.g. for extracting datacenter and cluster).
"""

import logging
import ssl
import ipaddress
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect

logger = logging.getLogger(__name__)


def get_datacenter_and_cluster(vm):
    """
    Return (datacenter_name, cluster_name) for a given VM object.
    """
    host = vm.runtime.host
    if not host:
        return "UnknownDC", "UnknownCluster"

    compute_resource = host.parent
    if not compute_resource:
        return "UnknownDC", "UnknownCluster"

    if isinstance(compute_resource, vim.ClusterComputeResource):
        cluster_name = compute_resource.name
    elif isinstance(compute_resource, vim.ComputeResource):
        cluster_name = compute_resource.name
    else:
        cluster_name = "UnknownCluster"

    parent_entity = compute_resource.parent
    datacenter_name = "UnknownDC"
    while parent_entity:
        if isinstance(parent_entity, vim.Datacenter):
            datacenter_name = parent_entity.name
            break
        parent_entity = parent_entity.parent

    return datacenter_name, cluster_name


def gather_vm_info_in_memory(vcenter_host, vcenter_user, vcenter_password):
    """
    Connect to vCenter and collect detailed VM information.

    Connects to the specified vCenter server and retrieves comprehensive VM data
    including power state, datacenter/cluster location, and network configuration
    with port groups, MAC addresses, and IP addresses.

    Args:
        vcenter_host (str): Hostname or IP of the vCenter server
        vcenter_user (str): Username for vCenter authentication
        vcenter_password (str): Password for vCenter authentication

    Returns:
        dict: Dictionary of VM information keyed by VM UUID, with each entry containing:
            - name: VM name
            - uuid: VM unique identifier
            - powered_on: Boolean indicating power state
            - datacenter_name: Name of the datacenter containing the VM
            - cluster_name: Name of the cluster containing the VM
            - network_interfaces: List of network interface configurations
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    vsphere_data = {}

    try:
        si = SmartConnect(
            host=vcenter_host,
            user=vcenter_user,
            pwd=vcenter_password,
            sslContext=context
        )
        logger.info(f"Connected to vCenter {vcenter_host}, beginning VM inventory collection...")
    except Exception as e:
        logger.error(f"[{vcenter_host}] Connection failed: {e}")
        # Return empty dict to indicate failure
        return vsphere_data

    content = si.RetrieveContent()

    # Build a port-group map for distributed virtual port groups.
    dvpg_map = {}
    dvs_container = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.dvs.DistributedVirtualPortgroup], True
    )
    for dvpg in dvs_container.view:
        dvs_uuid = dvpg.config.distributedVirtualSwitch.uuid
        dvs_port_key = dvpg.key
        dvpg_map[(dvs_uuid, dvs_port_key)] = dvpg.name
    dvs_container.Destroy()

    # Get all VMs in the vCenter inventory
    vm_container = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.VirtualMachine], True
    )
    all_vms = vm_container.view

    for vm in all_vms:
        vm_name = vm.name
        powered_on = (vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn)

        if not vm.config or not vm.config.uuid:
            logger.warning(
                f"[{vcenter_host}] Skipping VM '{vm_name}' - missing UUID."
            )
            continue

        uuid = vm.config.uuid
        datacenter_name, cluster_name = get_datacenter_and_cluster(vm)

        # Prepare network_interfaces structure
        network_interfaces = []
        port_group_map = {}
        guest_net_info = vm.guest.net if (vm.guest and vm.guest.net) else []

        if vm.config and vm.config.hardware and vm.config.hardware.device:
            for dev in vm.config.hardware.device:
                if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                    mac_address = (dev.macAddress.lower() if dev.macAddress else None)
                    if mac_address is None:
                        continue

                    backing = dev.backing
                    pg_name = None

                    if isinstance(backing, vim.vm.device.VirtualEthernetCard.NetworkBackingInfo):
                        if backing.network:
                            pg_name = backing.network.name
                    elif isinstance(backing, vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo):
                        pg_key = backing.port.portgroupKey
                        switch_uuid = backing.port.switchUuid
                        pg_name = dvpg_map.get((switch_uuid, pg_key), "Unknown")

                    matching_net_info = None
                    for net_info in guest_net_info:
                        if net_info.macAddress and net_info.macAddress.lower() == mac_address:
                            matching_net_info = net_info
                            break

                    ip_list = []
                    if (matching_net_info and matching_net_info.ipConfig
                            and matching_net_info.ipConfig.ipAddress):
                        for ip_cfg in matching_net_info.ipConfig.ipAddress:
                            try:
                                ip_obj = ipaddress.ip_address(ip_cfg.ipAddress)
                                if isinstance(ip_obj, ipaddress.IPv4Address):
                                    cidr_str = f"{ip_obj}/{ip_cfg.prefixLength}"
                                    ip_list.append(cidr_str)
                            except ValueError:
                                pass

                    if pg_name not in port_group_map:
                        port_group_map[pg_name] = []
                    port_group_map[pg_name].append({
                        "mac_address": mac_address,
                        "ip_addresses": ip_list
                    })

        # Organize network interface data by port group with associated MAC and IP addresses
        for pg, iface_list in port_group_map.items():
            if iface_list:
                combined_ip_addresses = []
                for iface in iface_list:
                    combined_ip_addresses.extend(iface.get("ip_addresses", []))

                interface_entry = {
                    "mac_address": iface_list[0]["mac_address"],  # from the first
                    "ip_addresses": combined_ip_addresses
                }
                network_interfaces.append({
                    "port_group": pg,
                    "interfaces": [interface_entry]
                })

        vsphere_data[uuid] = {
            "name": vm_name,
            "uuid": uuid,
            "powered_on": powered_on,
            "datacenter_name": datacenter_name,
            "cluster_name": cluster_name,
            "network_interfaces": network_interfaces
        }

    vm_container.Destroy()
    Disconnect(si)

    logger.info(f"[{vcenter_host}] Found {len(vsphere_data)} VM(s) in this vCenter.")
    return vsphere_data


def gather_dc_cluster_info(vm_data):
    """
    Extract unique datacenter and cluster names from the VM info dict,
    and also build a mapping of cluster_name -> datacenter_name.
    """

    # Suggested:
    """
    Extract datacenter and cluster relationship information from VM data.

    Processes VM data to create three data structures:
    1. A list of unique datacenter names
    2. A list of unique cluster names
    3. A mapping of cluster names to their parent datacenter names

    Args:
        vm_data (dict): Dictionary of VM information as returned by gather_vm_info_in_memory()
    """

    datacenters = set()
    clusters = set()
    cluster_to_datacenter = {}

    for vm in vm_data.values():
        dc = vm.get("datacenter_name", "UnknownDC")
        cl = vm.get("cluster_name", "UnknownCluster")
        datacenters.add(dc)
        clusters.add(cl)

        if cl != "UnknownCluster":
            cluster_to_datacenter[cl] = dc

    return {
        "datacenters": list(datacenters),
        "clusters": list(clusters),
        "cluster_to_datacenter": cluster_to_datacenter
    }
