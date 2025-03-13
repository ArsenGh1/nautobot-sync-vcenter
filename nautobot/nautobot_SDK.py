#!/usr/bin/env python3
"""
Nautobot SDK: A client to interact with Nautobot's REST API.
"""

import requests
import urllib3
import json
import logging

# Configure logging
logger = logging.getLogger(__name__)


class NautobotAPIError(Exception):
    """Custom exception for Nautobot API errors."""

    def __init__(self, status_code, message, detail=None, method=None, url=None):
        self.status_code = status_code
        self.message = message
        self.detail = detail
        self.method = method
        self.url = url
        super().__init__(self.message)

    def __str__(self):
        base_msg = f"{self.status_code} Error: {self.message}"
        if self.detail:
            base_msg += f" - {self.detail}"
        if self.method and self.url:
            base_msg += f" [{self.method} {self.url}]"
        return base_msg


class nautobot:
    """
    A Nautobot client for convenient REST API interactions.
    """

    def __init__(self, Token, URL, verify_ssl=False, timeout=30):
        """
        Initialize the Nautobot client with the given API token.

        Args:
            Token (str): The Nautobot API authentication token
            URL (str): Base URL of the Nautobot instance (without /api)
            verify_ssl (bool): Whether to verify SSL certificates
            timeout (int): Request timeout in seconds
        """
        self.token = Token
        self.base_url = f"{URL}/api"
        self.headers = {
            "Authorization": f"Token {Token}",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate, br"
        }
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # Suppress InsecureRequestWarning only if verify_ssl is False
        if not verify_ssl:
            urllib3.disable_warnings()

    @staticmethod
    def _process_response(response, method, url):
        """
        Process API response, raise exceptions on errors.

        Args:
            response (requests.Response): The HTTP response to process
            method (str): The HTTP method used (GET, POST, etc.)
            url (str): The URL that was requested

        Returns:
            dict or Response: JSON response or the Response object depending on the method

        Raises:
            NautobotAPIError: On API errors
        """
        try:
            if 200 <= response.status_code < 300:
                # For successful responses, return JSON for GET and the response for others
                if method.upper() == "GET":
                    return response.json()
                else:
                    return response

            # Handle error responses
            error_detail = None
            try:
                error_content = response.json()
                if isinstance(error_content, dict):
                    error_detail = json.dumps(error_content)
            except (ValueError, json.JSONDecodeError):
                error_detail = response.text if response.text else None

            # Map common status codes to friendly messages
            status_messages = {
                400: "Bad Request - Invalid data or parameters",
                401: "Unauthorized - Authentication failed",
                403: "Forbidden - Insufficient permissions",
                404: "Not Found - Resource doesn't exist",
                405: "Method Not Allowed",
                409: "Conflict - Resource already exists",
                500: "Internal Server Error",
            }

            message = status_messages.get(response.status_code, f"HTTP Error {response.status_code}")
            raise NautobotAPIError(
                status_code=response.status_code,
                message=message,
                detail=error_detail,
                method=method,
                url=url
            )

        except requests.exceptions.RequestException as e:
            # Handle request exceptions (timeout, connection errors, etc.)
            raise NautobotAPIError(
                status_code=0,
                message=f"Request failed: {str(e)}",
                method=method,
                url=url
            )

    def _request(self, method, endpoint, data=None, params=None):
        """
        Make an HTTP request to the Nautobot API.

        Args:
            method (str): HTTP method (GET, POST, PATCH, DELETE)
            endpoint (str): API endpoint (without base URL)
            data (dict, optional): JSON data for POST/PATCH requests
            params (dict, optional): Query parameters

        Returns:
            dict or Response: Processed API response

        Raises:
            NautobotAPIError: On API errors
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=data if data else None,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            return self._process_response(response, method, url)

        except requests.exceptions.Timeout:
            raise NautobotAPIError(
                status_code=0,
                message="Request timed out",
                method=method,
                url=url
            )
        except requests.exceptions.ConnectionError:
            raise NautobotAPIError(
                status_code=0,
                message="Connection error - unable to connect to Nautobot",
                method=method,
                url=url
            )
        except NautobotAPIError:
            # Just re-raise the same exception, to avoid double-wrapping
            raise
        except Exception as e:
            raise NautobotAPIError(
                status_code=0,
                message=f"Unexpected error: {str(e)}",
                method=method,
                url=url
            )

    ###########################################################################
    # Status / Extras
    ###########################################################################
    def get_status_info(self, status_name):
        """
        Get status info by name.

        Args:
            status_name (str): The name of the status to retrieve

        Returns:
            dict: Status information
        """
        return self._request("GET", "extras/statuses/", params={"name": status_name})

    def get_custom_fields(self, custom_field_name):
        """
        Get custom field info by name.

        Args:
            custom_field_name (str): The label of the custom field

        Returns:
            dict: Custom field information
        """
        return self._request("GET", "extras/custom-fields/", params={"label": custom_field_name})

    def config_custom_field(self, custom_field_data):
        """
        Config custom field.

        Args:
            custom_field_data (dict): The custom field configuration data

        Returns:
            Response: The API response
        """
        return self._request("POST", "extras/custom-fields/", data=custom_field_data)

    ###########################################################################
    # IPAM - Prefixes
    ###########################################################################
    def get_namespace_id(self, namespace_name):
        """
        Get namespace information.

        Args:
            namespace_name (str): The name of the namespace

        Returns:
            dict: Namespace information
        """
        return self._request("GET", "ipam/namespaces/", params={"name": namespace_name})

    def get_prefixes(self, filter=""):
        """
        Get prefixes (optionally filtered).

        Args:
            filter (str, optional): Query filter string

        Returns:
            dict: Prefix information
        """
        params = {"q": filter} if filter else None
        return self._request("GET", "ipam/prefixes/", params=params)

    def get_exact_prefix(self, prefix):
        """
        Get a single prefix by prefix.

        Args:
            prefix (str): The prefix to retrieve (e.g., "192.168.1.0/24")

        Returns:
            Response: The API response
        """
        return self._request("GET", "ipam/prefixes/", params={"prefix": prefix})

    def create_prefix(self, prefix_parameters):
        """
        Create a new prefix.

        Args:
            prefix_parameters (dict): The prefix configuration data

        Returns:
            Response: The API response
        """
        return self._request("POST", "ipam/prefixes/", data=prefix_parameters)

    ###########################################################################
    # IPAM - IP Addresses
    ###########################################################################
    def get_addresses(self, ip_address_and_mask="", filter="", ip_address=""):
        """
        Get IP addresses by CIDR or filter.

        Args:
            ip_address_and_mask (str, optional): CIDR notation address
            filter (str, optional): Query filter
            ip_address (str, optional): IP address to search for

        Returns:
            Response: The API response
        """
        params = {}
        if ip_address_and_mask:
            params["address"] = ip_address_and_mask
        elif ip_address:
            params["q"] = ip_address
        elif filter:
            # Assuming filter is a string to be appended to the URL
            # This should probably be changed to use proper parameters
            return self._request("GET", f"ipam/ip-addresses{filter}")

        return self._request("GET", "ipam/ip-addresses/", params=params)

    def create_ip_address(self, ip_address_parameters):
        """
        Create a new IP address.

        Args:
            ip_address_parameters (dict): The IP address configuration data

        Returns:
            Response: The API response
        """
        return self._request("POST", "ipam/ip-addresses/", data=ip_address_parameters)

    def delete_addresses(self, uuid=""):
        """
        Delete an IP address by UUID.

        Args:
            uuid (str): The UUID of the IP address to delete

        Returns:
            Response: The API response
        """
        if not uuid:
            raise ValueError("UUID must be provided to delete an IP address")
        return self._request("DELETE", f"ipam/ip-addresses/{uuid}/")

    ###########################################################################
    # Virtualization - VMs and Interfaces
    ###########################################################################
    def get_vm_info(self, vm_id):
        """
        Get a single VM by ID.

        Args:
            vm_id (str): The ID of the virtual machine

        Returns:
            dict: Virtual machine information
        """
        return self._request("GET", f"virtualization/virtual-machines/{vm_id}/")

    def update_vm_fields(self, vm_id, vm_data_payload):
        """
        Patch VM fields.

        Args:
            vm_id (str): The ID of the virtual machine
            vm_data_payload (dict): The VM data to update

        Returns:
            Response: The API response
        """
        return self._request("PATCH", f"virtualization/virtual-machines/{vm_id}/", data=vm_data_payload)

    def get_nautobot_vm_id(self, vm_uuid_custom, vcenter_name):
        """
        Get a VM by custom VM UUID.

        Args:
            vm_uuid_custom (str): The custom UUID of the VM
            vcenter_name (str): The vCenter name

        Returns:
            dict: Virtual machine information
        """
        params = {
            "cf_vm_uuid": vm_uuid_custom,
            "cf_vcenter": vcenter_name
        }
        return self._request("GET", "virtualization/virtual-machines/", params=params)

    def get_vm_interface(self, vm_id):
        """
        Get interfaces for a VM.

        Args:
            vm_id (str): The ID of the virtual machine

        Returns:
            Response: The API response
        """
        return self._request("GET", "virtualization/interfaces", params={"virtual_machine": vm_id})

    def change_vm_interface(self, vm_int_id):
        """
        Get a VM interface by ID.

        Args:
            vm_int_id (str): The ID of the VM interface

        Returns:
            dict: VM interface information
        """
        return self._request("GET", f"virtualization/interfaces/{vm_int_id}/")

    def get_cluster_info(self, cluster_name):
        """
        Get cluster info by name.

        Args:
            cluster_name (str): The name of the cluster

        Returns:
            dict: Cluster information
        """
        return self._request("GET", "virtualization/clusters/", params={"name": cluster_name})

    def get_cluster_type(self, cluster_type, cluster_type_id=False):
        """
        Get cluster type information.

        Args:
            cluster_type (str): The name of the cluster type
            cluster_type_id (bool): If True, return only the ID

        Returns:
            str or dict: Cluster type ID if cluster_type_id is True, otherwise the full response
        """
        response = self._request("GET", "virtualization/cluster-types/", params={"name": cluster_type})

        if cluster_type_id:
            try:
                return response["results"][0]["id"]
            except (KeyError, IndexError):
                raise NautobotAPIError(
                    status_code=404,
                    message="Cluster type not found or has no ID",
                    method="GET",
                    url=f"{self.base_url}/virtualization/cluster-types/?name={cluster_type}"
                )

        return response

    def get_cluster_group_id(self, cluster_group):
        """
        Get cluster group info by name.

        Args:
            cluster_group (str): The name of the cluster group

        Returns:
            dict: Cluster group information
        """
        return self._request("GET", "virtualization/cluster-groups/", params={"name": cluster_group})

    def create_cluster_group(self, cluster_group_data):
        """
        Create a new cluster group.

        Args:
            cluster_group_data (dict): The cluster group configuration data

        Returns:
            Response: The API response
        """
        return self._request("POST", "virtualization/cluster-groups/", data=cluster_group_data)

    def create_cluster_type(self, cluster_type_data):
        """
        Create a new cluster type.

        Args:
            cluster_type_data (dict): The cluster type configuration data

        Returns:
            Response: The API response
        """
        return self._request("POST", "virtualization/cluster-types/", data=cluster_type_data)

    def create_cluster(self, cluster_data):
        """
        Create a new cluster.

        Args:
            cluster_data (dict): The cluster configuration data

        Returns:
            Response: The API response
        """
        return self._request("POST", "virtualization/clusters/", data=cluster_data)

    def create_vm(self, vm_json):
        """
        Create a VM.

        Args:
            vm_json (dict): The virtual machine configuration data

        Returns:
            dict: Created VM information
        """
        return self._request("POST", "virtualization/virtual-machines/", data=vm_json)

    def attach_vm_to_ipv4(self, vm_id, vm_attach_ipv4_json):
        """
        Patch VM with primary_ipv4 reference.

        Args:
            vm_id (str): The ID of the virtual machine
            vm_attach_ipv4_json (dict): The IPv4 attachment data

        Returns:
            Response: The API response
        """
        return self._request("PATCH", f"virtualization/virtual-machines/{vm_id}/", data=vm_attach_ipv4_json)

    def create_vm_interface(self, vm_int_json):
        """
        Create a VM interface.

        Args:
            vm_int_json (dict): The VM interface configuration data

        Returns:
            dict: Created VM interface information
        """
        return self._request("POST", "virtualization/interfaces/", data=vm_int_json)

    def attach_vm_interface_to_ip(self, vm_int_ip_json):
        """
        Attach an IP to a VM interface.

        Args:
            vm_int_ip_json (dict): The IP attachment data

        Returns:
            Response: The API response
        """
        return self._request("POST", "ipam/ip-address-to-interface/", data=vm_int_ip_json)

    def delete_virtual_machine(self, vm_id):
        """
        Delete a VM by ID.

        Args:
            vm_id (str): The ID of the virtual machine to delete

        Returns:
            Response: The API response
        """
        return self._request("DELETE", f"virtualization/virtual-machines/{vm_id}/")

    def delete_vm_interface(self, vm_interface_id):
        """
        Delete a VM interface by ID.

        Args:
            vm_interface_id (str): The ID of the VM interface to delete

        Returns:
            Response: The API response
        """
        return self._request("DELETE", f"virtualization/interfaces/{vm_interface_id}/")

    ###########################################################################
    # GraphQL
    ###########################################################################
    def get_graphql_info(self, graphql_filter):
        """
        Post a GraphQL query to Nautobot.

        Args:
            graphql_filter (str): The GraphQL query

        Returns:
            dict: GraphQL query results
        """
        return self._request("POST", "graphql/", data={"query": graphql_filter})