#!/usr/bin/env python3
"""
Origin Pool Manager - Fetch origin pool configurations from F5 Distributed Cloud
"""

import requests
import json
import sys
import yaml
import os
from typing import Optional, Dict, Any, List, Set
from collections import defaultdict


class OriginPoolManager:
    def __init__(self, cert_path: str, cert_password: str, base_url: str):
        """
        Initialize the Origin Pool Manager

        Args:
            cert_path: Path to the P12 certificate file
            cert_password: Password for the P12 certificate
            base_url: Base URL for the API
        """
        self.cert_path = cert_path
        self.cert_password = cert_password
        self.base_url = base_url
        self.pools_data = None
        self.current_pool = None
        self.pool_to_lbs = defaultdict(list)  # Mapping of pools to load balancers

    def list_origin_pools(self, namespace: str) -> Dict[str, Any]:
        """
        List all origin pools in a given namespace

        Args:
            namespace: The namespace to query

        Returns:
            The full JSON response containing all origin pools
        """
        url = f"{self.base_url}/api/config/namespaces/{namespace}/origin_pools"

        try:
            from requests_pkcs12 import Pkcs12Adapter

            session = requests.Session()
            session.mount('https://', Pkcs12Adapter(
                pkcs12_filename=self.cert_path,
                pkcs12_password=self.cert_password
            ))

            response = session.get(url, verify=True)
            response.raise_for_status()

            self.pools_data = response.json()
            return self.pools_data

        except ImportError:
            print("Warning: requests_pkcs12 not installed. Attempting alternative method...")
            return self._fetch_with_curl(url, 'list')
        except Exception as e:
            print(f"Error fetching origin pools: {e}")
            raise

    def get_origin_pool(self, namespace: str, pool_name: str) -> Dict[str, Any]:
        """
        Get a specific origin pool configuration

        Args:
            namespace: The namespace
            pool_name: The name of the origin pool

        Returns:
            The full JSON response for the specific origin pool
        """
        url = f"{self.base_url}/api/config/namespaces/{namespace}/origin_pools/{pool_name}"

        try:
            from requests_pkcs12 import Pkcs12Adapter

            session = requests.Session()
            session.mount('https://', Pkcs12Adapter(
                pkcs12_filename=self.cert_path,
                pkcs12_password=self.cert_password
            ))

            response = session.get(url, verify=True)
            response.raise_for_status()

            self.current_pool = response.json()
            return self.current_pool

        except ImportError:
            print("Warning: requests_pkcs12 not installed. Attempting alternative method...")
            return self._fetch_with_curl(url, 'get')
        except Exception as e:
            print(f"Error fetching origin pool '{pool_name}': {e}")
            raise

    def _fetch_with_curl(self, url: str, operation: str) -> Dict[str, Any]:
        """Fallback method using curl subprocess"""
        import subprocess

        cmd = [
            'curl', '-X', 'GET',
            '--cert-type', 'P12',
            '--cert', f'{self.cert_path}:{self.cert_password}',
            url
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)

            if operation == 'list':
                self.pools_data = data
            else:
                self.current_pool = data

            return data
        except subprocess.CalledProcessError as e:
            print(f"Error running curl: {e}")
            print(f"stderr: {e.stderr}")
            raise
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {e}")
            raise

    def get_pool_names(self) -> List[str]:
        """
        Extract all pool names from the list response

        Returns:
            List of origin pool names
        """
        if not self.pools_data:
            raise ValueError("No pool data available. Call list_origin_pools first.")

        try:
            if "items" in self.pools_data:
                return [item["name"] for item in self.pools_data["items"]]
            else:
                return []
        except (KeyError, TypeError):
            return []

    def list_http_loadbalancers(self, namespace: str) -> List[str]:
        """
        List all HTTP load balancers in a namespace

        Args:
            namespace: The namespace to query

        Returns:
            List of HTTP load balancer names
        """
        url = f"{self.base_url}/api/config/namespaces/{namespace}/http_loadbalancers"

        try:
            from requests_pkcs12 import Pkcs12Adapter

            session = requests.Session()
            session.mount('https://', Pkcs12Adapter(
                pkcs12_filename=self.cert_path,
                pkcs12_password=self.cert_password
            ))

            response = session.get(url, verify=True)
            response.raise_for_status()

            data = response.json()
            lb_names = []

            if "items" in data:
                lb_names = [item["name"] for item in data["items"]]

            return lb_names

        except ImportError:
            return self._list_lbs_with_curl(url)
        except Exception as e:
            print(f"Error listing HTTP load balancers: {e}")
            return []

    def _list_lbs_with_curl(self, url: str) -> List[str]:
        """Fallback method using curl subprocess for listing LBs"""
        import subprocess

        cmd = [
            'curl', '-X', 'GET',
            '--cert-type', 'P12',
            '--cert', f'{self.cert_path}:{self.cert_password}',
            '-s',
            url
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)

            if "items" in data:
                return [item["name"] for item in data["items"]]
            return []
        except Exception:
            return []

    def get_http_loadbalancer(self, namespace: str, lb_name: str) -> Dict[str, Any]:
        """
        Get a specific HTTP load balancer configuration

        Args:
            namespace: The namespace
            lb_name: The name of the HTTP load balancer

        Returns:
            The full JSON response for the load balancer
        """
        url = f"{self.base_url}/api/config/namespaces/{namespace}/http_loadbalancers/{lb_name}"

        try:
            from requests_pkcs12 import Pkcs12Adapter

            session = requests.Session()
            session.mount('https://', Pkcs12Adapter(
                pkcs12_filename=self.cert_path,
                pkcs12_password=self.cert_password
            ))

            response = session.get(url, verify=True)
            response.raise_for_status()

            return response.json()

        except ImportError:
            return self._get_lb_with_curl(url)
        except Exception:
            return {}

    def _get_lb_with_curl(self, url: str) -> Dict[str, Any]:
        """Fallback method using curl subprocess for getting LB"""
        import subprocess

        cmd = [
            'curl', '-X', 'GET',
            '--cert-type', 'P12',
            '--cert', f'{self.cert_path}:{self.cert_password}',
            '-s',
            url
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except Exception:
            return {}

    def extract_origin_pools_from_lb(self, lb_config: Dict[str, Any]) -> Set[str]:
        """
        Extract all origin pool references from an HTTP load balancer configuration

        Args:
            lb_config: The load balancer configuration

        Returns:
            Set of origin pool names referenced in the configuration
        """
        pools = set()

        def search_for_pools(obj):
            """Recursively search for origin pool references"""
            if isinstance(obj, dict):
                # Check for common origin pool reference patterns
                if "origin_pool" in obj:
                    pool_ref = obj["origin_pool"]
                    if isinstance(pool_ref, dict):
                        if "name" in pool_ref:
                            pools.add(pool_ref["name"])
                        elif "pool" in pool_ref:
                            if isinstance(pool_ref["pool"], dict) and "name" in pool_ref["pool"]:
                                pools.add(pool_ref["pool"]["name"])

                # Check for pool in routes
                if "pool" in obj and isinstance(obj["pool"], dict):
                    if "name" in obj["pool"]:
                        pools.add(obj["pool"]["name"])

                # Recursively search all dict values
                for value in obj.values():
                    search_for_pools(value)

            elif isinstance(obj, list):
                # Recursively search all list items
                for item in obj:
                    search_for_pools(item)

        # Start the search from the spec
        if "spec" in lb_config:
            search_for_pools(lb_config["spec"])

        return pools

    def map_pools_to_loadbalancers(self, namespace: str, verbose: bool = True):
        """
        Create a mapping of origin pools to HTTP load balancers

        Args:
            namespace: The namespace to scan
            verbose: If True, print progress information
        """
        if verbose:
            print(f"\nScanning HTTP load balancers for origin pool references...")

        lb_names = self.list_http_loadbalancers(namespace)

        if not lb_names:
            if verbose:
                print(f"  No HTTP load balancers found in namespace '{namespace}'")
            return

        if verbose:
            print(f"  Found {len(lb_names)} HTTP load balancer(s)")

        # Clear existing mappings
        self.pool_to_lbs.clear()

        # Scan each load balancer
        for lb_name in lb_names:
            lb_config = self.get_http_loadbalancer(namespace, lb_name)
            if not lb_config:
                continue

            pools = self.extract_origin_pools_from_lb(lb_config)

            for pool_name in pools:
                self.pool_to_lbs[pool_name].append(lb_name)

        if verbose:
            pools_with_refs = len([p for p in self.pool_to_lbs if self.pool_to_lbs[p]])
            print(f"  Found {pools_with_refs} origin pool(s) with HTTP LB references\n")

    def get_pool_summary(self, pool_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Extract key information from a pool configuration

        Args:
            pool_data: Pool data to summarize. If None, uses current_pool

        Returns:
            Dictionary with summary information
        """
        data = pool_data or self.current_pool
        if not data:
            raise ValueError("No pool data available")

        summary = {
            "name": data.get("metadata", {}).get("name", "Unknown"),
            "namespace": data.get("metadata", {}).get("namespace", "Unknown"),
        }

        # Add referring load balancers from mapping
        pool_name = summary["name"]
        summary["referring_loadbalancers"] = self.pool_to_lbs.get(pool_name, [])

        spec = data.get("spec", {})

        # Get origin servers
        origin_servers = spec.get("origin_servers", [])
        summary["origin_server_count"] = len(origin_servers)
        summary["origin_servers"] = []

        for server in origin_servers:
            server_info = {}

            # Check different origin server types
            if "public_name" in server:
                server_info["type"] = "public_name"
                server_info["dns_name"] = server["public_name"].get("dns_name", "")
            elif "public_ip" in server:
                server_info["type"] = "public_ip"
                server_info["ip"] = server["public_ip"].get("ip", "")
            elif "private_name" in server:
                server_info["type"] = "private_name"
                server_info["dns_name"] = server["private_name"].get("dns_name", "")
            elif "private_ip" in server:
                server_info["type"] = "private_ip"
                server_info["ip"] = server["private_ip"].get("ip", "")
            elif "k8s_service" in server:
                server_info["type"] = "k8s_service"
                server_info["service_name"] = server["k8s_service"].get("service_name", "")
            elif "consul_service" in server:
                server_info["type"] = "consul_service"
                server_info["service_name"] = server["consul_service"].get("service_name", "")

            summary["origin_servers"].append(server_info)

        # Get port information
        summary["port"] = spec.get("port", "Unknown")

        # Get load balancer algorithm
        if "loadbalancer_algorithm" in spec:
            summary["lb_algorithm"] = spec["loadbalancer_algorithm"]
        else:
            summary["lb_algorithm"] = "Not specified"

        # Get health check info
        if "health_check" in spec:
            health_checks = spec["health_check"]
            summary["health_checks"] = []
            for hc in health_checks:
                hc_info = {}
                if "http_health_check" in hc:
                    hc_info["type"] = "HTTP"
                    hc_info["path"] = hc["http_health_check"].get("path", "/")
                elif "https_health_check" in hc:
                    hc_info["type"] = "HTTPS"
                    hc_info["path"] = hc["https_health_check"].get("path", "/")
                elif "tcp_health_check" in hc:
                    hc_info["type"] = "TCP"
                elif "udp_health_check" in hc:
                    hc_info["type"] = "UDP"

                summary["health_checks"].append(hc_info)
        else:
            summary["health_checks"] = []

        return summary

    def display_pools_list(self):
        """Display a summary of all origin pools"""
        if not self.pools_data:
            print("No pools data available")
            return

        print("\n" + "="*60)
        print("Origin Pools List")
        print("="*60)

        pool_names = self.get_pool_names()
        if not pool_names:
            print("\nNo origin pools found")
        else:
            print(f"\nTotal pools: {len(pool_names)}\n")
            for idx, name in enumerate(pool_names, 1):
                print(f"{idx}. {name}")

        print("="*60 + "\n")

    def display_pool_details(self, pool_data: Optional[Dict[str, Any]] = None):
        """
        Display detailed information about an origin pool

        Args:
            pool_data: Pool data to display. If None, uses current_pool
        """
        try:
            summary = self.get_pool_summary(pool_data)
        except ValueError as e:
            print(f"Error: {e}")
            return

        print("\n" + "="*60)
        print("Origin Pool Details")
        print("="*60)

        print(f"\nName: {summary['name']}")
        print(f"Namespace: {summary['namespace']}")
        print(f"Port: {summary['port']}")
        print(f"Load Balancer Algorithm: {summary['lb_algorithm']}")

        print(f"\n--- Origin Servers ({summary['origin_server_count']}) ---")
        for idx, server in enumerate(summary['origin_servers'], 1):
            print(f"\n  Server {idx}:")
            print(f"    Type: {server.get('type', 'Unknown')}")
            if 'dns_name' in server:
                print(f"    DNS Name: {server['dns_name']}")
            elif 'ip' in server:
                print(f"    IP: {server['ip']}")
            elif 'service_name' in server:
                print(f"    Service: {server['service_name']}")

        if summary['health_checks']:
            print(f"\n--- Health Checks ({len(summary['health_checks'])}) ---")
            for idx, hc in enumerate(summary['health_checks'], 1):
                print(f"\n  Health Check {idx}:")
                print(f"    Type: {hc.get('type', 'Unknown')}")
                if 'path' in hc:
                    print(f"    Path: {hc['path']}")
        else:
            print("\n--- Health Checks ---")
            print("  No health checks configured")

        # Display referring load balancers
        if summary.get('referring_loadbalancers'):
            lbs = summary['referring_loadbalancers']
            print(f"\n--- Used by HTTP Load Balancers ({len(lbs)}) ---")
            for idx, lb_name in enumerate(sorted(lbs), 1):
                print(f"  {idx}. {lb_name}")
        else:
            print("\n--- Used by HTTP Load Balancers ---")
            print("  Not currently used by any HTTP load balancers")

        print("\n" + "="*60 + "\n")

    def save_to_file(self, filename: str, data: Optional[Dict[str, Any]] = None):
        """
        Save configuration to a file

        Args:
            filename: Output filename
            data: Data to save. If None, uses pools_data or current_pool
        """
        output_data = data or self.pools_data or self.current_pool

        if not output_data:
            raise ValueError("No data available to save")

        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=2)

        print(f"Configuration saved to {filename}")

    def save_all_pools(self, namespace: str, output_dir: str = "."):
        """
        Fetch and save all origin pools individually

        Args:
            namespace: The namespace to query
            output_dir: Directory to save pool configurations (default: current directory)
        """
        import os

        if not self.pools_data:
            print("Fetching pools list...")
            self.list_origin_pools(namespace)

        pool_names = self.get_pool_names()

        if not pool_names:
            print("No pools found")
            return

        print(f"\nFetching and saving {len(pool_names)} origin pools...")

        for pool_name in pool_names:
            try:
                print(f"  Fetching: {pool_name}...")
                pool_data = self.get_origin_pool(namespace, pool_name)

                filename = os.path.join(output_dir, f"origin_pool_{pool_name}.json")
                self.save_to_file(filename, pool_data)

            except Exception as e:
                print(f"  Error fetching {pool_name}: {e}")

        print(f"\nCompleted. Pools saved to {output_dir}/")


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file

    Args:
        config_path: Path to the config file

    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_path}' not found")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file: {e}")
        sys.exit(1)


def main():
    """Example usage"""
    # Load configuration from YAML file
    config = load_config()

    # Extract API configuration
    api_config = config.get('api', {})
    CERT_PATH = api_config.get('cert_path')
    CERT_PASSWORD = api_config.get('cert_password')
    BASE_URL = api_config.get('base_url')

    # Extract origin pool configuration
    pool_config = config.get('origin_pool', {})
    NAMESPACE = pool_config.get('namespace')
    OUTPUT_DIR = pool_config.get('output_dir', '.')

    # Validate required configuration
    if not all([CERT_PATH, CERT_PASSWORD, BASE_URL, NAMESPACE]):
        print("Error: Missing required configuration values")
        print("Please check config.yaml file")
        sys.exit(1)

    # Create manager instance
    manager = OriginPoolManager(CERT_PATH, CERT_PASSWORD, BASE_URL)

    try:
        # List all origin pools
        print("Fetching origin pools list...")
        manager.list_origin_pools(NAMESPACE)

        # Display the list
        manager.display_pools_list()

        # Save the list to file
        manager.save_to_file('origin_pools_list.json')

        # Map pools to load balancers
        manager.map_pools_to_loadbalancers(NAMESPACE, verbose=True)

        # Fetch and display details for all pools
        pool_names = manager.get_pool_names()
        if pool_names:
            print(f"\nFetching details for all {len(pool_names)} origin pools...\n")

            # Create output directory if it doesn't exist
            if not os.path.exists(OUTPUT_DIR):
                os.makedirs(OUTPUT_DIR)
                print(f"Created output directory: {OUTPUT_DIR}\n")

            for idx, pool_name in enumerate(pool_names, 1):
                try:
                    print(f"[{idx}/{len(pool_names)}] Fetching: {pool_name}...")
                    manager.get_origin_pool(NAMESPACE, pool_name)
                    manager.display_pool_details()

                    # Save individual pool config
                    filename = os.path.join(OUTPUT_DIR, f'origin_pool_{pool_name}.json')
                    manager.save_to_file(filename)

                except Exception as e:
                    print(f"  Error fetching {pool_name}: {e}\n")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
