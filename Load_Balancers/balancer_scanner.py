

import azure.identity
from azure.mgmt.network import NetworkManagementClient

from conf.claudius_constants import subscription_id


class DefaultAzureCredential:
    pass


class BALANCER_scanner:

    def Load_Balancers_Without_Instances(self):

        # Set the default Azure credentials
        credentials = DefaultAzureCredential()

        # Create a Network Management client
        network_client = NetworkManagementClient(credentials, subscription_id)

        # Get the list of load balancers
        load_balancers = network_client.load_balancers.list_all()

        # Check if there are load balancers without associated instances
        load_balancers_without_instances = [
            lb.name for lb in load_balancers
            if not lb.backend_address_pools
        ]

        # Print information about load balancers without instances
        if load_balancers_without_instances:
            print("Load Balancers Without Instances found:")
            for lb_name in load_balancers_without_instances:
                print(f"  Load Balancer: {lb_name}")
        else:
            print("No Load Balancers Without Instances found.")
        pass
    def insecure_ports(self):

        # Set the default Azure credentials
        credentials = DefaultAzureCredential()

        # Create a Network Management client
        network_client = NetworkManagementClient(credentials, subscription_id)

        # Get the list of load balancers
        load_balancers = list(network_client.load_balancers.list_all())

        # Check if there are no load balancers
        if not load_balancers:
            print("No Load Balancers found.")
        else:
            # Check for insecure ports open for each load balancer
            for load_balancer in load_balancers:
                insecure_ports = [
                    rule for rule in load_balancer.inbound_nat_rules
                    if rule.frontend_port in {80, 443}
                ]

                # Print information about insecure ports for each load balancer
                if insecure_ports:
                    print(f"\nInsecure Ports Open for Load Balancer '{load_balancer.name}':")
                    for rule in insecure_ports:
                        print(f"  Rule Name: {rule.name}, Frontend Port: {rule.frontend_port}")
                else:
                    print(f"\nNo Insecure Ports Open for Load Balancer '{load_balancer.name}'.")
        pass
