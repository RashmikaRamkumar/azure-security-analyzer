from conf.claudius_constants import subscription_id
class Load_Balancer:
    def public_load_balancer:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.resource import ResourceManagementClient
        from azure.core.exceptions import ResourceNotFoundError

        def assess_load_balancer_risk(public_ip_address):
            # Perform your risk assessment logic here
            if public_ip_address:
                return "High"  # Public load balancer detected
            else:
                return "Low"  # No public load balancer detected

        def check_public_load_balancers_in_subscription(subscription_id):
            # Authenticate using the default Azure credentials
            credential = DefaultAzureCredential()

            # Create the Network Management Client
            network_client = NetworkManagementClient(credential, subscription_id)

            # Create the Resource Management Client
            resource_client = ResourceManagementClient(credential, subscription_id)

            # Get a list of all resource groups in the subscription
            resource_groups = resource_client.resource_groups.list()

            for resource_group in resource_groups:
                print(f"\nChecking Resource Group: {resource_group.name}")

                # Check public load balancers in the current resource group
                check_public_load_balancers(network_client, resource_group.name)

        def check_public_load_balancers(network_client, resource_group_name):
            # Get a list of all load balancers in the specified resource group
            load_balancers = network_client.load_balancers.list(resource_group_name)

            for load_balancer in load_balancers:
                print(f"Checking Load Balancer: {load_balancer.name}")

                # Initialize risk level to Low
                risk_level = "Low"

                # Check if the load balancer has frontend IP configurations
                if load_balancer.frontend_ip_configurations:
                    for frontend_ip_config in load_balancer.frontend_ip_configurations:
                        # Check if the frontend IP configuration has a public IP address
                        if frontend_ip_config.public_ip_address:
                            public_ip_config_id = frontend_ip_config.public_ip_address.id
                            public_ip_name = public_ip_config_id.split('/')[-1]

                            try:
                                # Attempt to retrieve the public IP details
                                public_ip = network_client.public_ip_addresses.get(resource_group_name, public_ip_name)
                                print(
                                    f"Load Balancer '{load_balancer.name}' has a public IP address associated with frontend '{frontend_ip_config.name}'.")
                                print(f"Public IP Address: {public_ip.ip_address}")

                                # Assess risk based on the public IP address
                                risk_level = assess_load_balancer_risk(public_ip.ip_address)
                            except ResourceNotFoundError as e:
                                print(f"Error retrieving public IP details for '{public_ip_name}': {e}")
                        else:
                            print(
                                f"Load Balancer '{load_balancer.name}' does not have a public IP address associated with frontend '{frontend_ip_config.name}'.")

                else:
                    print(f"Load Balancer '{load_balancer.name}' does not have frontend IP configurations.")

                # Print the assessed risk level
                print(f"Risk Level: {risk_level}\n")

        if __name__ == "__main__":

            check_public_load_balancers_in_subscription(subscription_id)
