from conf.claudius_constants import subscription_id
import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient


class NGS_Scanner:
    def openRDP(self):

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_rdp_rules(subscription_id):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            for nsg in nsgs:
                # Reset rdp_found for each NSG iteration
                rdp_found = False

                # Check inbound security rules for TCP port 3389 in each NSG
                for rule in nsg.security_rules:
                    if rule.protocol == 'TCP' and rule.destination_port_range == '3389' and rule.direction == 'Inbound':
                        if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*':
                            # Extract the resource group from the NSG ID
                            resource_group = get_resource_group_from_id(nsg.id)

                            print(
                                f"Inbound rule '{rule.name}' for TCP port 3389 in NSG '{nsg.name}' in Resource Group '{resource_group}' is exposed to the public (ALLOW from ANY source to ANY destination).")
                            print("Risk level: High")

                            rdp_found = True

                if not rdp_found:
                    # If no rule is found for TCP port 3389
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"No inbound rule found for TCP port 3389 in NSG '{nsg.name}' in Resource Group '{resource_group}'.")


        check_rdp_rules(conf.subscription_id)
    def openRPC(self):
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_nsg_rules(subscription_id, resource_group):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            for nsg in nsgs:
                # Check inbound security rules for TCP port 135 in each NSG
                for rule in nsg.security_rules:
                    if rule.protocol == 'TCP' and rule.destination_port_range == '135' and rule.direction == 'Inbound' and rule.name == 'RPC':
                        if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*':
                            # Extract the resource group from the NSG ID
                            resource_group = get_resource_group_from_id(nsg.id)

                            print(
                                f"Inbound rule '{rule.name}' for TCP port 135 in NSG '{nsg.name}' in Resource Group '{resource_group}' is exposed to the public (ALLOW from ANY source to ANY destination).")
                            print("Risk level: High")
                        else:
                            print(
                                f"Inbound rule '{rule.name}' for TCP port 135 in NSG '{nsg.name}' in Resource Group '{resource_group}' exists but may be restricted to specific addresses.")
                            print("Risk level: Low")
                        return

            # If no rule is found for TCP port 135
            print("No inbound rule found for TCP port 135 in any NSG.")

        # Replace with your Azure subscription ID
        

        check_nsg_rules(subscription_id)
    def open_ssh(self):
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_ssh_open(subscription_id):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            for nsg in nsgs:
                ssh_open = False

                # Check security rules for TCP port 22 with ANY source and destination
                for rule in nsg.security_rules:
                    if rule.protocol == 'TCP' and rule.destination_port_range == '22' and rule.direction == 'Inbound':
                        if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*':
                            # Extract the resource group from the NSG ID
                            resource_group = get_resource_group_from_id(nsg.id)

                            print(
                                f"Inbound rule '{rule.name}' for TCP port 22 in NSG '{nsg.name}' in Resource Group '{resource_group}' is exposed to the public (ALLOW from ANY source to ANY destination).")
                            print("Risk level: High")

                            ssh_open = True

                # Print a message if no rule is found for TCP port 22
                if not ssh_open:
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"No inbound rule found for TCP port 22 in NSG '{nsg.name}' in Resource Group '{resource_group}'.")

        check_ssh_open(subscription_id)
    def open_VNS_Server(self):
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_vnc_server_open(subscription_id):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            for nsg in nsgs:
                vnc_server_open = False

                # Check security rules for TCP port 5900 with ANY source and destination
                for rule in nsg.security_rules:
                    if rule.protocol == 'TCP' and rule.destination_port_range == '5900' and rule.direction == 'Inbound':
                        if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*':
                            # Extract the resource group from the NSG ID
                            resource_group = get_resource_group_from_id(nsg.id)

                            print(
                                f"Inbound rule '{rule.name}' for TCP port 5900 in NSG '{nsg.name}' in Resource Group '{resource_group}' is exposed to the public (ALLOW from ANY source to ANY destination).")
                            print("Risk level: High")

                            vnc_server_open = True
                        else:
                            print(
                                f"Inbound rule '{rule.name}' for TCP port 5900 in NSG '{nsg.name}' in Resource Group '{resource_group}' exists but may be restricted to specific addresses.")
                            print("Risk level: Low")

                # Print a message if no rule is found for TCP port 5900
                if not vnc_server_open:
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"No inbound rule found for TCP port 5900 in NSG '{nsg.name}' in Resource Group '{resource_group}'.")


        check_vnc_server_open(subscription_id)

    def open_all_ports:
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_all_ports_open(subscription_id):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            # List to store resource groups with vulnerabilities
            vulnerable_resource_groups = []

            for nsg in nsgs:
                all_ports_open = False

                # Check security rules for ANY source and destination, indicating all ports open
                for rule in nsg.security_rules:
                    if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*' and rule.direction == 'Inbound':
                        # Extract the resource group from the NSG ID
                        resource_group = get_resource_group_from_id(nsg.id)

                        print(
                            f"Inbound rule '{rule.name}' in NSG '{nsg.name}' in Resource Group '{resource_group}' allows traffic from ANY source to ANY destination (opening all ports).")
                        print("Risk level: High")

                        # Add the resource group to the list if it has vulnerabilities
                        vulnerable_resource_groups.append(resource_group)

                        all_ports_open = True

                if not all_ports_open:
                    # If no rule is found opening all ports
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"No inbound rule found opening all ports in NSG '{nsg.name}' in Resource Group '{resource_group}'.")

            # Check if there are vulnerable resource groups and print a message for others
            all_resource_groups = {get_resource_group_from_id(nsg.id) for nsg in nsgs}
            non_vulnerable_resource_groups = all_resource_groups - set(vulnerable_resource_groups)

            if non_vulnerable_resource_groups:
                print("No vulnerabilities found in the following resource groups:")
                for resource_group in non_vulnerable_resource_groups:
                    print(f"- {resource_group}")

        check_all_ports_open(subscription_id)
    def open_FTP:
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_ftp_ports_open(subscription_id):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            # Define the ports to check
            ftp_ports = ['20', '21']

            for nsg in nsgs:
                ftp_ports_open = []

                # Check security rules for TCP ports 20 and 21 with ANY source and destination
                for rule in nsg.security_rules:
                    if rule.protocol == 'TCP' and rule.destination_port_range in ftp_ports and rule.direction == 'Inbound':
                        if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*':
                            # Add the exposed port to the list
                            ftp_ports_open.append(rule.destination_port_range)

                # Print risk level and detailed statements if TCP ports 20 or 21 are exposed
                for port in ftp_ports_open:
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"Inbound rule '{rule.name}' for TCP port {port} in NSG '{nsg.name}' in Resource Group '{resource_group}' is exposed to the public (ALLOW from ANY source to ANY destination). Risk level: High")

                if not ftp_ports_open:
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"No inbound rule found for TCP ports 20 and 21 in NSG '{nsg.name}' in Resource Group '{resource_group}'.")

        check_ftp_ports_open(subscription_id)
    def open_hadoop_metadata:
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_hdfs_namenode_port_open(subscription_id):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            # Define the port to check
            hdfs_namenode_port = '8020'

            for nsg in nsgs:
                hdfs_namenode_port_open = False

                # Check security rules for TCP port 8020 with ANY source and destination
                for rule in nsg.security_rules:
                    if rule.protocol == 'TCP' and rule.destination_port_range == hdfs_namenode_port and rule.direction == 'Inbound':
                        if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*':
                            # Set the flag if the port is exposed
                            hdfs_namenode_port_open = True

                # Print risk level and detailed statement if TCP port 8020 is exposed
                if hdfs_namenode_port_open:
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"Inbound rule '{rule.name}' for TCP port {hdfs_namenode_port} in NSG '{nsg.name}' in Resource Group '{resource_group}' is exposed to the public (ALLOW from ANY source to ANY destination). Risk level: High")
                else:
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"No inbound rule found for TCP port {hdfs_namenode_port} in NSG '{nsg.name}' in Resource Group '{resource_group}'.")


        check_hdfs_namenode_port_open(subscription_id)
    def open_Postgresql(self):

        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_postgresql_rules(subscription_id):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            for nsg in nsgs:
                # Check inbound security rules for TCP port 5432 in each NSG
                for rule in nsg.security_rules:
                    if rule.protocol == 'TCP' and rule.destination_port_range == '5432' and rule.direction == 'Inbound':
                        if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*':
                            # Extract the resource group from the NSG ID
                            resource_group = get_resource_group_from_id(nsg.id)

                            print(
                                f"Inbound rule '{rule.name}' for TCP port 5432 in NSG '{nsg.name}' in Resource Group '{resource_group}' is exposed to the public (ALLOW from ANY source to ANY destination).")
                            print("Risk level: High")
                        else:
                            print(
                                f"Inbound rule '{rule.name}' for TCP port 5432 in NSG '{nsg.name}' in Resource Group '{resource_group}' exists but may be restricted to specific addresses.")
                            print("Risk level: Low")

            # If no rule is found for TCP port 5432
            print("No inbound rule found for TCP port 5432 in any NSG.")

        check_postgresql_rules(subscription_id)
    def open_Oracele_auto_data_warehouse(self):
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_oracle_adw_open(subscription_id):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            for nsg in nsgs:
                oracle_adw_open = False

                # Check security rules for TCP port 1522 with ANY source and destination
                for rule in nsg.security_rules:
                    if rule.protocol == 'TCP' and rule.destination_port_range == '1522' and rule.direction == 'Inbound':
                        if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*':
                            # Extract the resource group from the NSG ID
                            resource_group = get_resource_group_from_id(nsg.id)

                            print(
                                f"Inbound rule '{rule.name}' for TCP port 1522 in NSG '{nsg.name}' in Resource Group '{resource_group}' is exposed to the public (ALLOW from ANY source to ANY destination).")
                            print("Risk level: High")

                            oracle_adw_open = True
                        else:
                            print(
                                f"Inbound rule '{rule.name}' for TCP port 1522 in NSG '{nsg.name}' in Resource Group '{resource_group}' exists but may be restricted to specific addresses.")
                            print("Risk level: Low")

                # Print a message if no rule is found for TCP port 1522
                if not oracle_adw_open:
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"No inbound rule found for TCP port 1522 in NSG '{nsg.name}' in Resource Group '{resource_group}'.")

        check_oracle_adw_open(subscription_id)
    def open_hadoop_webui(self):
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        def get_resource_group_from_id(resource_id):
            # Extract resource group from the resource ID
            parts = resource_id.split('/')
            resource_group = parts[4]  # Adjust the index based on the resource ID format
            return resource_group

        def check_hadoop_ports_open(subscription_id):
            # Create a Network Management client
            network_client = NetworkManagementClient(
                DefaultAzureCredential(),
                subscription_id
            )

            # Get all NSGs in the subscription
            nsgs = network_client.network_security_groups.list_all()

            # Define the ports to check
            hadoop_ports = ['50070', '50470']

            for nsg in nsgs:
                hadoop_ports_open = []

                # Check security rules for TCP ports 50070 and 50470 with ANY source and destination
                for rule in nsg.security_rules:
                    if rule.protocol == 'TCP' and rule.destination_port_range in hadoop_ports and rule.direction == 'Inbound':
                        if rule.source_address_prefix == '*' and rule.destination_address_prefix == '*':
                            # Add the exposed port to the list
                            hadoop_ports_open.append(rule.destination_port_range)

                # Print risk level and detailed statements if TCP ports 50070 or 50470 are exposed
                for port in hadoop_ports_open:
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"Inbound rule '{rule.name}' for TCP port {port} in NSG '{nsg.name}' in Resource Group '{resource_group}' is exposed to the public (ALLOW from ANY source to ANY destination). Risk level: High")

                if not hadoop_ports_open:
                    resource_group = get_resource_group_from_id(nsg.id)
                    print(
                        f"No inbound rule found for TCP ports 50070 and 50470 in NSG '{nsg.name}' in Resource Group '{resource_group}'.")

        check_hadoop_ports_open(subscription_id)
    


