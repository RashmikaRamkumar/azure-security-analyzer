from azure.mgmt.containerregistry import ContainerRegistryManagementClient

from conf.claudius_constants import resource_group_name, subscription_id, tenant_id
from vulnerability.azure.Load_Balancers.balancer_scanner import DefaultAzureCredential


class Registries_Scanner:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.containerregistry import ContainerRegistryManagementClient

    def disable_admin_user(subscription_id, tenant_id, resource_group_name, vulnerability, description, resource,detailed_vulnerability_message):

        #pip install azure-mgmt-containerregistry
        subscription_id = subscription_id.strip()

        # Create a service principal using DefaultAzureCredential
        credentials = DefaultAzureCredential()

        # Create the ContainerRegistryManagementClient
        client = ContainerRegistryManagementClient(
            credentials,
            subscription_id,
        )

        # Get a list of all registries in the specified resource group
        registries = client.registries.list_by_resource_group(resource_group_name)

        for registry in registries:
            registry_name = registry.name
            registry_info = client.registries.get(resource_group_name, registry_name)
            registry_info.admin_user_enabled = False
            client.registries.begin_update(resource_group_name, registry_name, registry_info).wait()

            vulnerability = 'High'
            description = 'Azure Container_Registries with Admin User'
            resource = 'Container Registry'
            detailed_vulnerability_message = 'This plugin ensures that the admin user is not enabled on container registries...'
            # Print details for the vulnerability
            print(f"Vulnerability: {vulnerability}")
            print(f"Description: {description}")
            print(f"Resource: {resource}")
            print(f"Detailed Vulnerability Message: {detailed_vulnerability_message}")
            print(f"Admin user disabled for Azure Container Registry: {registry_name}")



        disable_admin_user(subscription_id, tenant_id, resource_group_name)