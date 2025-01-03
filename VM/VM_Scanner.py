from azure.mgmt.recoveryservices import RecoveryServicesClient

from conf.claudius_constants import subscription_id, resource_group_name, vm_name

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient


class VM_scanner:
    def Low_VM_Instant_Restore_Backup_Retention_Limit(self):

        # Set the desired backup retention days
        retention_days = 30  # Change this to your desired value

        # Initialize Azure credentials
        credentials = DefaultAzureCredential()

        # Initialize Compute Management Client
        compute_client = ComputeManagementClient(credentials, subscription_id)

        # Get the VM
        vm = compute_client.virtual_machines.get(resource_group_name, vm_name)

        # Find the backup extension in the virtual machine extensions
        backup_extension = next((ext for ext in vm.resources if ext.name == 'AzureBackupVM'), None)

        if backup_extension:
            # Access the backup profile and update the retention policy
            backup_profile = backup_extension.settings['instantRpRetentionRangeInDays']
            backup_profile['value'] = retention_days

            # Update the VM
            compute_client.virtual_machines.create_or_update(resource_group_name, vm_name, vm)

            # Additional details to print if the backup extension is found
            print("Backup Settings Updated:")
            print(f"VM Name: {vm.name}")
            print(f"Resource Group: {resource_group_name}")
            print(f"Instant restore backup retention limit set to {retention_days} days.")
            print("Vulnerability: Low VM Instant Restore Backup Retention Limit")


        else:
            # Details to print if the backup extension is not found
            print("subscription_id is: ", subscription_id)
            print("resource_group_name is: ", resource_group_name)
            print("vm_name is :", vm_name)
            print("Vulnerability: Low VM Instant Restore Backup Retention Limit")
            print("Azure Backup extension not found on the virtual machine.")

    def undisered_SKU_size(self,vm_desired_sizes, resource_group_name, vm_name):
        def add_vulnerability_to_database(vulnerability):
            # Assuming there's a function to add the vulnerability to the database
            # This could be a call to an API, a database insertion, or any other method
            print("Adding vulnerability to the database:")
            print(f"  vulnerability_id: {vulnerability['vulnerability_id']}")
            print(f"  description: {vulnerability['description']}")
            print(f"  resource: {vulnerability['resource']}")
            print(f"  detailed_vulnerability_message: {vulnerability['detailed_vulnerability_message']}")
        vulnerability_id = '123'
        description = 'Undesired VM SKU Size'

        # Authenticate to Azure using default credentials
        credentials = DefaultAzureCredential()
        compute_client = ComputeManagementClient(credentials, '494a8e9a-3d2c-4a53-b3fa-6deb19b9fa74')

        # Get VM details
        vm = compute_client.virtual_machines.get(resource_group_name, vm_name)

        # Check if the VM SKU size is in the desired list
        vm_size = vm.hardware_profile.vm_size
        if vm_size not in vm_desired_sizes:
            # Raise an issue or take necessary action
            print(f"Issue: VM {vm_name} in resource group {resource_group_name} has an undesired SKU size: {vm_size}")

            # Assuming you have a vulnerability object or data structure
            vulnerability = {
                'vulnerability_id': vulnerability_id,
                'description': description,
                'resource': f'/subscriptions/494a8e9a-3d2c-4a53-b3fa-6deb19b9fa74/resourceGroups/{resource_group_name}/providers/Microsoft.Compute/virtualMachines/{vm_name}',
                'detailed_vulnerability_message': f"VM {vm_name} has an undesired SKU size."
            }

            # Assuming you have a function to add this vulnerability to a database or system
            add_vulnerability_to_database(vulnerability)


    def Recovery_Services_Vault(self,resource_group_name, vm_name):
        credentials = DefaultAzureCredential()

        recovery_services_client = RecoveryServicesClient(credentials, subscription_id)

        # Get VM details
        compute_client = ComputeManagementClient(credentials, subscription_id)
        vm = compute_client.virtual_machines.get(resource_group_name, vm_name)

        # Check if VM has a recovery services vault configured
        if vm.identity and 'Microsoft.RecoveryServices/vaults' not in vm.identity.type:
            # Raise an issue or take necessary action
            print("with the subscription_id:", subscription_id)
            print(
                f"Issue: VM {vm_name} in resource group {resource_group_name} does not have a Recovery Services vault configured.")
        else:
            # Print a message indicating that the VM has a Recovery Services vault configured
            print("with the subscription_id:", subscription_id)
            print(f"VM {vm_name} in resource group {resource_group_name} has a Recovery Services vault configured.")

