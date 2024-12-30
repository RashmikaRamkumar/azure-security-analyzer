class key_vaults_scanner:
    def key_vault_recovery_disabled:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
        from azure.mgmt.keyvault import KeyVaultManagementClient
        from azure.mgmt.resource import ResourceManagementClient
        from azure.core.exceptions import HttpResponseError

        def get_all_key_vaults():
            # Use DefaultAzureCredential to authenticate with Azure services
            credential = DefaultAzureCredential()

            # Create a ResourceManagementClient for working with Azure resources
            resource_client = ResourceManagementClient(credential, "494a8e9a-3d2c-4a53-b3fa-6deb19b9fa74")

            # List all resources of type 'Microsoft.KeyVault/vaults' in the subscription
            key_vaults = resource_client.resources.list(filter="resourceType eq 'Microsoft.KeyVault/vaults'")

            # Extract and return the list of Key Vault names
            return [vault.name for vault in key_vaults]

        def check_recovery_status_for_all_secrets_in_vaults(vault_names):
            for vault_name in vault_names:
                key_vault_url = f"https://{vault_name}.vault.azure.net/"

                # Use DefaultAzureCredential to authenticate with Azure services
                credential = DefaultAzureCredential()

                # Create a SecretClient for working with the key vault
                secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

                try:
                    # Get a list of all secrets in the key vault
                    secrets = secret_client.list_properties_of_secrets()

                    # Check if there are no secrets
                    if not secrets:
                        print(f"No secrets found in the Key Vault '{vault_name}'.")
                        continue

                    for secret in secrets:
                        # Retrieve the properties of each secret
                        secret_properties = secret_client.get_secret(secret.name).properties

                        # Check if soft delete and purge protection are both enabled
                        if secret_properties.recovery_level == "Purgeable":
                            print(
                                f"Secret '{secret.name}' in Key Vault '{vault_name}': Soft delete and purge protection are enabled.")
                        elif secret_properties.recovery_level == "Recoverable":
                            # Check if recoverable_days attribute is available
                            if hasattr(secret_properties, 'recoverable_days'):
                                print(
                                    f"Secret '{secret.name}' in Key Vault '{vault_name}': Soft delete is enabled, and purge protection may be enforced with {secret_properties.recoverable_days} days until purge.")
                            else:
                                print(
                                    f"Secret '{secret.name}' in Key Vault '{vault_name}': Soft delete is enabled, but purge protection status is inconclusive. Risk Level: Medium")
                        else:
                            print(
                                f"Secret '{secret.name}' in Key Vault '{vault_name}': Soft delete is not enabled. Risk Level: Medium")

                            # Print additional message or take actions for the medium risk level

                except HttpResponseError as e:
                    print(f"Error for Key Vault '{vault_name}': {e}")

        if __name__ == "__main__":
            # Get all Key Vaults in the subscription
            all_vaults = get_all_key_vaults()

            # Check recovery status for secrets in each Key Vault
            check_recovery_status_for_all_secrets_in_vaults(all_vaults)
    def secert_expiration_disabled(self):
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
        from datetime import datetime, timedelta

        def check_key_expiration(key_vault_url):
            # Authenticate using the default Azure credentials
            credential = DefaultAzureCredential()
            secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

            # Get a list of all secrets in the Key Vault
            secrets = secret_client.list_properties_of_secrets()

            for secret in secrets:
                # Get the secret's properties, including expiration time
                secret_properties = secret_client.get_secret(secret.name).properties

                # Check if expiration time is set
                if secret_properties.expires_on is None:
                    print(f"Key '{secret.name}' does not have an expiration time set. Risk Level: High")
                else:
                    expiration_time = secret_properties.expires_on
                    current_time = datetime.utcnow()

                    # Check if the key is expired or close to expiration
                    if current_time > expiration_time - timedelta(days=30):  # You can adjust the threshold as needed
                        print(f"Key '{secret.name}' is close to expiration or already expired. Risk Level: Low")
                    else:
                        print(f"Key '{secret.name}' is within the acceptable expiration period. Risk Level: Low")

        if __name__ == "__main__":
            # Replace 'your_key_vault_url' with the actual URL of your Azure Key Vault
            key_vault_url = "https://newvaults.vault.azure.net/"

            check_key_expiration(key_vault_url)
    def key_expiration_disabled(self):
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys import KeyClient
        from datetime import datetime, timedelta, timezone

        def check_key_expiration(key_vault_url):
            try:
                # Authenticate using the default Azure credentials
                credential = DefaultAzureCredential()
                key_client = KeyClient(vault_url=key_vault_url, credential=credential)

                # Get a list of all keys in the Key Vault
                keys = list(key_client.list_properties_of_keys())

                if not keys:
                    print("No keys found in the Key Vault.")
                    return

                print(f"Number of keys found: {len(keys)}")

                for key in keys:
                    print(f"Processing key: {key.name}")

                    # Get the key's properties, including expiration time
                    key_properties = key_client.get_key(key.name).properties

                    # Check if expiration time is set
                    if key_properties.expires_on is None:
                        print(f"Key '{key.name}' does not have an expiration time set. Risk Level: High")
                    else:
                        expiration_time = key_properties.expires_on
                        current_time = datetime.now(timezone.utc)  # Use timezone-aware object

                        # Check if the key is expired or close to expiration
                        if current_time > expiration_time - timedelta(
                                days=30):  # You can adjust the threshold as needed
                            print(f"Key '{key.name}' is close to expiration or already expired. Risk Level: Low")
                        else:
                            print(f"Key '{key.name}' is within the acceptable expiration period. Risk Level: Low")

            except Exception as e:
                print(f"An error occurred: {str(e)}")

        if __name__ == "__main__":
            # Replace 'your_key_vault_url' with the actual URL of your Azure Key Vault
            key_vault_url = "https://newvaults.vault.azure.net/"

            check_key_expiration(key_vault_url)
