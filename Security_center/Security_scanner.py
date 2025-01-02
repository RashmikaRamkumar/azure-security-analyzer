from azure.mgmt.monitor import MonitorManagementClient

from azure.mgmt.monitor import MonitorManagementClient
import azure.mgmt.security
from conf.claudius_constants import subscription_id
from vulnerability.azure.Load_Balancers.balancer_scanner import DefaultAzureCredential


class SECURITY_scanner:
    def  Severity_Alerts(self):

        resource_group_name = 'cybersec'

        # Set the default Azure credentials
        credentials = DefaultAzureCredential()

        # Create a Monitor Management client
        monitor_client = MonitorManagementClient(credentials, subscription_id)

        # Get the list of alert rules
        alert_rules = monitor_client.alert_rules.list_by_resource_group(resource_group_name)

        # Identify if high severity alerts are disabled
        high_severity_disabled = True

        for alert_rule in alert_rules:
            # Check if the alert rule is for high severity
            if 'severity' in alert_rule.conditions and alert_rule.conditions['severity'] == '3':
                high_severity_disabled = False
                break

        # Print information about high severity alerts status
        if high_severity_disabled:
            print("High Severity Alerts are Disabled.")
        else:
            print("High Severity Alerts are Enabled.")
        pass