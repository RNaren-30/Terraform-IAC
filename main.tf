/*Resource Group*/

terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = "3.0.2"
    }
  }
}

provider "azurerm" {
  features{}
  
}
resource "azurerm_resource_group" "rg" {
  name     = "terraform"
  location = "us-east-1"
}

/*Active directory*/

terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.15.0"
    }
  }
}

# Configure the Azure Active Directory Provider
provider "azuread" {
  tenant_id = "00000000-0000-0000-0000-000000000000"
}

# Retrieve domain information
data "azuread_domains" "active" {
  only_initial = true
}

# Create an application
resource "azuread_application" "active" {
  display_name = "active direct"
}

# Create a service principal
resource "azuread_service_principal" "active" {
  application_id = azuread_application.active.application_id
}

# Create a user
resource "azuread_user" "active" {
  user_principal_name = "activeUser@${data.azuread_domains.active.domains.0.domain_name}"
  display_name        = "active User"
  password            = "..."
}

/*Azure Monitor*/
 
resource "azurerm_resource_group" "main" {
  name     = "az monitor-resources"
  location = "us-east-1"
}

resource "azurerm_storage_account" "to_monitor" {
  name                     = "az monitorstorageaccount"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_monitor_action_group" "main" {
  name                = "az monitor-actiongroup"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "az monitor act"

  webhook_receiver {
    name        = "callmyapi"
    service_uri = "http://az monitor.com/alert"
  }
}

resource "azurerm_monitor_metric_alert" "az monitor" {
  name                = "az monitor-metricalert"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_storage_account.to_monitor.id]
  description         = "Action will be triggered when Transactions count is greater than 50."

  criteria {
    metric_namespace = "Microsoft.Storage/storageAccounts"
    metric_name      = "Transactions"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 50

    dimension {
      name     = "ApiName"
      operator = "Include"
      values   = ["*"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id
  }
}
terraform import azurerm_monitor_metric_alert.main /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/az monitor-resources/providers/Microsoft.Insights/metricAlerts/az monitor-metricalert

/*Azure log analytics workspace*/

resource "azurerm_resource_group" "az_log_analytics" {
  name     = "az log-resources"
  location = "us-east-1"
}

resource "azurerm_log_analytics_workspace" "az_log_analytics" {
  name                = "acctest-01"
  location            = azurerm_resource_group.az_log_analytics.location
  resource_group_name = azurerm_resource_group.az_log_analytics.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

/*Azure Blueprint*/

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

data "azurerm_subscription" "az blueprint" {}

data "azurerm_blueprint_definition" "az blueprint" {
  name     = "az Blueprint"
  scope_id = data.azurerm_subscription.az blueprint.id
}

data "azurerm_blueprint_published_version" "az blueprint" {
  scope_id       = data.azurerm_blueprint_definition.az blueprint.scope_id
  blueprint_name = data.azurerm_blueprint_definition.az blueprint.name
  version        = "v1.0.0"
}

resource "azurerm_resource_group" "az blueprint" {
  name     = "azRG-bp"
  location = "us-east-1"

  tags = {
    Environment = "az"
  }
}

resource "azurerm_user_assigned_identity" "az blueprint" {
  resource_group_name = azurerm_resource_group.az blueprint.name
  location            = azurerm_resource_group.az blueprint.location
  name                = "bp-user-az"
}

resource "azurerm_role_assignment" "operator" {
  scope                = data.azurerm_subscription.az blueprint.id
  role_definition_name = "Blueprint Operator"
  principle_id         = azurerm_user_assigned_identity.az blueprint.principle_id
}

resource "azurerm_role_assignment" "owner" {
  scope                = data.azurerm_subscription.az blueprint.id
  role_definition_name = "Owner"
  principle_id         = azurerm_user_assigned_identity.az blueprint.principle_id
}

resource "azurerm_blueprint_assignment" "az blueprint" {
  name                   = "testAccBPAssignment"
  target_subscription_id = data.azurerm_subscription.az blueprint.id
  version_id             = data.azurerm_blueprint_published_version.az blueprint.id
  location               = azurerm_resource_group.az blueprint.location

  lock_mode = "AllResourcesDoNotDelete"

  lock_exclude_principals = [
    data.azurerm_client_config.current.object_id,
  ]

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.blueprint.id]
  }

  resource_groups = <<GROUPS
    {
      "ResourceGroup": {
        "name": "azRG-bp"
      }
    }
  GROUPS

  parameter_values = <<VALUES
    {
      "allowedlocationsforresourcegroups_listOfAllowedLocations": {
        "value": ["westus", "westus2", "eastus", "centralus", "centraluseuap", "southcentralus", "northcentralus", "westcentralus", "eastus2", "eastus2euap", "brazilsouth", "brazilus", "northeurope", "westeurope", "eastasia", "southeastasia", "japanwest", "japaneast", "koreacentral", "koreasouth", "indiasouth", "indiawest", "indiacentral", "australiaeast", "australiasoutheast", "canadacentral", "canadaeast", "uknorth", "uksouth2", "uksouth", "ukwest", "francecentral", "francesouth", "australiacentral", "australiacentral2", "uaecentral", "uaenorth", "southafricanorth", "southafricawest", "switzerlandnorth", "switzerlandwest", "germanynorth", "germanywestcentral", "norwayeast", "norwaywest"]
      }
    }

/*Connectivity subscription( Azure firewall, Virtual network, VPN Gateway, Public IP address)*/

resource "azurerm_resource_group" "connectivity" {
  name     = "connectivity-resources"
  location = "us-east-1"
}

resource "azurerm_virtual_network" "connectivity" {
  name                = "testvnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.connectivity.location
  resource_group_name = azurerm_resource_group.connectivity.name
}

resource "azurerm_subnet" "connectivity" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.connectivity.name
  virtual_network_name = azurerm_virtual_network.connectivity.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_public_ip" "connectivity" {
  name                = "testpip"
  location            = azurerm_resource_group.connectivity.location
  resource_group_name = azurerm_resource_group.connectivity.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_firewall" "connectivity" {
  name                = "testfirewall"
  location            = azurerm_resource_group.connectivity.location
  resource_group_name = azurerm_resource_group.connectivity.name

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.connectivity.id
    public_ip_address_id = azurerm_public_ip.connectivity.id
  }
}

/*Azure network watcher*/

resource "azurerm_resource_group" "nw watcher" {
  name     = "production-nwwatcher"
  location = "us-east-1"
}

resource "azurerm_network_watcher" "nw watcher" {
  name                = "production-nwwatcher"
  location            = azurerm_resource_group.nw watcher.location
  resource_group_name = azurerm_resource_group.nw watcher.name
}
terraform import azurerm_network_watcher.watcher1 /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mygroup1/providers/Microsoft.Network/networkWatchers/watcher1

/*Azure Policy and management group*/

resource "azurerm_management_group" "az policy" {
  display_name = "Some Management Group"
}

resource "azurerm_policy_definition" "az policy" {
  name                = "only-deploy-in-westeurope"
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = azurerm_management_group.az policy.group_id

  policy_rule = <<POLICY_RULE
    {
    "if": {
      "not": {
        "field": "location",
        "equals": "westeurope"
      }
    },
    "then": {
      "effect": "Deny"
    }
  }
POLICY_RULE
}

resource "azurerm_management_group_policy_assignment" "az policy" {
  name                 = "az policy-policy"
  policy_definition_id = azurerm_policy_definition.az policy.id
  management_group_id  = azurerm_management_group.az policy.id
}
terraform import azurerm_management_group_policy_assignment.az policy /providers/Microsoft.Management/managementGroups/group1/providers/Microsoft.Authorization/policyAssignments/assignment1