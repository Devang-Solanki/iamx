"""
Pre-defined Azure service groups for targeted enumeration.
Values are provider prefix substrings matched against AZURE_OPERATIONS keys.
"""

AZURE_SERVICE_GROUPS: dict[str, list[str]] = {
    "compute": [
        "Microsoft.Compute",
        "Microsoft.AzureFleet",
        "Microsoft.AzureLargeInstance",
    ],
    "network": [
        "Microsoft.Network",
        "Microsoft.Cdn",
        "Microsoft.FrontDoor",
    ],
    "storage": [
        "Microsoft.Storage",
        "Microsoft.StorageCache",
        "Microsoft.StorageMover",
        "Microsoft.StorageSync",
        "Microsoft.DataBox",
    ],
    "databases": [
        "Microsoft.Sql",
        "Microsoft.DBforPostgreSQL",
        "Microsoft.DBforMySQL",
        "Microsoft.DBforMariaDB",
        "Microsoft.CosmosDB",
        "Microsoft.Cache",
        "Microsoft.DocumentDB",
        "Microsoft.Synapse",
    ],
    "iam": [
        "Microsoft.Authorization",
        "Microsoft.ManagedIdentity",
        "Microsoft.AAD",
        "Microsoft.Aadiam",
        "Microsoft.ADHybridHealthService",
    ],
    "security": [
        "Microsoft.Security",
        "Microsoft.KeyVault",
        "Microsoft.Attestation",
        "Microsoft.ConfidentialLedger",
    ],
    "monitoring": [
        "Microsoft.Insights",
        "Microsoft.Monitor",
        "Microsoft.OperationalInsights",
        "Microsoft.OperationsManagement",
        "Microsoft.AlertsManagement",
    ],
    "serverless": [
        "Microsoft.Web",
        "Microsoft.Logic",
        "Microsoft.EventGrid",
        "Microsoft.ServiceBus",
        "Microsoft.EventHub",
        "Microsoft.App",
        "Microsoft.AppConfiguration",
    ],
    "ai": [
        "Microsoft.CognitiveServices",
        "Microsoft.MachineLearningServices",
        "Microsoft.BotService",
        "Microsoft.Search",
    ],
    "devops": [
        "Microsoft.ContainerRegistry",
        "Microsoft.ContainerService",
        "Microsoft.DevTestLab",
        "Microsoft.DevCenter",
    ],
}

# Human-readable labels for --group help text
AZURE_SERVICE_GROUP_LABELS: dict[str, str] = {
    "compute":    "VMs, scale sets, availability sets",
    "network":    "VNets, NSGs, load balancers, CDN",
    "storage":    "Storage accounts, blobs, file shares",
    "databases":  "SQL, PostgreSQL, MySQL, CosmosDB, Redis",
    "iam":        "RBAC, managed identities, AAD",
    "security":   "Security Center, Key Vault, Attestation",
    "monitoring": "Azure Monitor, Log Analytics, Insights",
    "serverless": "Functions, Logic Apps, Event Grid, Service Bus",
    "ai":         "Cognitive Services, ML, Bot Service, Search",
    "devops":     "AKS, ACR, DevTest Labs, Dev Center",
}

