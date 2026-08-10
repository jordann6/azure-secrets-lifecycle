#!/usr/bin/env python3
"""Render docs/architecture.png.

    pip install diagrams && brew install graphviz
    python3 diagram.py
"""

from diagrams import Cluster, Diagram, Edge
from diagrams.azure.compute import ContainerRegistries
from diagrams.azure.database import DatabaseForPostgresqlServers
from diagrams.azure.security import KeyVaults
from diagrams.azure.identity import ManagedIdentities
from diagrams.azure.analytics import LogAnalyticsWorkspaces
from diagrams.azure.storage import BlobStorage
from diagrams.azure.integration import AppConfiguration
from diagrams.azure.ml import CognitiveServices
from diagrams.azure.general import Managementgroups
from diagrams.onprem.client import Users

GRAPH_ATTR = {
    "fontsize": "13",
    "bgcolor": "white",
    "pad": "0.5",
    "splines": "spline",
    "nodesep": "0.6",
    "ranksep": "1.3",
    "concentrate": "false",
}

NODE_ATTR = {"fontsize": "11"}
EDGE_ATTR = {"fontsize": "10"}


with Diagram(
    "Secrets Lifecycle and Rotation Readiness (Azure)",
    filename="docs/architecture",
    outformat="png",
    show=False,
    direction="TB",
    graph_attr=GRAPH_ATTR,
    node_attr=NODE_ATTR,
    edge_attr=EDGE_ATTR,
):
    with Cluster("Secret bearing sources"):
        vault = KeyVaults("Key Vault\nsecrets + certificates")
        appcs = AppConfiguration("App Configuration\nkey values")
        entra = ManagedIdentities("Entra ID\napp registrations")

    registry = ContainerRegistries("Container Registry\nAcrPull via MI")

    with Cluster("Container Apps, one Rails image"):
        scan_job = Managementgroups("scan job\ncron, daily")
        dashboard = Managementgroups("dashboard\nscale to zero")
        consumers = Managementgroups("consumer jobs\nstand-in workloads")

    with Cluster("Data and evidence"):
        workspace = LogAnalyticsWorkspaces("Log Analytics\naudit + findings table")
        postgres = DatabaseForPostgresqlServers("Postgres Flexible\nEntra token auth")
        evidence = BlobStorage("Blob evidence\nversioned + immutable")
        openai = CognitiveServices("Azure OpenAI\nrunbook synthesis")

    operator = Users("operator")

    # Sweep: metadata only, never a value.
    scan_job >> Edge(label="list metadata", color="darkgreen") >> vault
    scan_job >> Edge(label="$select, no value", color="darkgreen") >> appcs
    scan_job >> Edge(label="Graph, credential\ndescriptors", color="darkgreen") >> entra

    # Consumers produce the audit trail the consumer map is built from.
    consumers >> Edge(label="reads values", color="firebrick", style="dashed") >> vault
    vault >> Edge(label="AuditEvent", color="gray") >> workspace
    appcs >> Edge(label="Audit", color="gray") >> workspace

    # Analyze.
    workspace >> Edge(label="KQL consumer map", color="darkblue") >> scan_job
    scan_job >> Edge(label="high risk only,\nbounded", color="darkblue") >> openai
    scan_job >> Edge(label="inventory,\nscores, findings") >> postgres
    scan_job >> Edge(label="evidence artifact") >> evidence
    scan_job >> Edge(label="Logs Ingestion API\nSentinel table") >> workspace

    # Serve.
    postgres >> Edge(label="live render") >> dashboard
    dashboard >> Edge(color="gray", style="dotted") >> operator
    registry >> Edge(color="gray", style="dotted") >> scan_job
