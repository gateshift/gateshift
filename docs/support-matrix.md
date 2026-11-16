# Supported vendors

Every platform Gateshift reads or writes, in which form, in which direction and in which edition.

| Platform | Form | Read | Push | Edition |
|---|---|---|---|---|
| **Firewalls and Clusters** | | | | |
| Palo Alto Networks (PAN-OS) | standalone, HA pair, each vsys of a multi-vsys firewall as a scope | yes | yes | CE |
| FortiGate (FortiOS) | standalone, FGCP cluster, direct or through FortiGate Cloud, each VDOM of a multi-VDOM unit as a scope | yes | yes | CE |
| Check Point | one gateway or ClusterXL cluster at a time, through SmartCenter or Smart-1 Cloud, the virtual systems of a VSX gateway as scopes (sources, and targets of their policy) | yes | yes | CE |
| Cisco Firepower (FTD, FDM-managed) | standalone | yes | - | CE |
| Cisco Secure Firewall Management Center | on-premises or cloud-delivered, its domains, access policies and devices (standalone, HA pair) as scopes | yes | - | CE |
| Cisco ASA | configuration file | yes | - | CE |
| OPNsense | configuration file | yes | - | CE |
| **Cloud Platforms** | | | | |
| Amazon Web Services | account, over the provider's API or from an exported bundle | yes | - | CE |
| Microsoft Azure | account, over the provider's API or from an exported bundle | yes | - | CE |
| Google Cloud | account, over the provider's API or from an exported bundle | yes | - | CE |
| **Manager** | | | | |
| Panorama | manager, its device groups and template stacks as scopes | yes | yes | EE, discovery in CE |
| FortiManager, FortiManager Cloud | manager, its ADOMs and policy packages as scopes, the cloud one through a FortiCloud IAM API user | yes | yes | EE, discovery in CE |
| Check Point management | SmartCenter, Smart-1 Cloud or Multi-Domain, every domain and gateway as scopes | yes | yes | EE, discovery in CE |
| Strata Cloud Manager | cloud manager, its folders and snippets as scopes | yes | yes | EE, discovery in CE |
| **Log Sources** | | | | |
| OPNsense | traffic logs over syslog, a ruleset generated from what they show | yes | - | CE |

CE is this repository, the Community Edition, EE the commercial Enterprise Edition. "Discovery in CE" means the Community Edition shows a manager's scopes with their counts, importing and pushing them is EE. The Cisco Secure Firewall Management Center, a source only, is imported by the Community Edition.

What each platform needs on its side (API users, permissions, trusted hosts): [vendor-prerequisites.md](vendor-prerequisites.md). What Gateshift deliberately does not do per platform: [KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md).
