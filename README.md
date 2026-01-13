# Peer Network – Ansible Configuration Repository

This repository contains the configuration, inventory, and playbooks used to **install and manage the core infrastructure** of the **Peer Network** environments.

These Ansible files and inventories are used to provision and maintain **Peer’s different environments** (production, staging, testing, etc.) across virtualized and cloud-based infrastructure.

---

## 🏗️ Overview

Each environment consists of a defined series of virtual machines (VMs), managed primarily through **Proxmox**.  
Below is an example of the production setup:

```
VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID
100 peer-prod-front running 1024 20.00 3655
101 peer-prod-backend-template stopped 16224 0.00 0
102 peer-prod-database running 16384 0.00 3774
103 peer-prod-admin running 1024 20.00 3941
104 peer-prod-bastion running 2048 20.00 462348
105 peer-prod-backend running 32768 0.00 4340
106 peer-prod-website running 1024 20.00 4533
9000 ubuntu-noble-template stopped 1024 3.50 0
```

---

## 🧩 Directory Layout

The repository follows a conventional **Ansible directory structure**:
```
.
├── ansible.cfg
├── inventory
│ └── inventory.yml
├── playbooks
│ └── test-all-vms.yml
├── role
└── roles
├── apache2
│ ├── handlers
│ │ └── main.yml
│ └── tasks
│ └── main.yml
├── nginx
│ ├── handlers
│ │ └── main.yml
│ └── tasks
│ └── main.yml
└── php
├── handlers
│ └── main.yml
└── tasks
└── main.yml
```

---

## ⚙️ Purpose

- Standardize software installation and configuration across Peer environments  
- Automate VM provisioning, service deployment, and updates  
- Maintain consistency between development, staging, and production nodes  

---

## 🪪 License

© 2025 Peer Network UG (haftungsbeschränkt).  
All rights reserved unless otherwise stated.
