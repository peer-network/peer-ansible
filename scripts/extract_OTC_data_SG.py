#!/usr/bin/env python3
"""
Extract security groups from peer_groups.yml and map them to VMs from inventory.yml

This script:
1. Reads security groups from peer_groups.yml
2. Reads VM definitions from inventory.yml
3. Maps security groups to inventory VMs
4. Generates Proxmox firewall rules only for inventory VMs
"""

import yaml
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict


class InventoryAwareSecurityMapper:
    """Maps security groups to VMs using both peer_groups.yml and inventory.yml"""
    
    # Mapping keywords in security group names to VM roles
    SG_TO_ROLE_KEYWORDS = {
        "database": ["database", "db", "pg", "postgres", "rds", "mysql", "mariadb"],
        "frontend": ["frontend", "web-frontend", "web_frontend"],
        "backend": ["backend", "api"],
        "bastion": ["bastion", "jump", "jumphost"],
        "admin": ["admin"],
        "website": ["website", "peer-web", "web", "www"],
    }
    
    def __init__(self, peer_groups_file: str, inventory_file: str):
        """Initialize with both config files"""
        self.peer_groups_file = Path(peer_groups_file)
        self.inventory_file = Path(inventory_file)
        
        # Load data
        self.peer_groups_data = self._load_yaml(self.peer_groups_file)
        self.inventory_data = self._load_yaml(self.inventory_file)
        
        # Extract relevant data
        self.security_groups = self._extract_security_groups()
        self.inventory_vms = self._extract_inventory_vms()
        
    def _load_yaml(self, file_path: Path) -> Dict:
        """Load YAML file"""
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _extract_security_groups(self) -> List[Dict]:
        """Extract ONLY security groups from peer_groups.yml"""
        return self.peer_groups_data.get('security_groups', [])
    
    def _extract_inventory_vms(self) -> Dict[str, Dict]:
        """
        Extract VMs from inventory.yml
        Returns: {vm_name: {role, vm_id, ansible_host, ...}}
        """
        vms = {}
        
        # Navigate inventory structure to find all production VMs
        production = self.inventory_data.get('all', {}).get('children', {}).get('production', {})
        
        # Iterate through all server groups
        for group_name, group_data in production.get('children', {}).items():
            hosts = group_data.get('hosts', {})
            for vm_name, vm_data in hosts.items():
                vms[vm_name] = vm_data
        
        return vms
    
    def match_sg_to_role(self, sg_name: str) -> Optional[str]:
        """
        Match security group name to a VM role
        Returns the role (database, frontend, etc.) or None
        """
        sg_name_lower = sg_name.lower()
        
        for role, keywords in self.SG_TO_ROLE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in sg_name_lower:
                    return role
        
        return None
    
    def find_vms_by_role(self, role: str) -> List[str]:
        """
        Find all inventory VMs that match a given role
        Returns list of VM names
        """
        matching_vms = []
        for vm_name, vm_data in self.inventory_vms.items():
            vm_role = vm_data.get('role', '')
            if vm_role == role:
                matching_vms.append(vm_name)
        
        return matching_vms
    
    def convert_rule_to_proxmox(self, rule: Dict, sg_name: str) -> Optional[Dict]:
        """Convert OpenStack rule to Proxmox format"""
        # Skip rules without protocol or with empty essential fields
        if not rule.get('protocol') and not rule.get('port_range_min'):
            return None
        
        direction = rule.get('direction', 'ingress')
        ethertype = rule.get('ethertype', 'IPv4')
        protocol = rule.get('protocol', '')
        port_min = rule.get('port_range_min')
        port_max = rule.get('port_range_max')
        remote_ip = rule.get('remote_ip_prefix', '0.0.0.0/0')
        
        # Skip IPv6 rules (enable if needed)
        if ethertype == 'IPv6':
            return None
        
        # Map direction
        action = 'ACCEPT'
        pve_direction = 'IN' if direction == 'ingress' else 'OUT'
        
        # Build Proxmox rule
        pve_rule = {
            'type': pve_direction,
            'action': action,
            'enable': 1,
            'comment': f'From {sg_name}',
        }
        
        # Add protocol
        if protocol:
            pve_rule['proto'] = protocol
        
        # Add ports
        if port_min and port_max:
            if port_min == port_max:
                pve_rule['dport'] = str(port_min)
            else:
                pve_rule['dport'] = f"{port_min}:{port_max}"
        
        # Add source/dest IP based on direction
        if remote_ip and remote_ip not in ['', '::/0']:
            if pve_direction == 'IN':
                pve_rule['source'] = remote_ip
            else:
                pve_rule['dest'] = remote_ip
        
        return pve_rule
    
    def generate_vm_mappings(self) -> Dict[str, List[Dict]]:
        """
        Generate mappings of inventory VMs to their security group rules
        
        Returns: {vm_name: [list of proxmox rules]}
        """
        vm_rules = defaultdict(list)
        mapping_report = []
        
        print(f"\n🔍 Processing {len(self.security_groups)} security groups...")
        print(f"📋 Inventory has {len(self.inventory_vms)} VMs\n")
        
        for sg in self.security_groups:
            sg_name = sg.get('name', '')
            sg_id = sg.get('id', '')
            rules = sg.get('rules', [])
            
            # Try to match this security group to a role
            matched_role = self.match_sg_to_role(sg_name)
            
            if matched_role:
                # Find all inventory VMs with this role
                matching_vms = self.find_vms_by_role(matched_role)
                
                if matching_vms:
                    for vm_name in matching_vms:
                        mapping_report.append({
                            'security_group': sg_name,
                            'sg_id': sg_id,
                            'mapped_to_vm': vm_name,
                            'via_role': matched_role,
                            'rule_count': len(rules)
                        })
                        
                        # Convert each rule
                        for rule in rules:
                            pve_rule = self.convert_rule_to_proxmox(rule, sg_name)
                            if pve_rule:
                                vm_rules[vm_name].append(pve_rule)
                else:
                    mapping_report.append({
                        'security_group': sg_name,
                        'sg_id': sg_id,
                        'mapped_to_vm': f'ROLE MATCHED ({matched_role}) but NO VM in inventory',
                        'via_role': matched_role,
                        'rule_count': len(rules)
                    })
            else:
                mapping_report.append({
                    'security_group': sg_name,
                    'sg_id': sg_id,
                    'mapped_to_vm': 'UNMAPPED',
                    'via_role': 'none',
                    'rule_count': len(rules)
                })
        
        self.mapping_report = mapping_report
        return dict(vm_rules)
    
    def save_mapping_report(self, output_file: str = 'mapping_report.txt'):
        """Generate human-readable mapping report"""
        output_path = Path(output_file)
        
        with open(output_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("SECURITY GROUP TO INVENTORY VM MAPPING REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("INVENTORY VMs:\n")
            f.write("-" * 80 + "\n")
            for vm_name, vm_data in self.inventory_vms.items():
                f.write(f"VM: {vm_name}\n")
                f.write(f"  Role: {vm_data.get('role')}\n")
                f.write(f"  VM ID: {vm_data.get('vm_id')}\n")
                f.write(f"  IP: {vm_data.get('ansible_host')}\n\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("SUCCESSFULLY MAPPED:\n")
            f.write("-" * 80 + "\n")
            
            mapped = [item for item in self.mapping_report if item['mapped_to_vm'] not in ['UNMAPPED'] and 'NO VM in inventory' not in item['mapped_to_vm']]
            
            if mapped:
                for item in mapped:
                    f.write(f"Security Group: {item['security_group']}\n")
                    f.write(f"  → Mapped to VM: {item['mapped_to_vm']}\n")
                    f.write(f"  → Via Role: {item['via_role']}\n")
                    f.write(f"  → Rules: {item['rule_count']}\n\n")
            else:
                f.write("None\n\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("UNMAPPED SECURITY GROUPS:\n")
            f.write("-" * 80 + "\n")
            
            unmapped = [item for item in self.mapping_report if item['mapped_to_vm'] == 'UNMAPPED' or 'NO VM in inventory' in item['mapped_to_vm']]
            
            if unmapped:
                for item in unmapped:
                    f.write(f"Security Group: {item['security_group']}\n")
                    f.write(f"  → Status: {item['mapped_to_vm']}\n")
                    f.write(f"  → Rules: {item['rule_count']}\n\n")
            else:
                f.write("None - all security groups were mapped!\n\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("SUMMARY:\n")
            f.write("-" * 80 + "\n")
            total = len(self.mapping_report)
            mapped_count = len(mapped)
            f.write(f"Total Security Groups: {total}\n")
            f.write(f"Inventory VMs: {len(self.inventory_vms)}\n")
            f.write(f"Successfully Mapped: {mapped_count}\n")
            f.write(f"Unmapped: {total - mapped_count}\n")
            f.write("=" * 80 + "\n")
        
        print(f"✓ Mapping report saved to: {output_path}")
    
    def save_ansible_vars(self, vm_rules: Dict, output_file: str = 'proxmox_firewall_rules.yml'):
        """Save VM rules as Ansible variables with inventory integration"""
        output_path = Path(output_file)
        
        # Build VM metadata from inventory
        vm_metadata = {}
        for vm_name in vm_rules.keys():
            if vm_name in self.inventory_vms:
                vm_metadata[vm_name] = {
                    'ip': self.inventory_vms[vm_name].get('ansible_host'),
                    'vm_id': self.inventory_vms[vm_name].get('vm_id'),
                    'role': self.inventory_vms[vm_name].get('role'),
                }
        
        ansible_vars = {
            'proxmox_firewall_rules': vm_rules,
            'vm_metadata': vm_metadata,
        }
        
        with open(output_path, 'w') as f:
            f.write("---\n")
            f.write("# Generated Proxmox Firewall Rules from Inventory\n")
            f.write("# Source: peer_groups.yml + inventory.yml\n")
            f.write("# Use with: ansible-playbook -i inventory.yml apply_proxmox_firewall_v3.yml\n\n")
            yaml.dump(ansible_vars, f, default_flow_style=False, sort_keys=False)
        
        print(f"✓ Ansible variables saved to: {output_path}")
    
    def print_summary(self, vm_rules: Dict):
        """Print summary to console"""
        print("\n" + "=" * 80)
        print("EXTRACTION SUMMARY")
        print("=" * 80)
        print(f"Total Security Groups in peer_groups.yml: {len(self.security_groups)}")
        print(f"Inventory VMs: {len(self.inventory_vms)}")
        print(f"VMs with Firewall Rules: {len(vm_rules)}")
        print("\nRules per VM:")
        for vm, rules in sorted(vm_rules.items()):
            vm_id = self.inventory_vms[vm].get('vm_id', '???')
            role = self.inventory_vms[vm].get('role', '???')
            print(f"  - {vm} (VMID {vm_id}, role: {role}): {len(rules)} rules")
        print("=" * 80 + "\n")


def main():
    """Main execution"""
    print("\n" + "=" * 80)
    print("INVENTORY-AWARE SECURITY GROUP EXTRACTOR")
    print("=" * 80 + "\n")
    
    # Input files
    peer_groups_file = '/mnt/user-data/uploads/peer_groups.yml'
    inventory_file = '/mnt/user-data/uploads/inventory.yml'
    
    # Check files exist
    if not Path(peer_groups_file).exists():
        print(f"❌ Error: {peer_groups_file} not found")
        return 1
    
    if not Path(inventory_file).exists():
        print(f"❌ Error: {inventory_file} not found")
        return 1
    
    print(f"📄 Reading security groups from: {peer_groups_file}")
    print(f"📋 Reading inventory from: {inventory_file}\n")
    
    # Initialize mapper
    mapper = InventoryAwareSecurityMapper(peer_groups_file, inventory_file)
    
    # Generate VM mappings
    print("🔄 Generating VM mappings...\n")
    vm_rules = mapper.generate_vm_mappings()
    
    # Save outputs
    mapper.save_mapping_report('mapping_report_inventory.txt')
    mapper.save_ansible_vars(vm_rules, 'proxmox_firewall_rules_inventory.yml')
    
    # Print summary
    mapper.print_summary(vm_rules)
    
    print("✅ All done! Check the generated files:")
    print("  1. mapping_report_inventory.txt          - Review mapping results")
    print("  2. proxmox_firewall_rules_inventory.yml  - Ansible vars for playbook")
    print("\nNext: Review the mapping report, then run the Ansible playbook!\n")
    
    return 0


if __name__ == '__main__':
    exit(main())