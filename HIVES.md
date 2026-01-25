# Windows Registry Hives Guide

## Overview
Registry forensics and hive analysis techniques.

## Key Hives

### SYSTEM Hive
- Services configuration
- Driver settings
- Control sets
- Network profiles

### SAM Hive
- Local user accounts
- Password hashes
- Account policies
- Group membership

### SECURITY Hive
- LSA secrets
- Cached credentials
- Security policies
- Audit settings

### SOFTWARE Hive
- Installed applications
- File associations
- Run keys
- Uninstall info

### NTUSER.DAT
- User preferences
- Recent files
- TypedPaths
- UserAssist

## Forensic Artifacts

### Persistence Locations
- Run/RunOnce keys
- Services
- Scheduled tasks
- Startup folders

### User Activity
- RecentDocs
- OpenSaveMRU
- LastVisitedMRU
- ComDlg32

### Network Evidence
- Network profiles
- Adapter settings
- Wireless keys
- VPN configurations

## Analysis Tools
- RegRipper plugins
- Registry Explorer
- RECmd scripting
- Direct parsing

## Legal Notice
For authorized forensic analysis.
