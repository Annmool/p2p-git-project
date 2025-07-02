# 📦 SyncIt

A decentralized peer-to-peer version control system inspired by Git concepts, aiming to remove the central server and allow true peer-to-peer collaboration.

---

## 🎯 Table of Contents

- [Overview](#overview)  
- [Motivation](#motivation)  
- [Architecture](#architecture)  
  - [Peer Roles & P2P Network](#peer-roles--p2p-network)  
  - [Data Flow & Sync Process](#data-flow--sync-process)  

---

## Overview

This project creates a **distributed version-control platform**:  
- Every node acts as both a client and server.  
- Peers discover, sync, and verify changes directly via P2P.  
- No single point of failure—true decentralization.

---

## Motivation

Bhai, traditional Git revolves around a central server like GitHub—it's client-server, not P2P. This project aims to break that mold and allow:

- 🔗 True peer-to-peer cloning and sharing  
- 🛡️ Security via commit verification  
- 🌐 Collaboration without relying on central infra  

---

## Architecture

### Peer Roles & P2P Network

Nodes in the network have dual roles: both **Host** (sharing objects/refs) and **Client** (requesting updates). Peer discovery uses a bootstrap node or protocol to find and connect peers in a loosely connected network.

### Data Flow & Sync Process

1. **Initialization** – Peer starts and announces itself.
2. **Discovery** – Connects and exchanges ref lists.
3. **Fetch/Push** – Transfers missing commits/objects.
4. **Verification** – Ensures integrity via hashes/signatures.

---

## Design & Flowcharts

### System Flowchart

```flow
graph LR
  A[Peer Start] --> B[Discover Peers]
  B --> C{Have New Refs?}
  C -- Yes --> D[Fetch Missing Objects]
  C -- No --> E[Idle & Wait]
  D --> F[Merge & Update Local Repo]
  F --> E
  E --> B
