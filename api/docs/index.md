# Minecharts API

Minecharts API automates the lifecycle of Minecraft servers inside a Kubernetes cluster. This site gives you the essentials required to run and operate the service without overwhelming detail.

## What the Platform Does
- Spins up Kubernetes StatefulSets backed by persistent volumes, using the `itzg/minecraft-server` image as a base.
- Enforces authentication through JWT cookies or API keys, then applies fine-grained permissions on each request.
- Tracks users, keys, and server metadata in a database so that cluster state and API state remain aligned.

## How to Use This Documentation
- Understand how clients interact with the service: [API Overview](api/index.md)
- Configure runtime behaviour and storage: [Configuration](configuration.md)
- Explore the persistence model and relationships: [Database Architecture](database.md)

!!! tip "Fast feedback loop"
    Keep a terminal with `kubectl` open when experimenting. Watching StatefulSets, pods, and PVCs appear alongside API responses is the fastest way to build intuition.
