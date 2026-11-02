# synodmgr

Synod Manager: the enterprise management tool for Synod RAC clusters, in the role Oracle Enterprise
Manager, srvctl and DBCA play for Oracle RAC. One service the customer runs in their own network shows
every cluster's health and performance, runs admin actions through the Synod control plane, and raises
alerts. A web console and the `synodmgr` CLI share one API.

**Status:** design proposal, no code yet. Read [docs/design.md](docs/design.md) (the live, commentable
version is the Claude Doc "Synod Manager: design proposal").

Related private repos: `sangrhee88/synod-storage` (Synod itself: the control plane, the `synod`
extension, the storage) and `sangrhee88/stage3-neon-m1` (installer and tests).
