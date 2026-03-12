# Confidential Computing device plugin for Kubernetes
[![Go Report Card](https://goreportcard.com/badge/github.com/google/cc-device-plugin)](https://goreportcard.com/report/github.com/google/cc-device-plugin)

## Introduction

This is a [Kubernetes][k8s] [device plugin][dp] implementation that enables
the registration of Confidential Computing devices in a Google Kubernetes
Engine (GKE) cluster for compute workloads. With the appropriate GKE setup
and this plugin deployed, your Kubernetes cluster will be able to run jobs
(e.g., Attestation) that require Confidential Computing devices.

This plugin supports the following technologies on GKE:
*   **vTPM / AMD SEV:** Exposes `google.com/cc` resource.
*   **AMD SEV-SNP:** Exposes `amd.com/sev-snp` resource. Requires AMD SNP machines.
*   **Intel TDX:** Exposes `intel.com/tdx` resource. Requires Intel TDX machines.

## Prerequisites
*   A GKE cluster with node pools configured to support the desired
    Confidential Computing technology (SEV, SEV-SNP, or TDX). This
    includes selecting appropriate machine types and enabling Confidential
    Nodes in the node pool settings.
*   For SEV-SNP, ensure the node pool uses AMD SEV-SNP machine types.
*   For TDX, ensure the node pool uses Intel TDX machine types.

## Limitations
This plugin targets Kubernetes v1.18+ for AMD SEV. For other Confidential
Computing technologies, the minimum required GKE versions (when using Ubuntu
node images) are branch-dependent:
*   **AMD SEV-SNP:** v1.33.5-gke.1350000+ or v1.34.1-gke.2037000+
*   **Intel TDX:** v1.33.5-gke.1697000+ or v1.34.1-gke.2909000+
*   Refer to [Confidential VM Supported Configurations][supported-configs]
    for specific version and region availability.


## Deployment
The device plugin needs to be run on all the nodes that are equipped with
Confidential Computing devices.  The simplest way to do this is to create a
Kubernetes [DaemonSet][dp], which runs a copy of a pod on all (or some) Nodes
in the cluster. 

We have a pre-built Docker image on [Google Artifact Registry][release] that
you can use with your DaemonSet.  This repository also has a pre-defined yaml
file named `cc-device-plugin.yaml`.  You can create a DaemonSet in your
Kubernetes cluster by running this command using a stable version from the
release repository:

```
kubectl create -f manifests/cc-device-plugin.yaml
```
or directly pull from the web using
```
kubectl create -f https://raw.githubusercontent.com/google/cc-device-plugin/main/manifests/cc-device-plugin.yaml
```

[dp]: https://kubernetes.io/docs/concepts/cluster-administration/device-plugins/
[k8s]: https://kubernetes.io
[tpm]: https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#vtpm
[sevsnp]: https://cloud.google.com/confidential-computing/confidential-vm/docs/confidential-vm-overview#amd_sev-snp
[tdx]: https://cloud.google.com/blog/products/identity-security/confidential-vms-on-intel-cpus-your-datas-new-intelligent-defense
[release]: https://us-central1-docker.pkg.dev/gce-confidential-compute/release/cc-device-plugin
[supported-configs]: https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations
