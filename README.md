# Confidential Computing device plugin for Kubernetes
[![Go Report Card](https://goreportcard.com/badge/github.com/google/cc-device-plugin)](https://goreportcard.com/report/github.com/google/cc-device-plugin)

## Introduction
This is a [Kubernetes][k8s] [device plugin][dp] implementation that enables the
registration of Confidential Computing devices in a Google
Kubernetes Engine (GKE) for compute workload. With the appropriate GKE setup and
this plugin deployed in your Kubernetes cluster, you will be able to run jobs
(e.g. Attestation) that require Confidential Computing devices. (Note that: Current version supports [TPM][tpm]. Support for [SEV SNP][sevsnp] and [TDX][tdx] are on the way.)

## Prerequisites
* GKE

## Limitations
* This plugin targets Kubernetes v1.18+.

## Deployment
The device plugin needs to be run on all the nodes that are equipped with Confidential Computing devices (e.g. TPM).  The simplest way of doing so is to create a Kubernetes [DaemonSet][dp], which run a copy of a pod on all (or some) Nodes in the cluster.  We have a pre-built Docker image on [Google Artifact Registry][release] that you can use for with your DaemonSet.  This repository also have a pre-defined yaml file named `cc-device-plugin.yaml`.  You can create a DaemonSet in your Kubernetes cluster by running this command:

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
