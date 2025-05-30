# [v1.9.2](https://github.com/kubermatic/kubeone/releases/tag/v1.9.2) - 2025-02-05

## Changelog since v1.9.1

## Changes by Kind

### Feature

- Label the control plane nodes before applying addons and Helm charts to allow addons and Helm charts to utilize the label selectors ([#3547](https://github.com/kubermatic/kubeone/pull/3547), [@xmudrii](https://github.com/xmudrii))
- Add parameter `insecure` to the `backups-restic` addon used to disable/skip the TLS verification ([#3547](https://github.com/kubermatic/kubeone/pull/3547), [@xmudrii](https://github.com/xmudrii))

### Bug or Regression

- Resolve the `clusterID` conflicts in cloud-config for AWS by prioritizing the cluster name from the Terraform configuration ([#3547](https://github.com/kubermatic/kubeone/pull/3547), [@xmudrii](https://github.com/xmudrii))
- Drop trailing slash from the `VSPHERE_SERVER` variable to ensure compatibility with machine-controller and vSphere CCM and CSI ([#3547](https://github.com/kubermatic/kubeone/pull/3547), [@xmudrii](https://github.com/xmudrii))
- Use the GPG key from the latest Kubernetes package repository to fix failures to install older versions of Kubernetes packages ([#3526](https://github.com/kubermatic/kubeone/pull/3526), [@kubermatic-bot](https://github.com/kubermatic-bot))
- Configure the `POD_NAMESPACE` environment variable for machine-controller-webhook on the KubeVirt clusters ([#3549](https://github.com/kubermatic/kubeone/pull/3549), [@kubermatic-bot](https://github.com/kubermatic-bot))
- Fix incorrect image references and tolerations in the KubeVirt CSI addon ([#3547](https://github.com/kubermatic/kubeone/pull/3547), [@xmudrii](https://github.com/xmudrii))

### Updates

#### machine-controller

- Update machine-controller to v1.61.0 ([#3547](https://github.com/kubermatic/kubeone/pull/3547), [@xmudrii](https://github.com/xmudrii))

# [v1.9.1](https://github.com/kubermatic/kubeone/releases/tag/v1.9.1) - 2024-12-23

## Changelog since v1.9.0

## Changes by Kind

### Feature

- Add `.cloudProvider.kubevirt.infraNamespace` field to the KubeOneCluster API used to control what namespace will be used by the KubeVirt provider to create and manage resources in the infra cluster, such as VirtualMachines and VirtualMachineInstances ([#3503](https://github.com/kubermatic/kubeone/pull/3503), [@kubermatic-bot](https://github.com/kubermatic-bot))
- Add support for the KubeVirt CSI driver. The CSI driver is deployed automatically for all KubeVirt clusters (unless `.cloudProvider.disableBundledCSIDrivers` is set to `true`). A new optional field, `.cloudProvider.kubevirt.infraClusterKubeconfig`, has been added to the KubeOneCluster API used to provide a kubeconfig file for a KubeVirt infra cluster (a cluster where KubeVirt is installed). This kubeconfig can be used by the CSI driver for provisioning volumes. ([#3512](https://github.com/kubermatic/kubeone/pull/3512), [@kubermatic-bot](https://github.com/kubermatic-bot))
- Update OpenStack CCM and CSI driver to v1.31.2 and v1.30.2 ([#3489](https://github.com/kubermatic/kubeone/pull/3489), [@kubermatic-bot](https://github.com/kubermatic-bot))

### Bug or Regression

- Fix an error message appearing in the KubeOne UI for clusters that don't have any Machine/MachineDeployment ([#3480](https://github.com/kubermatic/kubeone/pull/3480), [@kubermatic-bot](https://github.com/kubermatic-bot))

### Other (Cleanup or Flake)

- Use dedicated keyring for Docker repositories to solve `apt-key` deprecation warning upon installing/upgrading containerd ([#3485](https://github.com/kubermatic/kubeone/pull/3485), [@kubermatic-bot](https://github.com/kubermatic-bot))

### Updates

#### Others

- KubeOne is now built with Go 1.23.4 ([#3513](https://github.com/kubermatic/kubeone/pull/3513), [@kubermatic-bot](https://github.com/kubermatic-bot))

# [v1.9.0](https://github.com/kubermatic/kubeone/releases/tag/v1.9.0) - 2024-11-22

We're happy to announce a new KubeOne minor release — KubeOne 1.9! Please
consult the changelog below, as well as, the following two documents before
upgrading:

- [Upgrading from KubeOne 1.8 to 1.9 guide](https://docs.kubermatic.com/kubeone/v1.9/tutorials/upgrading/upgrading-from-1.8-to-1.9/)
- [Known Issues in KubeOne 1.9](https://docs.kubermatic.com/kubeone/v1.9/known-issues/)

## Changelog since v1.8.0

## Urgent Upgrade Notes 

### (No, really, you MUST read this before you upgrade)

- Add support for Ubuntu 24.04. Example Terraform configs for all providers are now using Ubuntu 24.04 by default. If you're using the latest Terraform configs with an existing cluster, make sure to bind the operating system/image to the image that you're currently using, otherwise your instances/cluster might get recreated by Terraform. On some providers, machine-controller will use Ubuntu 24.04 if the image is not explicitly specified. ([#3302](https://github.com/kubermatic/kubeone/pull/3302), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Example Terraform configs for Hetzner are now using `cx22` instead of `cx21` instance type by default. If you use the latest Terraform configs with an existing cluster, make sure to override the instance type as needed, otherwise your instances/cluster might get recreated by Terraform. ([#3370](https://github.com/kubermatic/kubeone/pull/3370), [@kron4eg](https://github.com/kron4eg))
- KubeOne is now validating that IP addresses and hostnames provided for control plane nodes and static worker nodes are different. In other words, it's not possible to use the same machine both as a control plane node and a static worker node. This behavior has never been supported by KubeOne; if you want a control plane node that can schedule any pod, you can provision it as a control plane node and remove the control plane taint (`node-role.kubernetes.io/control-plane:NoSchedule`). ([#3334](https://github.com/kubermatic/kubeone/pull/3334), [@kron4eg](https://github.com/kron4eg))
- Update Cilium to v1.16.3. This change might affect users that have nodes that are low on capacity (pods or resources wise). The Cilium architecture has been changed so that the Envoy Proxy is not integrated into Cilium, but is a dedicated component/DaemonSet. If you have nodes that are low on capacity, you might encounter issues when trying to start Envoy Proxy pods on those nodes. In this case, you'll need to override the Cilium addon to use the old architecture with Envoy Proxy integrated into Cilium. ([#3415](https://github.com/kubermatic/kubeone/pull/3415), [@xmudrii](https://github.com/xmudrii))
- `kubeone install` and `kubeone upgrade` subcommands are removed. We have deprecated these commands in KubeOne 1.4, and made them hidden in KubeOne 1.5. With this change, we're permanently removing these two commands. `kubeone apply` should be used instead. ([#3349](https://github.com/kubermatic/kubeone/pull/3349), [@mohamed-rafraf](https://github.com/mohamed-rafraf))
 
## Changes by Kind

### Deprecations and Removals

- Remove support for Kubernetes 1.28. `kubeone migrate to-ccm-csi` and `kubeone migrate to-containerd` commands are hidden and will be removed in a future KubeOne release because they cannot be used with Kubernetes v1.29+ clusters ([#3417](https://github.com/kubermatic/kubeone/pull/3417), [@xmudrii](https://github.com/xmudrii))
- Super-admin kubeconfig (`/etc/kubernetes/super-admin.conf`) automatically generated by kubeadm is now removed from the nodes. ([#3319](https://github.com/kubermatic/kubeone/pull/3319), [@kron4eg](https://github.com/kron4eg))

### API Change

- Add `.containerRuntime.containerd.deviceOwnershipFromSecurityContext` option to the KubeOneCluster API used to enable/disable `device_ownership_from_security_context` option in the containerd configuration. This option is at the moment only applied to the control plane nodes and the static worker nodes. This field is set to false by default in the KubeOneCluster v1beta2 API, but it'll be set to true by default in the KubeOneCluster v1beta3 API. If you don't want to use this option, we recommend explicitly disabling it to avoid any potential issues after migrating to the KubeOneCluster v1beta3 API ([#3392](https://github.com/kubermatic/kubeone/pull/3392), [@kron4eg](https://github.com/kron4eg))
- Add `.helmRelease[*].wait` and `.helmRelease[*].timeout` fields to the KubeOneCluster API to allow configuring wait and timeout parameters for Helm releases installed by the KubeOne Helm integration ([#3190](https://github.com/kubermatic/kubeone/pull/3190), [@mohamed-rafraf](https://github.com/mohamed-rafraf))


### Feature

- Add support for Kubernetes v1.31 ([#3358](https://github.com/kubermatic/kubeone/pull/3358), [@xmudrii](https://github.com/xmudrii))
- Migrate PersistentVolumeClaims (PVCs) upon upgrading to Kubernetes v1.31 to remove `.status.allocatedResourceStatus` if needed as instructed by the Kubernetes v1.31.0 changelog ([#3361](https://github.com/kubermatic/kubeone/pull/3361), [@xmudrii](https://github.com/xmudrii))
- Add new `kubeone kubeconfig generate` command with an option to generate kubeconfig file with the custom permissions and properties ([#3319](https://github.com/kubermatic/kubeone/pull/3319), [@kron4eg](https://github.com/kron4eg))
- Automatically delete unused container images after upgrading the cluster ([#3348](https://github.com/kubermatic/kubeone/pull/3348), [@mohamed-rafraf](https://github.com/mohamed-rafraf))
- Add support for enabling config drive on OpenStack ([#3317](https://github.com/kubermatic/kubeone/pull/3317), [@ahmedwaleedmalik](https://github.com/ahmedwaleedmalik))
- Initial implementation of the KubeVirt provider for KubeOne. At the moment, the provider only supports deploying machine-controller and operating-system-manager for the KubeVirt-based clusters. Terraform integration, CCM, CSI, and other cloud provider specific components are not supported and/or deployed automatically at the moment. ([#3416](https://github.com/kubermatic/kubeone/pull/3416), [@xmudrii](https://github.com/xmudrii))
- Add the technical preview of the KubeOne UI. At the moment, this is a read only UI allowing you to monitor the cluster status, mainly the health of the control plane nodes, components, and worker nodes. ([#3203](https://github.com/kubermatic/kubeone/pull/3203), [@stroebitzer](https://github.com/stroebitzer))

### Bug or Regression

- Use the RHEL upstream Docker package repository instead of the abandoned CentOS package repository ([#3316](https://github.com/kubermatic/kubeone/pull/3316), [@kron4eg](https://github.com/kron4eg))
- Upgrade the follower control plane nodes using individual tasks to avoid unnecessary retries on failure ([#3301](https://github.com/kubermatic/kubeone/pull/3301), [@kron4eg](https://github.com/kron4eg))

### Other (Cleanup or Flake)

- Add the bastion host support to the example Terraform configs for VMware vCloud Director ([#3277](https://github.com/kubermatic/kubeone/pull/3277), [@ahmedwaleedmalik](https://github.com/ahmedwaleedmalik))
- Add `disable_auto_update` option to example Terraform configs for AWS, Azure, OpenStack, and vSphere, used to disable automatic updates for all Flatcar nodes ([#3391](https://github.com/kubermatic/kubeone/pull/3391), [@xmudrii](https://github.com/xmudrii))
- Add `disable_auto_update` option to example Terraform configs for Equinix Metal, used to disable automatic updates for all Flatcar nodes ([#3398](https://github.com/kubermatic/kubeone/pull/3398), [@xmudrii](https://github.com/xmudrii))
- Bind `csi-snapshotter` to v8.0.1 for all providers that are supporting snapshotting the volumes ([#3269](https://github.com/kubermatic/kubeone/pull/3269), [@xmudrii](https://github.com/xmudrii))

### Updates

#### machine-controller

- Update machine-controller to v1.60.0 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))

#### operating-system-manager

- Update operating-system-manager to v1.6.0 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))

#### containerd

- Update containerd to v1.7 ([#3313](https://github.com/kubermatic/kubeone/pull/3313), [#3309](https://github.com/kubermatic/kubeone/pull/3309), [#3311](https://github.com/kubermatic/kubeone/pull/3311), [@kron4eg](https://github.com/kron4eg))

#### CNIs

- Update Canal CNI to v3.27.3 ([#3199](https://github.com/kubermatic/kubeone/pull/3199), [@kron4eg](https://github.com/kron4eg))
- Update Canal CNI to v3.28.0 ([#3216](https://github.com/kubermatic/kubeone/pull/3216), [@samuelfischer](https://github.com/samuelfischer))
- Update Canal CNI to v3.28.1 to fix the CPU high load issues ([#3327](https://github.com/kubermatic/kubeone/pull/3327), [@kron4eg](https://github.com/kron4eg))
- Update Canal CNI and Calico VXLAN CNI addon to v3.28.2 ([#3411](https://github.com/kubermatic/kubeone/pull/3411), [@xmudrii](https://github.com/xmudrii))
- Update Cilium to v1.15.6 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update Cilium to v1.16.3. This change might affect users that have nodes that are low on capacity (pods or resources wise). The Cilium architecture has been changed so that the Envoy Proxy is not integrated into Cilium, but is a dedicated component/DaemonSet. If you have nodes that are low on capacity, you might encounter issues when trying to start Envoy Proxy pods on those nodes. In this case, you'll need to override the Cilium addon to use the old architecture with Envoy Proxy integrated into Cilium. ([#3415](https://github.com/kubermatic/kubeone/pull/3415), [@xmudrii](https://github.com/xmudrii))

#### Cloud Provider integrations

- Update AWS CCM to v1.30.1, v1.29.3, v1.28.6, and v1.27.7 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update AWS CCM to v1.31.1 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update AWS EBS CSI driver to v1.31.0 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update AWS EBS CSI driver to v1.35.0 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update Azure CCM to v1.30.3 for Kubernetes 1.30 clusters ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update Azure CCM and CNM to latest patch versions ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update AzureDisk CSI driver to v1.30.1 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update AzureDisk CSI driver to v1.30.3 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update AzureFile CSI driver to v1.30.2 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update AzureFile CSI driver to v1.30.5 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update DigitalOcean CCM to v0.1.53 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update DigitalOcean CCM to v0.1.56 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update DigitalOcean CSI to v4.10.0 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update DigitalOcean CSI to v4.12.0 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update Equinix Metal CCM to v3.8.1 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update GCP CCM to v30.0.0 ([#3232](https://github.com/kubermatic/kubeone/pull/3232), [@xrstf](https://github.com/xrstf))
- Update GCP CSI driver to v1.13.2 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update GCP CSI driver to v1.15.0 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update Hetzner CCM to v1.20.0 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update Hetzner CSI to v2.7.0 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update Hetzner CSI to v2.9.0 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update Nutanix CCM to v0.4.1 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update Nutanix CSI driver to v2.6.10 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update OpenStack CCM and CSI to v1.30.0 for Kubernetes 1.30 clusters ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update OpenStack CCM to latest patch versions ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update OpenStack Cinder CSI to latest patch versions ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update vSphere CCM to v1.30.1 for Kubernetes 1.30 clusters ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update vSphere CCM to latest patch versions ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update vSphere CSI driver to v3.2.0 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update vSphere CSI driver to v3.3.1 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))
- Update CSI snapshotter to v8.0.1 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update CSI snapshotter to v8.1.0 ([#3410](https://github.com/kubermatic/kubeone/pull/3410), [@xmudrii](https://github.com/xmudrii))

#### Others

- Update metrics-server to v0.7.2 ([#3411](https://github.com/kubermatic/kubeone/pull/3411), [@xmudrii](https://github.com/xmudrii))
- Update NodeLocalDNSCache to v1.23.1 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update cluster-autoscaler to v1.30.1, v1.29.3, v1.28.5, and v1.27.8 ([#3214](https://github.com/kubermatic/kubeone/pull/3214), [@SimonTheLeg](https://github.com/SimonTheLeg))
- Update backups-restic addon's components to the latest versions ([#3412](https://github.com/kubermatic/kubeone/pull/3412), [@xmudrii](https://github.com/xmudrii))
- KubeOne is now built with Go 1.23.0 ([#3350](https://github.com/kubermatic/kubeone/pull/3350), [@xrstf](https://github.com/xrstf))
