/*
Copyright 2019 The KubeOne Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mcv1beta2

import (
	"encoding/json"
	"fmt"

	"github.com/imdario/mergo"

	kubeonev1beta2 "k8c.io/kubeone/pkg/apis/kubeone/v1beta2"
	"k8c.io/kubeone/pkg/fail"
	"k8c.io/kubeone/pkg/templates/machinecontroller"

	corev1 "k8s.io/api/core/v1"
)

type Config struct {
	TFConfig *TerraformConfig
	MCConfig *MachineControllerConfig
}

// TerraformConfig represents configuration in the terraform output format
type TerraformConfig struct {
	KubeOneCluster struct {
		Sensitive json.RawMessage `json:"sensitive"`
		Type      json.RawMessage `json:"type"`

		Value struct {
			ClusterName               string   `json:"cluster_name"`
			CloudProvider             *string  `json:"cloud_provider"`
			Endpoint                  string   `json:"endpoint"`
			APIServerAlternativeNames []string `json:"apiserver_alternative_names"`
			LeaderIP                  string   `json:"leader_ip"`
			Untaint                   bool     `json:"untaint"`
		} `json:"value"`
	} `json:"kubeone_cluster"`

	KubeOneWorkers struct {
		Sensitive json.RawMessage `json:"sensitive"`
		Type      json.RawMessage `json:"type"`

		Value map[string]kubeonev1beta2.DynamicWorkerConfig `json:"value"`
	} `json:"kubeone_workers"`

	Proxy struct {
		Sensitive json.RawMessage `json:"sensitive"`
		Type      json.RawMessage `json:"type"`

		Value kubeonev1beta2.ProxyConfig `json:"value"`
	} `json:"proxy"`
}

// MachineControllerConfig represents configuration in the machine-controller output format
type MachineControllerConfig struct {
	ControlPlaneMachines []hostsSpec `json:"control_plane_machines"`
	Bastion              *hostsSpec  `json:"bastion"`
}

type hostsSpec struct {
	PublicAddress     string `json:"public_address"`
	PrivateAddress    string `json:"private_address"`
	Hostname          string `json:"hostname"`
	OperatingSystem   string `json:"operating_system"`
	SSHUser           string `json:"ssh_user"`
	SSHPort           int    `json:"ssh_port"`
	SSHPrivateKeyFile string `json:"ssh_private_key_file"`
	SSHAgentSocket    string `json:"ssh_agent_socket"`
	SSHHostKey        []byte `json:"ssh_hosts_key"`
}

type hostConfigsOpts func([]kubeonev1beta2.HostConfig)

func isLeaderHostConfigsOpts(leaderIP string) hostConfigsOpts {
	return func(hosts []kubeonev1beta2.HostConfig) {
		if leaderIP == "" {
			return
		}

		for i := range hosts {
			hosts[i].IsLeader = leaderIP == hosts[i].PublicAddress || leaderIP == hosts[i].PrivateAddress
		}
	}
}

func untainerHostConfigsOpts(untaint bool) hostConfigsOpts {
	return func(hosts []kubeonev1beta2.HostConfig) {
		if !untaint {
			return
		}

		for i := range hosts {
			hosts[i].Taints = []corev1.Taint{}
		}
	}
}

func idIncrementerHostConfigsOpts(currentHostID int) hostConfigsOpts {
	return func(hosts []kubeonev1beta2.HostConfig) {
		for i := range hosts {
			hosts[i].ID = currentHostID
			currentHostID++
		}
	}
}

func bastionHostConfigsOpts(spec *hostsSpec) hostConfigsOpts {
	return func(hosts []kubeonev1beta2.HostConfig) {
		if spec != nil {
			address := spec.PublicAddress
			if address == "" {
				address = spec.PrivateAddress
			}

			for i := range hosts {
				hosts[i].Bastion = address
				hosts[i].BastionPort = spec.SSHPort
				hosts[i].BastionUser = spec.SSHUser
				hosts[i].BastionHostPublicKey = spec.SSHHostKey
			}
		}
	}
}

func (mcc *MachineControllerConfig) toHostConfigs(opts ...hostConfigsOpts) []kubeonev1beta2.HostConfig {
	hosts := []kubeonev1beta2.HostConfig{}

	for _, machine := range mcc.ControlPlaneMachines {
		privateIP := machine.PublicAddress
		if machine.PrivateAddress != "" {
			privateIP = machine.PrivateAddress
		}

		hosts = append(hosts, newHostConfig(machine.PublicAddress, privateIP, machine.Hostname, machine.SSHHostKey, &machine)) //nolint:gosec
	}

	for _, mutatorFn := range opts {
		mutatorFn(hosts)
	}

	return hosts
}

type cloudProviderFlags struct {
	key   string
	value interface{}
}

// NewConfigFromJSON creates a new config object from json
func NewConfigFromJSON(tf, mc []byte) (*Config, error) {
	wholeTFOutput := struct {
		KubeOneCluster interface{} `json:"kubeone_cluster"`
		KubeoneWorkers interface{} `json:"kubeone_workers"`
		Proxy          interface{} `json:"proxy"` // TODO: this is missing in the original configs
	}{}

	// cat off all the excessive fields from the terraform output JSON that will prevent otherwise strict unmarshalling
	// of our known fields
	if err := json.Unmarshal(tf, &wholeTFOutput); err != nil {
		return nil, fail.Runtime(err, "unmarshal terraform output")
	}

	strictTF, err := json.Marshal(wholeTFOutput)
	if err != nil {
		return nil, fail.Runtime(err, "marshal terraform output")
	}

	tfConfig := &TerraformConfig{}

	if tfErr := unmarshalStrict(strictTF, tfConfig); tfErr != nil {
		return nil, fail.Runtime(tfErr, "reading terraform output")
	}

	wholeMCOutput := struct {
		ControlPlaneMachines interface{} `json:"control_plane_machines"`
		Bastion              interface{} `json:"bastion"`
	}{}

	// cat off all the excessive fields from the machine-controller output JSON that will prevent otherwise strict unmarshalling
	// of our known fields
	if mcErr := json.Unmarshal(mc, &wholeMCOutput); mcErr != nil {
		return nil, fail.Runtime(mcErr, "unmarshal machine-controller output")
	}

	strictMC, err := json.Marshal(wholeMCOutput)
	if err != nil {
		return nil, fail.Runtime(err, "marshal machine-controller output")
	}

	mcConfig := &MachineControllerConfig{}

	if err := unmarshalStrict(strictMC, mcConfig); err != nil {
		return nil, fail.Runtime(err, "reading machine-controller output")
	}

	config := &Config{
		TFConfig: tfConfig,
		MCConfig: mcConfig,
	}

	return config, nil
}

// Apply adds the terraform configuration options to the given cluster config.
func (output *Config) Apply(cluster *kubeonev1beta2.KubeOneCluster) error {
	cl := output.TFConfig.KubeOneCluster.Value

	if output.TFConfig.KubeOneCluster.Value.Endpoint != "" {
		cluster.APIEndpoint.Host = cl.Endpoint
	}

	if len(cl.APIServerAlternativeNames) > 0 {
		cluster.APIEndpoint.AlternativeNames = cl.APIServerAlternativeNames
	}

	if cl.CloudProvider != nil {
		cloudProvider := &kubeonev1beta2.CloudProviderSpec{}
		if err := kubeonev1beta2.SetCloudProvider(cloudProvider, *cl.CloudProvider); err != nil {
			return err
		}
		if err := mergo.Merge(&cluster.CloudProvider, cloudProvider); err != nil {
			return fail.Runtime(err, "merging cloud provider structs")
		}
	}

	cluster.Name = cl.ClusterName

	idIncrementer := idIncrementerHostConfigsOpts(0)
	isLeader := isLeaderHostConfigsOpts(cl.LeaderIP)
	untainer := untainerHostConfigsOpts(cl.Untaint)
	bastion := bastionHostConfigsOpts(output.MCConfig.Bastion)

	// build up a list of master nodes
	cpHosts := output.MCConfig.toHostConfigs(idIncrementer, isLeader, untainer, bastion)

	if len(cpHosts) > 0 {
		cluster.ControlPlane.Hosts = cpHosts
	}

	// var staticWorkerGroupNames []string
	// for key := range output.KubeOneStaticWorkers.Value {
	// 	staticWorkerGroupNames = append(staticWorkerGroupNames, key)
	// }

	// // avoid randomized access to the map
	// sort.Strings(staticWorkerGroupNames)
	// for _, groupName := range staticWorkerGroupNames {
	// 	staticWorkersGroup := output.KubeOneStaticWorkers.Value[groupName]
	// 	staticWorkers := staticWorkersGroup.toHostConfigs(idIncrementer)
	// 	cluster.StaticWorkers.Hosts = append(cluster.StaticWorkers.Hosts, staticWorkers...)
	// }

	// if err := mergo.Merge(&cluster.Proxy, &output.TFConfig.Proxy.Value); err != nil {
	// 	return fail.Runtime(err, "merging proxy settings")
	// }

	// if len(cp.NetworkID) > 0 && cluster.CloudProvider.Hetzner != nil {
	// 	// NetworkID is used only for Hetzner
	// 	cluster.CloudProvider.Hetzner.NetworkID = cp.NetworkID
	// }

	// if cluster.CloudProvider.VMwareCloudDirector != nil {
	// 	// VAppName is used only for VMware Cloud Director.
	// 	if len(cp.VAppName) > 0 {
	// 		cluster.CloudProvider.VMwareCloudDirector.VApp = cp.VAppName
	// 	} else {
	// 		cluster.CloudProvider.VMwareCloudDirector.VApp = cluster.Name
	// 	}

	// 	// Set StorageProfile.
	// 	if len(cp.StorageProfile) > 0 {
	// 		cluster.CloudProvider.VMwareCloudDirector.VApp = cp.VAppName
	// 	}
	// }

	// Walk through all configured workersets from terraform and apply their config
	// by either merging it into an existing workerSet or creating a new one
	for workersetName, workersetValue := range output.TFConfig.KubeOneWorkers.Value {
		var existingWorkerSet *kubeonev1beta2.DynamicWorkerConfig

		// Check do we have a workerset with the same name defined
		// in the KubeOneCluster object
		for idx, workerset := range cluster.DynamicWorkers {
			if workerset.Name == workersetName {
				existingWorkerSet = &cluster.DynamicWorkers[idx]

				break
			}
		}

		// If we didn't found a workerset defined in the cluster object,
		// append a workerset from the terraform output to the cluster object
		if existingWorkerSet == nil {
			// no existing workerset found, use what we have from terraform
			workersetValue.Name = workersetName
			cluster.DynamicWorkers = append(cluster.DynamicWorkers, workersetValue)

			continue
		}

		var err error

		// If we found a workerset defined in the cluster object,
		// merge values from the object and the terraform output
		switch {
		case cluster.CloudProvider.AWS != nil:
			err = updateAWSWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		case cluster.CloudProvider.Azure != nil:
			err = updateAzureWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		case cluster.CloudProvider.DigitalOcean != nil:
			err = updateDigitalOceanWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		case cluster.CloudProvider.GCE != nil:
			err = updateGCEWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		case cluster.CloudProvider.Hetzner != nil:
			err = updateHetznerWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		case cluster.CloudProvider.Nutanix != nil:
			err = updateNutanixWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		case cluster.CloudProvider.Openstack != nil:
			err = updateOpenStackWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		case cluster.CloudProvider.EquinixMetal != nil:
			err = updateEquinixMetalWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		case cluster.CloudProvider.VMwareCloudDirector != nil:
			err = updateVMwareCloudDirectorWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		case cluster.CloudProvider.Vsphere != nil:
			err = updateVSphereWorkerset(existingWorkerSet, workersetValue.Config.CloudProviderSpec)
		default:
			err = fail.Runtime(fmt.Errorf("unknown"), "checking provider")
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func newHostConfig(publicIP, privateIP, hostname string, sshHostKey []byte, spec *hostsSpec) kubeonev1beta2.HostConfig {
	hostConfig := kubeonev1beta2.HostConfig{
		Hostname:          hostname,
		OperatingSystem:   kubeonev1beta2.OperatingSystemName(spec.OperatingSystem),
		PrivateAddress:    privateIP,
		PublicAddress:     publicIP,
		SSHAgentSocket:    spec.SSHAgentSocket,
		SSHPrivateKeyFile: spec.SSHPrivateKeyFile,
		SSHUsername:       spec.SSHUser,
		SSHPort:           spec.SSHPort,
		// Kubelet:              kubeonev1beta2.KubeletConfig{},
		SSHHostPublicKey: sshHostKey,
	}

	// parseKubeletResourceParams(spec.Kubelet, &hostConfig.Kubelet)

	return hostConfig
}

func setWorkersetFlag(w *kubeonev1beta2.DynamicWorkerConfig, name string, value interface{}) error {
	// ignore empty values (i.e. not set in terraform output)
	switch s := value.(type) {
	case int:
		if s == 0 {
			return nil
		}
	case *int:
		if s == nil {
			return nil
		}
	case *uint:
		if s == nil {
			return nil
		}
	case string:
		if s == "" {
			return nil
		}
	case *string:
		if s == nil {
			return nil
		}
	case []string:
		if len(s) == 0 {
			return nil
		}
	case map[string]string:
		if s == nil {
			return nil
		}
	case bool:
	case *bool:
		if s == nil {
			return nil
		}
	case machinecontroller.AzureImagePlan:
	case *machinecontroller.AzureImagePlan:
		if s == nil {
			return nil
		}
	default:
		return fail.Runtime(fmt.Errorf("unsupported type %T %v", value, value), "reading terraform values")
	}

	// update CloudProviderSpec ONLY IF given terraform output is absent in
	// original CloudProviderSpec
	jsonSpec := make(map[string]interface{})
	if w.Config.CloudProviderSpec != nil {
		if err := json.Unmarshal(w.Config.CloudProviderSpec, &jsonSpec); err != nil {
			return fail.Config(err, "reading CloudProviderSpec")
		}
	}

	if _, exists := jsonSpec[name]; !exists {
		jsonSpec[name] = value
	}

	var err error
	w.Config.CloudProviderSpec, err = json.Marshal(jsonSpec)
	if err != nil {
		return fail.Config(err, "updating cloud provider spec")
	}

	return nil
}

// func parseKubeletResourceParams(ks kubeletSpec, kc *kubeonev1beta2.KubeletConfig) {
// 	if len(ks.KubeReserved) > 0 {
// 		kc.KubeReserved = map[string]string{}
// 		for _, krPair := range strings.Split(ks.KubeReserved, ",") {
// 			krKV := strings.SplitN(krPair, "=", 2)
// 			if len(krKV) != 2 {
// 				continue
// 			}
// 			kc.KubeReserved[krKV[0]] = krKV[1]
// 		}
// 	}

// 	if len(ks.SystemReserved) > 0 {
// 		kc.SystemReserved = map[string]string{}
// 		for _, srPair := range strings.Split(ks.SystemReserved, ",") {
// 			srKV := strings.SplitN(srPair, "=", 2)
// 			if len(srKV) != 2 {
// 				continue
// 			}
// 			kc.SystemReserved[srKV[0]] = srKV[1]
// 		}
// 	}

// 	if len(ks.EvictionHard) > 0 {
// 		kc.EvictionHard = map[string]string{}
// 		for _, ehPair := range strings.Split(ks.EvictionHard, ",") {
// 			ehKV := strings.SplitN(ehPair, "<", 2)
// 			if len(ehKV) != 2 {
// 				continue
// 			}
// 			kc.EvictionHard[ehKV[0]] = ehKV[1]
// 		}
// 	}

// 	kc.MaxPods = ks.MaxPods
// }
