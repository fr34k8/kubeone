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

package upgrade

import (
	"github.com/pkg/errors"

	"github.com/kubermatic/kubeone/pkg/config"
	"github.com/kubermatic/kubeone/pkg/ssh"
	"github.com/kubermatic/kubeone/pkg/util"
)

func upgradeFollower(ctx *util.Context) error {
	return ctx.RunTaskOnFollowers(upgradeFollowerExecutor, false)
}

func upgradeFollowerExecutor(ctx *util.Context, node *config.HostConfig, conn ssh.Connection) error {
	ctx.Logger.Infoln("Labeling follower control plane…")
	err := labelNode(ctx.DynamicClient, node)
	if err != nil {
		return errors.Wrap(err, "failed to label leader control plane node")
	}

	ctx.Logger.Infoln("Upgrading kubeadm on follower control plane…")
	err = upgradeKubeadm(ctx, node)
	if err != nil {
		return errors.Wrap(err, "failed to upgrade kubeadm on follower control plane")
	}

	ctx.Logger.Infoln("Running 'kubeadm upgrade' on the follower control plane node…")
	err = upgradeFollowerControlPlane(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to upgrade follower control plane")
	}

	ctx.Logger.Infoln("Upgrading kubelet…")
	err = upgradeKubelet(ctx, node)
	if err != nil {
		return errors.Wrap(err, "failed to upgrade kubelet")
	}

	ctx.Logger.Infoln("Unlabeling follower control plane…")
	err = unlabelNode(ctx.DynamicClient, node)
	if err != nil {
		return errors.Wrap(err, "failed to unlabel follower control plane node")
	}

	return nil
}