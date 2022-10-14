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

provider "aws" {
  region = var.aws_region
}

locals {
  kube_cluster_tag      = "kubernetes.io/cluster/${var.cluster_name}"
  ami                   = var.ami == "" ? data.aws_ami.ami.id : var.ami
  zoneA                 = data.aws_availability_zones.available.names[0]
  zoneB                 = data.aws_availability_zones.available.names[1]
  zoneC                 = data.aws_availability_zones.available.names[2]
  vpc_mask              = parseint(split("/", data.aws_vpc.selected.cidr_block)[1], 10)
  subnet_total          = pow(2, var.subnets_cidr - local.vpc_mask)
  subnet_newbits        = var.subnets_cidr - (32 - local.vpc_mask)
  worker_os             = var.worker_os == "" ? var.ami_filters[var.os].worker_os : var.worker_os
  worker_deploy_ssh_key = var.worker_deploy_ssh_key ? [aws_key_pair.deployer.public_key] : []
  ssh_username          = var.ssh_username == "" ? var.ami_filters[var.os].ssh_username : var.ssh_username
  bastion_user          = var.bastion_user == "" ? var.ami_filters[var.os].ssh_username : var.bastion_user
  kubeapi_endpoint      = ""

  initial_machinedeployment_spotinstances = var.initial_machinedeployment_spotinstances_max_price > 0

  subnets = {
    (local.zoneA) = length(aws_subnet.public.*.id) > 0 ? aws_subnet.public[0].id : ""
    (local.zoneB) = length(aws_subnet.public.*.id) > 0 ? aws_subnet.public[1].id : ""
    (local.zoneC) = length(aws_subnet.public.*.id) > 0 ? aws_subnet.public[2].id : ""
  }
}

################################# DATA SOURCES #################################

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ami" {
  most_recent = true
  owners      = var.ami_filters[var.os].owners

  filter {
    name   = "name"
    values = var.ami_filters[var.os].image_name
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

data "aws_vpc" "selected" {
  id = var.vpc_id == "default" ? aws_default_vpc.default.id : var.vpc_id
}

data "aws_internet_gateway" "default" {
  filter {
    name   = "attachment.vpc-id"
    values = [data.aws_vpc.selected.id]
  }
}

resource "aws_default_vpc" "default" {}

resource "random_integer" "cidr_block" {
  min = 0
  max = local.subnet_total - 1
}

############################### NETWORKING SETUP ###############################

resource "aws_subnet" "public" {
  count                   = 3
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  vpc_id                  = data.aws_vpc.selected.id

  cidr_block = cidrsubnet(
    data.aws_vpc.selected.cidr_block,
    local.subnet_newbits,
    (random_integer.cidr_block.result + count.index) % local.subnet_total,
  )

  tags = tomap({
    "Name"                   = "${var.cluster_name}-${data.aws_availability_zones.available.names[count.index]}",
    "Cluster"                = var.cluster_name,
    (local.kube_cluster_tag) = "shared",
  })
}

################################### FIREWALL ###################################

resource "aws_security_group" "common" {
  name        = "${var.cluster_name}-common"
  description = "cluster common rules"
  vpc_id      = data.aws_vpc.selected.id

  tags = tomap({
    "Cluster"                = var.cluster_name,
    (local.kube_cluster_tag) = "shared",
  })
}

resource "aws_security_group_rule" "ingress_self_allow_all" {
  type              = "ingress"
  security_group_id = aws_security_group.common.id

  description = "allow all incoming traffic from members of this group"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  self        = true
}

resource "aws_security_group_rule" "egress_allow_all" {
  type              = "egress"
  security_group_id = aws_security_group.common.id

  description = "allow all outgoing traffic"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "nodeports" {
  type              = "ingress"
  security_group_id = aws_security_group.common.id

  description = "open nodeports"
  from_port   = 30000
  to_port     = 32767
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.common.id

  description = "open ssh"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "apiserver" {
  type              = "ingress"
  security_group_id = aws_security_group.common.id

  description = "open apiserver"
  from_port   = 6443
  to_port     = 6443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

#################################### SSH KEY ###################################
resource "aws_key_pair" "deployer" {
  key_name   = "${var.cluster_name}-deployer-key"
  public_key = file(var.ssh_public_key_file)
}

##################################### IAM ######################################
resource "aws_iam_role" "role" {
  name = "${var.cluster_name}-host"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "profile" {
  name = "${var.cluster_name}-host"
  role = aws_iam_role.role.name
}

resource "aws_iam_role_policy" "policy" {
  name = "${var.cluster_name}-host"
  role = aws_iam_role.role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["ec2:*"],
        Resource = ["*"]
      },
      {
        Effect   = "Allow",
        Action   = ["elasticloadbalancing:*"],
        Resource = ["*"]
      }
    ]
  })
}
