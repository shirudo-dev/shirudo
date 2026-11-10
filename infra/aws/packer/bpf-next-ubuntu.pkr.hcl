packer {
  required_plugins {
    amazon = {
      version = ">= 1.8.2"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "region" {
  type    = string
  default = "us-west-2"
}

variable "instance_type" {
  type    = string
  default = "t3.large"
}

variable "root_volume_size" {
  type    = number
  default = 30
}

variable "ubuntu_version" {
  type    = string
  default = "26.04"
}

variable "image_role" {
  type        = string
  default     = "target"
  description = "Image role: target initializes Shirudo at boot; dev leaves it uninstalled."

  validation {
    condition     = contains(["dev", "target"], var.image_role)
    error_message = "The image_role must be dev or target."
  }
}

variable "kernel_github_run_id" {
  type        = string
  default     = ""
  description = "Optional exact GitHub Actions run id to use instead of the latest successful kernel main branch run."
}

variable "iam_instance_profile" {
  type        = string
  description = "IAM instance profile for the temporary builder instance. The wrapper script creates and passes one."
}

variable "github_token" {
  type        = string
  default     = env("GH_TOKEN")
  sensitive   = true
  description = "GitHub token supplied automatically through GH_TOKEN by the wrapper."
}

variable "shirudo_github_run_id" {
  type        = string
  default     = ""
  description = "Optional exact GitHub Actions run id to use instead of the latest successful main branch run."
}

variable "additional_build_tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags for the temporary EC2 builder instance and its root volume."
}

locals {
  ami_prefix                = var.image_role == "dev" ? "shirudo-dev-ubuntu" : "shirudo-target-ubuntu"
  ami_name                  = "${local.ami_prefix}-${var.ubuntu_version}-{{timestamp}}"
  shirudo_cert_path         = "${path.root}/../../certs/shirudo.der"
  shirudo_image_assets_path = "${path.root}/.shirudo-image-assets.tar.gz"
  target_provisioner_except = var.image_role == "dev" ? ["amazon-ebs.bpf_next_ubuntu"] : []
  packer_run_tags = merge(var.additional_build_tags, {
    Name = "packer-${local.ami_prefix}"
    env  = "build"
    role = "packer"
  })
  packer_run_volume_tags = merge(var.additional_build_tags, {
    Name = "packer-${local.ami_prefix}-root"
  })
}

source "amazon-ebs" "bpf_next_ubuntu" {
  region        = var.region
  instance_type = var.instance_type
  ssh_username  = "ubuntu"
  ami_name      = local.ami_name

  ami_description      = "Ubuntu ${var.ubuntu_version} ${var.image_role} AMI running a bpf-next kernel installed from deb packages"
  ena_support          = true
  communicator         = "ssh"
  ssh_interface        = "session_manager"
  iam_instance_profile = var.iam_instance_profile
  pause_before_ssm     = "45s"
  ssh_timeout          = "15m"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  user_data = <<-EOF
    #!/usr/bin/env bash
    set -eux

    ssm_tmp="$(mktemp -d)"
    trap 'rm -rf "$ssm_tmp"' EXIT
    if systemctl cat snap.amazon-ssm-agent.amazon-ssm-agent.service >/dev/null 2>&1; then
      snap remove amazon-ssm-agent || true
    fi
    curl -fsSL https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb \
      -o "$ssm_tmp/amazon-ssm-agent.deb"
    dpkg -i "$ssm_tmp/amazon-ssm-agent.deb"
    systemctl enable --now amazon-ssm-agent.service
    systemctl is-active --quiet amazon-ssm-agent.service
  EOF

  source_ami_filter {
    filters = {
      architecture        = "x86_64"
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-*-${var.ubuntu_version}-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"]
    most_recent = true
  }

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
  }

  run_tags        = local.packer_run_tags
  run_volume_tags = local.packer_run_volume_tags

  snapshot_tags = {
    Name = "${local.ami_name}-root"
  }

  tags = {
    Name         = local.ami_name
    BaseOS       = "ubuntu-${var.ubuntu_version}"
    KernelFlavor = "bpf-next"
    KernelDebs   = "kernel-packages-x86-64-full"
    ShirudoRole  = var.image_role
  }
}

build {
  name    = "bpf-next-ubuntu"
  sources = ["source.amazon-ebs.bpf_next_ubuntu"]

  provisioner "shell-local" {
    except = local.target_provisioner_except
    inline = [
      "set -eu",
      "test -s '${local.shirudo_cert_path}'",
    ]
  }

  provisioner "shell-local" {
    except = local.target_provisioner_except
    environment_vars = [
      "SHIRUDO_IMAGE_ASSETS_TARBALL=${local.shirudo_image_assets_path}",
    ]
    inline = [
      "set -eu",
      "test -n \"$SHIRUDO_IMAGE_ASSETS_TARBALL\"",
      "test -s \"$SHIRUDO_IMAGE_ASSETS_TARBALL\"",
      "assets_dir=$(mktemp -d)",
      "trap 'rm -rf \"$assets_dir\"' EXIT",
      "tar -xzf \"$SHIRUDO_IMAGE_ASSETS_TARBALL\" -C \"$assets_dir\"",
      "for file in shirudo-target initial.img initial.verity initial.roothash initial.p7s runtime.img runtime.verity runtime.roothash runtime.p7s runtime-service.conf initrd-bootstrap.conf; do test -s \"$assets_dir/$file\"; done",
      "test -x \"$assets_dir/shirudo-target\"",
      "runtime_root_hash=$(cat \"$assets_dir/runtime.roothash\")",
      "printf '%s\\n' \"$runtime_root_hash\" | grep -Eq '^[0-9a-f]{64}$'",
      "grep -Fqx 'runtime.image = /var/lib/shirudo/images/runtime' \"$assets_dir/initrd-bootstrap.conf\"",
      "grep -Fqx \"runtime.root_hash = $runtime_root_hash\" \"$assets_dir/initrd-bootstrap.conf\"",
    ]
  }

  provisioner "shell" {
    environment_vars = [
      "GITHUB_TOKEN=${var.github_token}",
      "KERNEL_GITHUB_RUN_ID=${var.kernel_github_run_id}",
    ]
    script       = "${path.root}/scripts/install-bpf-next-kernel.sh"
    timeout      = "45m"
  }

  provisioner "shell" {
    script = "${path.root}/scripts/pre-reboot-diagnostics.sh"
  }

  provisioner "shell" {
    inline            = ["sudo reboot"]
    expect_disconnect = true
    skip_clean        = true
  }

  provisioner "shell" {
    pause_before = "180s"
    inline = [
      "set -eu",
      "expected_kernel=$(cat /etc/bpf-next-kernel-release)",
      "running_kernel=$(uname -r)",
      "test \"$running_kernel\" = \"$expected_kernel\"",
      "cat /etc/bpf-next-kernel-build",
    ]
  }

  provisioner "shell" {
    except = local.target_provisioner_except
    environment_vars = [
      "GITHUB_TOKEN=${var.github_token}",
      "SHIRUDO_GITHUB_RUN_ID=${var.shirudo_github_run_id}",
    ]
    script  = "${path.root}/scripts/install-shirudo-target-from-github-artifact.sh"
    timeout = "20m"
  }

  provisioner "file" {
    except      = local.target_provisioner_except
    source      = local.shirudo_cert_path
    destination = "/tmp/shirudo-cert.der"
  }

  provisioner "shell" {
    except = local.target_provisioner_except
    inline = [
      "set -eu",
      "sudo install -d -o root -g root -m 0755 /var/lib/shirudo/keys",
      "sudo install -o root -g root -m 0644 /tmp/shirudo-cert.der /var/lib/shirudo/keys/cert.der",
      "rm -f /tmp/shirudo-cert.der",
    ]
  }

  provisioner "file" {
    except      = local.target_provisioner_except
    source      = local.shirudo_image_assets_path
    destination = "/tmp/shirudo-image-assets.tar.gz"
  }

  provisioner "shell" {
    except  = local.target_provisioner_except
    script  = "${path.root}/scripts/configure-shirudo-initrd.sh"
    timeout = "20m"
  }

  post-processor "manifest" {
    output     = "${path.root}/packer-manifest.json"
    strip_path = true
  }

  post-processor "shell-local" {
    environment_vars = [
      "AWS_REGION=${var.region}",
      "PACKER_MANIFEST_PATH=${path.root}/packer-manifest.json",
      "UBUNTU_VERSION=${var.ubuntu_version}",
      "KERNEL_ARTIFACT_NAME=kernel-packages-x86-64-full",
      "SHIRUDO_IMAGE_ROLE=${var.image_role}",
    ]
    script = "${path.root}/scripts/register-nitrotpm-ami.sh"
  }
}
