# TEMPLATE ONLY - NOT plan/apply validated against a live tenancy.
# Shows how a Compute instance with the audited Oracle Cloud Agent plugins
# would be declared; the Python audit checks exports against this posture.
terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0"
    }
  }
}

variable "compartment_ocid" {
  type        = string
  description = "OCID of the compartment that owns the instance"
}

variable "subnet_ocid" {
  type        = string
  description = "OCID of the subnet for the instance VNIC"
}

variable "image_ocid" {
  type        = string
  description = "OCID of the platform image"
}

# Reference posture: every audited plugin enabled on a production instance.
resource "oci_core_instance" "audited" {
  compartment_id      = var.compartment_ocid
  availability_domain = "change-me"
  shape               = "VM.Standard.E4.Flex"
  display_name        = "prod-audited-1"

  agent_config {
    is_management_disabled = false   # OS Management Service Agent (AGP003)
    is_monitoring_disabled = false   # Compute Instance Monitoring (AGP005)

    plugins_config {
      name          = "Bastion"
      desired_state = "ENABLED"      # AGP001
    }
    plugins_config {
      name          = "Vulnerability Scanning"
      desired_state = "ENABLED"      # AGP002
    }
    plugins_config {
      name          = "Custom Logs Monitoring"
      desired_state = "ENABLED"      # AGP004
    }
  }

  create_vnic_details {
    subnet_id = var.subnet_ocid
  }

  source_details {
    source_type = "image"
    source_id   = var.image_ocid
  }
}
