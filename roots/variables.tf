variable "run_profile" {
    type        = string
  default     = "dev"
}

variable "credential_file" {
        type        = string
  default     = "/Users/enochqu/.aws/credentials"
}

variable "vpc_region" {
  description = "region of vpc"
  type        = string
  default     = "us-west-2"
}

variable "vpc_cidr_block" {
      type        = string
  default     = "10.0.0.0/16"
}

variable "subnet1_cidr_block" {
      type        = string
  default     = "10.0.1.0/24"
}
variable "subnet2_cidr_block" {
      type        = string
  default     = "10.0.2.0/24"
}
variable "subnet3_cidr_block" {
      type        = string
  default     = "10.0.3.0/24"
}

variable "route_cidr_block" {
      type        = string
  default     = "0.0.0.0/0"
}

variable "ver" {
  type = string
  default = "0.0.0"
}

variable "vpc_name" {
  
}