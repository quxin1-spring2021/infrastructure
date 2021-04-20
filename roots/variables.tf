variable "run_profile" {
    type        = string
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
  type = string
}

variable "route53_record" {
  type = object({
    prod = string
    dev = string
  })

  default = {
    prod = "Z0618647372SM5AHYPKSG"
    dev = "Z06188442KAEZYTY2ORM4"
  }
}

variable "rds_db_instance" {
  type = object({
    engine = string
    engine_version = string
    allocated_storage = number
    instance_class = string
    identifier = string
    username = string
    name = string
    encrypt_option = bool
  })
  default = {
    engine = "mysql"
    engine_version = "8.0.20"
    allocated_storage = 20
    instance_class = "db.t3.micro"
    identifier = "webapp-rds-db"
    username = "webapp"
    name = "webapp"
    encrypt_option = true
  }
}

variable "db_password" {
  type = string
  sensitive = true
}

variable "ami" {
  type = string
  validation {
    condition     = length(var.ami) > 4 && substr(var.ami, 0, 4) == "ami-"
    error_message = "The image_id value must be a valid AMI id, starting with \"ami-\"."
  }
}

variable "bucket_name" {
  type = string
}