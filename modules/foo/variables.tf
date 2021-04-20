variable "run_profile" {
    type        = string
}

variable "vpc_name" {
  type = string
}

variable "password" {
  type = string
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