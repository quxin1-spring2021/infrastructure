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
  default = "ami-0d8bab8715de03443"
}

variable "bucket_name" {
  type = string
}