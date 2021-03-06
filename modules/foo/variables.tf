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
  default = "ami-0018242d05f0c9ce6"
}

variable "bucket_name" {
  type = string
}