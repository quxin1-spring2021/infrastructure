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
  default = "ami-0daa8070ba5c0d47c"
}

variable "bucket_name" {
  type = string
}