module "foo" {
    source = "../../roots"
    vpc_name = var.vpc_name
    ver = "3.2.1"
    password = var.password
    run_profile = var.run_profile
    bucket_name = var.bucket_name
    ami = var.ami

}