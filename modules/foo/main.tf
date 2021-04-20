module "foo" {
    source = "../../roots"
    vpc_name = var.vpc_name
    ver = "foo.1.2.3"
    password = var.password
    run_profile = var.run_profile
    bucket_name = var.bucket_name
    ami = var.ami

}