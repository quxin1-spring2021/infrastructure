module "foo" {
    source = "../roots"
    vpc_name = "testVpcName"
    ver = "1.2.3"
}

module "boo" {
    source = "../roots"
    vpc_name = "test-Vpc-Name"
    ver = "1.2.4"
}

module "hoo" {
    source = "../roots"
    vpc_name = "test-Vpc-Name-2"
    ver = "1.2.5"
}