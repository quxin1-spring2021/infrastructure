provider "aws" {
  region = "us-west-2"
    shared_credentials_file = "/Users/enochqu/.aws/credentials"
    profile = "dev"
}


# create vpc
resource "aws_vpc" "vpc123" {
  cidr_block       = "10.0.0.0/16"
    enable_dns_hostnames = true
  enable_dns_support = true
  enable_classiclink_dns_support = true
  assign_generated_ipv6_cidr_block = false
  instance_tenancy = "default"

  tags = {
    Name = "csye6225-test-vpc"
  }
}

# create subnets
resource "aws_subnet" "subnet01" {
  vpc_id     = aws_vpc.vpc123.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"
    map_public_ip_on_launch = true
  tags = {
    Name = "csye6225-vpc-test-subnet-01"
  }
}

resource "aws_subnet" "subnet02" {
  vpc_id     = aws_vpc.vpc123.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "us-west-2b"
  map_public_ip_on_launch = true
  tags = {
    Name = "csye6225-vpc-test-subnet-02"
  }
}

resource "aws_subnet" "subnet03" {
  vpc_id     = aws_vpc.vpc123.id
  cidr_block = "10.0.3.0/24"
  availability_zone = "us-west-2c"
    map_public_ip_on_launch = true
  tags = {
    Name = "csye6225-vpc-test-subnet-03"
  }
}

# create internet gateway
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.vpc123.id

  tags = {
    Name = "csye6225-test-internet-gateway"
  }
}

# create a public route table
resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.vpc123.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

#   route {
#     ipv6_cidr_block        = "::/0"
#     egress_only_gateway_id = aws_egress_only_internet_gateway.foo.id
#   }

  tags = {
    Name = "csye6225-test-route-table-as3"
  }
}

# associate route table and subnet
resource "aws_route_table_association" "a1" {
  subnet_id      = aws_subnet.subnet01.id
  route_table_id = aws_route_table.rt.id
}

resource "aws_route_table_association" "a2" {
  subnet_id      = aws_subnet.subnet02.id
  route_table_id = aws_route_table.rt.id
}

resource "aws_route_table_association" "a3" {
  subnet_id      = aws_subnet.subnet03.id
  route_table_id = aws_route_table.rt.id
}

