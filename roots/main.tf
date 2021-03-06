provider "aws" {
  region = var.vpc_region
  shared_credentials_file = var.credential_file
  profile = var.run_profile
}


# create vpc
resource "aws_vpc" "my_vpc" {
  cidr_block       = var.vpc_cidr_block
  enable_dns_hostnames = true
  enable_dns_support = true
  enable_classiclink_dns_support = true
  assign_generated_ipv6_cidr_block = false
  instance_tenancy = "default"

  tags = {
    Name = "demo-${var.ver}-${var.vpc_name}-vpc"
  }
}

# create subnets
resource "aws_subnet" "subnet01" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = var.subnet1_cidr_block
  availability_zone = "${var.vpc_region}a"
    map_public_ip_on_launch = true
  tags = {
    Name = "demo-${var.ver}-subnet-01"
  }
}

resource "aws_subnet" "subnet02" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = var.subnet2_cidr_block
  availability_zone = "${var.vpc_region}b"
  map_public_ip_on_launch = true
  tags = {
    Name = "demo-${var.ver}-subnet-02"
  }
}

resource "aws_subnet" "subnet03" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = var.subnet3_cidr_block
  availability_zone = "${var.vpc_region}c"
  map_public_ip_on_launch = true
  tags = {
    Name = "demo-${var.ver}-subnet-03"
  }
}

# create internet gateway
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name = "demo-${var.ver}-internet-gateway"
  }
}

# create a public route table
resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.my_vpc.id

  route {
    cidr_block = var.route_cidr_block
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = {
    Name = "demo-${var.ver}-route-table"
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

# create IAM policy
resource "aws_iam_policy" "policy" {
  name        = "WebAppS3-Demo"
  description = "Permissions for the S3 bucket to create secure policies."

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:*"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${aws_s3_bucket.bucket.id}",
                "arn:aws:s3:::${aws_s3_bucket.bucket.id}/*"
            ]
        }
    ]
})
}

# create IAM Role
resource "aws_iam_role" "role" {
  name = "EC2-CSYE6225-DEMO"
  description = "Allows EC2 instances to call AWS services on your behalf."
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

}

# attach role and policy
resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}

# application security group
resource "aws_security_group" "application" {
  name        = "WebApplicationSecurityGroup"
  description = "WebApplicationSecurityGroup"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "database" {
  name        = "DBSecurityGroup"
  description = "EC2 security group for your RDS instances."
  vpc_id      = aws_vpc.my_vpc.id


  ingress {
    description = "for PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  ingress {
    description = "for MySQL"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.application.id]
  }

}

# S3 bucket
resource "aws_s3_bucket" "bucket" {
  bucket = var.bucket_name
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
      }
    }
  }

  lifecycle_rule {

    enabled = true

    transition {
      days = 30
      storage_class = "STANDARD_IA"
    }
  }

  force_destroy = true

}

# db subnet group

resource "aws_db_subnet_group" "default" {
  name       = "main"
  subnet_ids = [aws_subnet.subnet01.id, aws_subnet.subnet02.id, aws_subnet.subnet03.id]

  tags = {
    Name = "My DB subnet group"
  }
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app_iam_profile"
  role = aws_iam_role.role.name
}

# RDS instance
resource "aws_db_instance" "db_instance" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0.20"
  instance_class       = "db.t3.micro"
  identifier           = "csye6225"
  name                 = "csye6225"
  username             = "csye6225"
  password             = "Crazy97021^"
  multi_az             = false
  publicly_accessible  = false
  skip_final_snapshot  = true
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name = aws_db_subnet_group.default.name
}

# EC2 instance

resource "aws_instance" "webapp" {
  ami           = var.ami
  instance_type = "t2.micro"
  key_name = "csye6225_2021spring"
  vpc_security_group_ids = [aws_security_group.application.id]
  iam_instance_profile = aws_iam_instance_profile.app_profile.id
  subnet_id = aws_subnet.subnet01.id
  root_block_device {
    volume_size = 20
    volume_type = "gp2"
    delete_on_termination = true
  }

  tags = {
    Name = "EC2-WebApplication"
  }

  user_data =  <<EOF
Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0
--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"
#cloud-config
cloud_final_modules:
- [scripts-user, always]
--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"
#!/bin/bash
/bin/echo "Hello World" >> /home/ubuntu/testfile.txt
/bin/mkdir /home/ubuntu/webapp
/bin/echo 'HOSTNAME = ${aws_db_instance.db_instance.address}' > /home/ubuntu/webapp/.env
/bin/echo 'RDS_USERNAME = ${aws_db_instance.db_instance.username}' >> /home/ubuntu/webapp/.env
/bin/echo 'RDS_PASSWORD = ${var.password}' >> /home/ubuntu/webapp/.env
/bin/echo 'RDS_DATABASE = ${aws_db_instance.db_instance.name}' >> /home/ubuntu/webapp/.env
/bin/echo 'RDS_PORT = ${aws_db_instance.db_instance.port}' >> /home/ubuntu/webapp/.env
/bin/echo 'BUCKET_NAME = ${aws_s3_bucket.bucket.id}' >> /home/ubuntu/webapp/.env
--//
EOF
}