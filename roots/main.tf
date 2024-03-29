#-------------------------------------------------------------------------------------#
# Provider
provider "aws" {
  region = var.vpc_region
  shared_credentials_file = var.credential_file
  profile = var.run_profile
}

#-------------------------------------------------------------------------------------#
# data offers informations of current profile
data "aws_caller_identity" "current" {}

#-------------------------------------------------------------------------------------#
# dummy zip file for initialize lambda function with empty function, the actual lambda function
# will be updated through CI/CD workflow.
data "archive_file" "dummy" {
  type = "zip"
  output_path = "./lambda_function_payload.zip"

  source {
    content = "hello"
    filename = "dummy.txt"
  }
}

#-------------------------------------------------------------------------------------#
# New VPC
resource "aws_vpc" "my_vpc" {
  cidr_block       = var.vpc_cidr_block
  enable_dns_hostnames = true
  enable_dns_support = true
  enable_classiclink_dns_support = true
  assign_generated_ipv6_cidr_block = false
  instance_tenancy = "default"

  tags = {
    Name = "ver-${var.ver}-${var.vpc_name}-vpc"
  }
}

#-------------------------------------------------------------------------------------#
# Subnets of New VPC
resource "aws_subnet" "subnet01" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = var.subnet1_cidr_block
  availability_zone = "${var.vpc_region}a"
    map_public_ip_on_launch = true
  tags = {
    Name = "ver-${var.ver}-subnet-01"
  }
}

resource "aws_subnet" "subnet02" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = var.subnet2_cidr_block
  availability_zone = "${var.vpc_region}b"
  map_public_ip_on_launch = true
  tags = {
    Name = "ver-${var.ver}-subnet-02"
  }
}

resource "aws_subnet" "subnet03" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = var.subnet3_cidr_block
  availability_zone = "${var.vpc_region}c"
  map_public_ip_on_launch = true
  tags = {
    Name = "ver-${var.ver}-subnet-03"
  }
}

#-------------------------------------------------------------------------------------#
# create internet gateway
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name = "ver-${var.ver}-internet-gateway"
  }
}

#-------------------------------------------------------------------------------------#
# create a public route table
resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.my_vpc.id

  route {
    cidr_block = var.route_cidr_block
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = {
    Name = "ver-${var.ver}-route-table"
  }
}

#-------------------------------------------------------------------------------------#
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

#-------------------------------------------------------------------------------------#
# IAM policy to allow applications on EC2 instances operate on S3 bucket
resource "aws_iam_policy" "webapp_s3_policy" {
  name        = "WebAppS3-Policy"
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
                "arn:aws:s3:::${aws_s3_bucket.object.id}",
                "arn:aws:s3:::${aws_s3_bucket.object.id}/*"
            ]
        }
    ]
})
}

#-------------------------------------------------------------------------------------#
# IAM policy to allow web application role use kms keys
resource "aws_iam_policy" "webapp_kms_policy" {
  name        = "WebApp-KMS-Policy"
  description = "Permissions for the KMS to create secure policies."

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:RevokeGrant",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyWithoutPlaintext",
                "kms:DescribeKey",
                "kms:CreateGrant",
                "kms:ListGrants"
            ],
            "Effect": "Allow",
            "Resource": [
                aws_kms_key.ebs.arn,
                aws_kms_key.rds.arn
            ]
        }
    ]
})
}

#-------------------------------------------------------------------------------------#
# Policy allows EC2 instances to get deploy package from S3 bucket. 
resource "aws_iam_policy" "CodeDeploy_EC2_S3" {
  name        = "CodeDeploy-EC2-S3"
  description = "Policy allows EC2 instances to read data from S3 buckets. "

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:Get*",
                "s3:List*"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::codedeploy.webapp.${var.run_profile}.xin.qu",
                "arn:aws:s3:::codedeploy.webapp.${var.run_profile}.xin.qu/*"
            ]
        }
    ]
})
}

#-------------------------------------------------------------------------------------#
# Policy allows GitHub Actions put new artifacte to S3 bucket. 
resource "aws_iam_policy" "GH_Upload_To_S3" {
  name        = "GH-Upload-To-S3"
  description = "Permissions for the S3 bucket to create secure policies."

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.webapp.${var.run_profile}.xin.qu",
                "arn:aws:s3:::codedeploy.webapp.${var.run_profile}.xin.qu/*"
            ]
        }
    ]
})
}

#-------------------------------------------------------------------------------------#
# Policy allows GitHub Actions to call CodeDeploy APIs to CodeDeploy applications.
resource "aws_iam_policy" "GH_Code_Deploy" {
  name        = "GH-Code-Deploy"
  description = "Policy allows GitHub Actions to call CodeDeploy APIs to initiate application deployment on EC2 instances."

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:GetApplicationRevision",
                "codedeploy:RegisterApplicationRevision"
            ],
            "Resource": "arn:aws:codedeploy:${var.vpc_region}:${data.aws_caller_identity.current.account_id}:application:${aws_codedeploy_app.webapp.name}"
        },
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:CreateDeployment",
                "codedeploy:GetDeployment"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:GetDeploymentConfig"
            ],
            "Resource": [
                "arn:aws:codedeploy:${var.vpc_region}:${data.aws_caller_identity.current.account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
                "arn:aws:codedeploy:${var.vpc_region}:${data.aws_caller_identity.current.account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
                "arn:aws:codedeploy:${var.vpc_region}:${data.aws_caller_identity.current.account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
            ]
        }
    ]
})
}

#-------------------------------------------------------------------------------------#
# Policy allows EC2 instances to publish to SNS topics
resource "aws_iam_policy" "Publish_to_SNS" {
  name        = "EC2-Publish-to-SNS"
  description = "Permissions for EC2 instances to publish messages to SNS."

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode( {
  "Version": "2012-10-17",
  "Statement": [
    {
    "Sid":"AllowPublishToMyTopic",
    "Effect":"Allow",
    "Action":"sns:Publish",
    "Resource": [
      aws_sns_topic.book_create.arn,
      aws_sns_topic.book_delete.arn,
    ]
  }
  ]
})
}

#-------------------------------------------------------------------------------------#
# create IAM User

resource "aws_iam_user" "ghactions" {
  name = "ghactions"
  path = "/"
}

#-------------------------------------------------------------------------------------#
# attach IAM Policies for IAM User
resource "aws_iam_user_policy_attachment" "ghaction_S3" {
  user       = aws_iam_user.ghactions.name
  policy_arn = aws_iam_policy.GH_Upload_To_S3.arn
}

resource "aws_iam_user_policy_attachment" "ghaction_CodeDeploy" {
  user       = aws_iam_user.ghactions.name
  policy_arn = aws_iam_policy.GH_Code_Deploy.arn
}

#-------------------------------------------------------------------------------------#
# create IAM Role for EC2 instances which serve web application
resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeploy-EC2-Service-Role"
  description = "for EC2 instances that will be used to host your web application."
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

#-------------------------------------------------------------------------------------#
# attach CodeDeployEC2ServiceRole and policies
resource "aws_iam_role_policy_attachment" "CodeDeployEC2Policy_S3_Object_Attach" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.webapp_s3_policy.arn
}

resource "aws_iam_role_policy_attachment" "CodeDeployEC2RolePolicy_Attach" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.CodeDeploy_EC2_S3.arn
}

resource "aws_iam_role_policy_attachment" "CloudWatchAgent_Attach" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "SNS" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.Publish_to_SNS.arn
}

#-------------------------------------------------------------------------------------#
# create CodeDeployServiceRole IAM Role
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"
  description = "Allows CodeDeploy to call AWS services such as Auto Scaling on your behalf"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "codedeploy.amazonaws.com"
        }
      },
    ]
  })
}

#-------------------------------------------------------------------------------------#
# attach CodeDeployServiceRole and policy
resource "aws_iam_role_policy_attachment" "CodeDeployRolePolicy_Attach" {
  role       = aws_iam_role.CodeDeployServiceRole.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}

#-------------------------------------------------------------------------------------#
# create CodeDeployServiceRoleLambda IAM Role
resource "aws_iam_role" "CodeDeployServiceRoleLambda" {
  name = "CodeDeployServiceRoleLambda"
  description = "Allows CodeDeploy to call AWS services such as Auto Scaling on your behalf"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "codedeploy.amazonaws.com"
        }
      },
    ]
  })
}

#-------------------------------------------------------------------------------------#
# attach CodeDeployServiceRoleLambda and policy
resource "aws_iam_role_policy_attachment" "CodeDeployRoleLambdaPolicy_Attach" {
  role       = aws_iam_role.CodeDeployServiceRoleLambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"
}

resource "aws_iam_role_policy_attachment" "CodeDeployRoleLambdaPolicyS3_Attach" {
  role       = aws_iam_role.CodeDeployServiceRoleLambda.name
  policy_arn = aws_iam_policy.CodeDeploy_EC2_S3.arn
}

#-------------------------------------------------------------------------------------#
# CodeDepoly Application for EC2 Web Application
resource "aws_codedeploy_app" "webapp" {
  compute_platform = "Server"
  name             = "webapp"
}

#-------------------------------------------------------------------------------------#
# CodeDeploy deployment group for updating web application
resource "aws_codedeploy_deployment_group" "webapp_deployment" {
  app_name              = aws_codedeploy_app.webapp.name
  deployment_config_name = "CodeDeployDefault.OneAtATime"
  deployment_group_name = "webapp-deployment"
  service_role_arn      = aws_iam_role.CodeDeployServiceRole.arn

  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type = "IN_PLACE"
  }

  load_balancer_info {
      target_group_info {
        name = aws_lb_target_group.target_group.name
      }
  }
  
  autoscaling_groups = [aws_autoscaling_group.asg.name]

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}

#-------------------------------------------------------------------------------------#
# CodeDepoly Application for lambda function
resource "aws_codedeploy_app" "webapp_lambda" {
  compute_platform = "Lambda"
  name             = "codedeploy-webapp-lambda"
}

#-------------------------------------------------------------------------------------#
# CodeDeploy deployment group for lambda function
resource "aws_codedeploy_deployment_group" "webapp_lambda_deployment" {
  app_name              = aws_codedeploy_app.webapp_lambda.name
  deployment_config_name = "CodeDeployDefault.LambdaAllAtOnce"
  deployment_group_name = "webapp-lambda-deployment"
  service_role_arn      = aws_iam_role.CodeDeployServiceRoleLambda.arn

    deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type = "BLUE_GREEN"
  }
}

#-------------------------------------------------------------------------------------#
# Application security group
# Only allows ingress from load balancer
resource "aws_security_group" "application" {
  name        = "WebApplicationSecurityGroup"
  description = "WebApplicationSecurityGroup"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    description = "For Health Checks from Load Balancer."
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = [aws_security_group.loadBalancer.id]
  }

  ingress {
    description = "Listener for Load Balancer."
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    security_groups = [aws_security_group.loadBalancer.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#-------------------------------------------------------------------------------------#
# Database security group, only enable web application security group to send request.
# Default egress is anywhere
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

#-------------------------------------------------------------------------------------#
# Load balancer security group, enable HTTPS port to secure connections to load balancer
# Two more rules are wrote as "aws_security_group_rule"
resource "aws_security_group" "loadBalancer" {
  name        = "LBSecurityGroup"
  description = "EC2 security group for load balancer."
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    description = "Allow access from anywhere."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#-------------------------------------------------------------------------------------#
# Add security group rule for load balancer security group to enable webapp port
# Use this resouce since the security rule references each other
resource "aws_security_group_rule" "webapp" {
  description = "To Instance Listener."
  type              = "egress"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  source_security_group_id = aws_security_group.application.id
  security_group_id = aws_security_group.loadBalancer.id
}

#-------------------------------------------------------------------------------------#
# Add security group rule for load balancer security group to enable health check port
# Use this resouce since the security rule references each other
resource "aws_security_group_rule" "health_check" {
  description = "To Instance Health Checks."
  type              = "egress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  source_security_group_id = aws_security_group.application.id
  security_group_id = aws_security_group.loadBalancer.id
}

#-------------------------------------------------------------------------------------#
# S3 bucket for image object storing
resource "aws_s3_bucket" "object" {
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

#-------------------------------------------------------------------------------------#
# db subnet group
resource "aws_db_subnet_group" "default" {
  name       = "main"
  subnet_ids = [aws_subnet.subnet01.id, aws_subnet.subnet02.id, aws_subnet.subnet03.id]

  tags = {
    Name = "My DB subnet group"
  }
}

#-------------------------------------------------------------------------------------#
# Instance Profile from the EC2 Service Role
resource "aws_iam_instance_profile" "app_profile" {
  name = "app_iam_ec2_profile"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}

#-------------------------------------------------------------------------------------#
# New Customer Managed Key for EBS
# Policy of this KMS key is customzied to let autoscaling service role has permissions to use this key.
resource "aws_kms_key" "ebs" {
  description             = "KMS key for EBS volume"
  deletion_window_in_days = 10
  policy = jsonencode( 
    {
    "Version": "2012-10-17",
    "Id": "key-default-1",
    "Statement": [
       {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": [data.aws_caller_identity.current.user_id, "arn:aws:iam::${data.aws_caller_identity.current.user_id}:root"],
            },
            "Action": [
                      "kms:Create*",
                      "kms:Describe*",
                      "kms:Enable*",
                      "kms:List*",
                      "kms:Put*",
                      "kms:Update*",
                      "kms:Revoke*",
                      "kms:Disable*",
                      "kms:Get*",
                      "kms:Delete*",
                      "kms:ScheduleKeyDeletion",
                      "kms:CancelKeyDeletion"
                  ],
            "Resource": "*"
        },
      {
        "Sid": "Allow service-linked role use of the CMK",
        "Effect": "Allow",
        "Principal": {
            "AWS": [
                "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            ]
        },
        "Action": [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:DescribeKey"
        ],
        "Resource": "*"
      },
      {
        "Sid": "Allow attachment of persistent resources",
        "Effect": "Allow",
        "Principal": {
            "AWS": [
                "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            ]
        },
        "Action": [
            "kms:CreateGrant"
        ],
        "Resource": "*",
        "Condition": {
            "Bool": {
                "kms:GrantIsForAWSResource": true
            }
          }
      }
    ]
    }
)
}

#-------------------------------------------------------------------------------------#
# Use the new customer managed key for ebs as default key for new ebs which enables encryption
resource "aws_ebs_default_kms_key" "example" {
  key_arn = aws_kms_key.ebs.arn
}

#-------------------------------------------------------------------------------------#
# New Customer Managed Key for RDS
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS volum"
  deletion_window_in_days = 10
}

# -------------------------------------------------------------------------------------- #
# RDS instance, db.t2.micro is the free tire db instance but it doesn't support kms encryption
resource "aws_db_instance" "db_instance" {
  allocated_storage    = var.rds_db_instance.allocated_storage
  engine               = var.rds_db_instance.engine
  engine_version       = var.rds_db_instance.engine_version
  instance_class       = var.rds_db_instance.identifier
  identifier           = var.rds_db_instance.identifier
  name                 = var.rds_db_instance.name
  username             = var.rds_db_instance.usename
  password             = var.db_password
  multi_az             = false
  publicly_accessible  = false
  skip_final_snapshot  = true
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name = aws_db_subnet_group.default.name
  kms_key_id           = aws_kms_key.rds.arn
  storage_encrypted    = var.rds_db_instance.encrypt_option
}

#-------------------------------------------------------------------------------------#
# Route 53 A Record for Web Application Instances Load Balancer
resource "aws_route53_record" "webapp" {
  zone_id = var.run_profile == "prod" ? var.route53_record.prod: var.route53_record.dev
  name    = "${var.run_profile}.chuhsin.me"
  type    = "A"

  alias {
    name                   = aws_lb.load_balancer.dns_name
    zone_id                = aws_lb.load_balancer.zone_id
    evaluate_target_health = true
  }
}

#-------------------------------------------------------------------------------------#
# Launch Configuration for Autoscaling Group Use
# UserData is used to configure database and SNS module of application
resource "aws_launch_configuration" "as_conf" {
  name   = "TR-LC"
  image_id      = var.ami
  instance_type = "t2.micro"
  security_groups = [aws_security_group.application.id]
  iam_instance_profile = aws_iam_instance_profile.app_profile.id
  key_name = "csye6225_2021spring"
  user_data =  <<EOF
#!/bin/bash
echo "Hello World" >> /home/ubuntu/testfile.txt
echo RDS_HOSTNAME=${aws_db_instance.db_instance.address} >> /etc/environment
echo RDS_USERNAME=${aws_db_instance.db_instance.username} >> /etc/environment
echo RDS_PASSWORD=${var.db_password} >> /etc/environment
echo RDS_DATABASE=${aws_db_instance.db_instance.name} >> /etc/environment
echo RDS_PORT=${aws_db_instance.db_instance.port} >> /etc/environment
echo BUCKET_NAME=${aws_s3_bucket.object.id} >> /etc/environment
echo TOPIC_DELETE=${aws_sns_topic.book_delete.arn} >> /etc/environment
echo TOPIC_CREATE=${aws_sns_topic.book_create.arn} >> /etc/environment
echo run_profile=${var.run_profile} >> /etc/environment
  EOF

  lifecycle {
    create_before_destroy = true
  }
  
  root_block_device {
    volume_type = "gp2"
    volume_size = 8
    encrypted = true
  }
}

#-------------------------------------------------------------------------------------#
# Auto Scaling Groups 
resource "aws_autoscaling_group" "asg" {
  name                 = "TR-ASG"
  launch_configuration = aws_launch_configuration.as_conf.name
  min_size             = 3
  max_size             = 5
  desired_capacity     = 3
  health_check_grace_period = 500
  default_cooldown = 500
  health_check_type         = "EC2"
  vpc_zone_identifier = [aws_subnet.subnet01.id, aws_subnet.subnet02.id, aws_subnet.subnet03.id]
  target_group_arns = [aws_lb_target_group.target_group.arn]

  tag {
    key                 = "autoscaling"
    value               = "true"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

#-------------------------------------------------------------------------------------#
# Autoscaling Group Scale Down policy and alarm
resource "aws_autoscaling_policy" "web_policy_down" {
  name = "web_policy_down"
  scaling_adjustment = -1
  adjustment_type = "ChangeInCapacity"
  cooldown = 600
  autoscaling_group_name = aws_autoscaling_group.asg.name
}

resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_down" {
  alarm_name = "web_cpu_alarm_down"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods = "5"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "120"
  statistic = "Average"
  threshold = "3"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }

  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = [ aws_autoscaling_policy.web_policy_down.arn ]
}

#-------------------------------------------------------------------------------------#
# Autoscaling Group Scale Up policy and alarm
resource "aws_autoscaling_policy" "web_policy_up" {
  name = "web_policy_up"
  scaling_adjustment = 1
  adjustment_type = "ChangeInCapacity"
  cooldown = 500
  autoscaling_group_name = aws_autoscaling_group.asg.name
}

resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_up" {
  alarm_name = "web_cpu_alarm_up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "3"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "120"
  statistic = "Average"
  threshold = "5"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }

  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = [ aws_autoscaling_policy.web_policy_up.arn ]
}

#-------------------------------------------------------------------------------------#
# Targets Group
resource "aws_lb_target_group" "target_group" {
  name     = "TF-TG"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.my_vpc.id
  deregistration_delay = 30
  health_check {
    interval = 10
    healthy_threshold = 2
  }
}

#-------------------------------------------------------------------------------------#
# Load Balancer
resource "aws_lb" "load_balancer" {
  name               = "TF-LB"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.loadBalancer.id]
  subnets            = [aws_subnet.subnet01.id, aws_subnet.subnet02.id, aws_subnet.subnet03.id]

  tags = {
    Environment = "production"
  }
}

#-------------------------------------------------------------------------------------#
# Load Balancer Listener Foward to Targets Group
resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.load_balancer.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn = var.run_profile == "prod" ? "arn:aws:acm:us-west-2:798539279327:certificate/45890e31-7c1e-478f-a993-f04b34730544": "arn:aws:acm:us-west-2:973459261718:certificate/c9b6ae4b-c35d-4a37-9428-dba10d09d73c"


  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target_group.arn
  }
}

#-------------------------------------------------------------------------------------#
# Attach ALB Target Group to the Autoscaling Group
resource "aws_autoscaling_attachment" "asg_attachment_bar" {
  autoscaling_group_name = aws_autoscaling_group.asg.id
  alb_target_group_arn   = aws_lb_target_group.target_group.arn
}

#-------------------------------------------------------------------------------------#
# IAM role for lambda function
resource "aws_iam_role" "iam_for_lambda" {
  name = "IAM_ROLE_FOR_Lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}

#-------------------------------------------------------------------------------------#
# Permission for Lambda Function to Create Logs and send emails through SES
resource "aws_iam_policy" "lambda_log_policy" {
  name        = "Lambda-Log-Policy"
  description = "Permission for Lambda Function to Create Logs"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            "Resource": "*"
        }
    ]
})
}

#-------------------------------------------------------------------------------------#
# log policy to allow lambda function to log on CloudWatch logging
resource "aws_iam_role_policy_attachment" "lambda" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_log_policy.arn
}

#-------------------------------------------------------------------------------------#
# attach DynamoDB Access policy to lambda role for lambda function
resource "aws_iam_role_policy_attachment" "lambda_dynamoDB" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

#-------------------------------------------------------------------------------------#
# Lambda Function
resource "aws_lambda_function" "lambda_function" {
  filename = data.archive_file.dummy.output_path
  function_name = "lambda_sns_function"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"
  publish       = true
  runtime = "nodejs14.x"

  environment {
    variables = {
      ACCOUNT = var.run_profile
    }
  }
}

#-------------------------------------------------------------------------------------#
# Lambda Alias point to the lambda functino version, imported this for Lambda function CD with CodeDeploy
resource "aws_lambda_alias" "lambda_alias" {
  name             = "my_alias"
  description      = "a sample description"
  function_name    = aws_lambda_function.lambda_function.arn
  function_version = aws_lambda_function.lambda_function.version

}

#-------------------------------------------------------------------------------------#
# SNS topics
resource "aws_sns_topic" "book_create" {
  name = "book-created"
}

resource "aws_sns_topic" "book_delete" {
  name = "book-deleted"
}

#-------------------------------------------------------------------------------------#
# subscription of SNS topic from lambda function
resource "aws_sns_topic_subscription" "book_created_lambda_target" {
  topic_arn = aws_sns_topic.book_create.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_alias.lambda_alias.arn
}

resource "aws_sns_topic_subscription" "book_deleted_lambda_target" {
  topic_arn = aws_sns_topic.book_delete.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_alias.lambda_alias.arn
}

#-------------------------------------------------------------------------------------#
# permission to allow SNS service invoke lambda function
resource "aws_lambda_permission" "with_sns_create" {
  statement_id  = "AllowExecutionFromSNSCreate"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_alias.lambda_alias.arn
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.book_create.arn
}

resource "aws_lambda_permission" "with_sns_delete" {
  statement_id  = "AllowExecutionFromSNSDelete"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_alias.lambda_alias.arn
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.book_delete.arn
}

#-------------------------------------------------------------------------------------#
# DynamoDB table, to store the message id to prevent duplicate emails been sent to users
resource "aws_dynamodb_table" "basic-dynamodb-table" {
  name           = "messages"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "MessageID"

  attribute {
    name = "MessageID"
    type = "S"
  }

  tags = {
    Name        = "dynamodb-table-1"
    Environment = "production"
  }
}
#-------------------------------------------------------------------------------------#

# EC2 instance
# This is a EC2 instance template to serve web application, the using launch configuration is based on this resource

# resource "aws_instance" "webapp" {
#   ami           = var.ami
#   instance_type = "t2.micro"
#   key_name = "csye6225_2021spring"
#   vpc_security_group_ids = [aws_security_group.application.id]
#   iam_instance_profile = aws_iam_instance_profile.app_profile.id
#   subnet_id = aws_subnet.subnet01.id
#   root_block_device {
#     volume_size = 20
#     volume_type = "gp2"
#     delete_on_termination = true
#   }

#   tags = {
#     Name = "EC2-WebApplication"
#     env = "codedeploy"
#   }

#   user_data =  <<EOF
# Content-Type: multipart/mixed; boundary="//"
# MIME-Version: 1.0
# --//
# Content-Type: text/cloud-config; charset="us-ascii"
# MIME-Version: 1.0
# Content-Transfer-Encoding: 7bit
# Content-Disposition: attachment; filename="cloud-config.txt"
# #cloud-config
# cloud_final_modules:
# - [scripts-user, always]
# --//
# Content-Type: text/x-shellscript; charset="us-ascii"
# MIME-Version: 1.0
# Content-Transfer-Encoding: 7bit
# Content-Disposition: attachment; filename="userdata.txt"
# #!/bin/bash
# /bin/echo "Hello World" >> /home/ubuntu/testfile.txt
# /bin/echo RDS_HOSTNAME=${aws_db_instance.db_instance.address} >> /etc/environment
# /bin/echo RDS_USERNAME=${aws_db_instance.db_instance.username} >> /etc/environment
# /bin/echo RDS_PASSWORD=${var.db_password} >> /etc/environment
# /bin/echo RDS_DATABASE=${aws_db_instance.db_instance.name} >> /etc/environment
# /bin/echo RDS_PORT=${aws_db_instance.db_instance.port} >> /etc/environment
# /bin/echo BUCKET_NAME=${aws_s3_bucket.object.id} >> /etc/environment
# --//
# EOF
# }