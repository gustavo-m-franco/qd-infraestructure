# TODO: change qd.api.gateway to qd-api-gateway.net in reasources values
provider "aws" {
  region = "eu-west-1"
}

variable "environment_name" {
  description = "The name of the environment (dev, staging, prod)"
  type        = string
}

variable "version_name" {
  description = "The version of the infrastructure"
  type        = string
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
}

variable "public_subnet_cidrs" {
  description = "List of CIDR blocks for the public subnets"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "List of CIDR blocks for the private subnets"
  type        = list(string)
}

locals {
  environment_domain_suffix = var.environment_name == "prod" ? "" : ".${var.environment_name}"
  environment_domain_prefix = var.environment_name == "prod" ? "" : "${var.environment_name}."
  environment_suffix = var.environment_name == "prod" ? "" : "-${var.environment_name}"
}

# VPC definition
resource "aws_vpc" "qd_vpc" {
  cidr_block = var.vpc_cidr
  enable_dns_support = true
  enable_dns_hostnames = true
  tags = {
    Name = "QuaDevVPC${local.environment_suffix}"
  }
}

# Internet Gateway definition
resource "aws_internet_gateway" "qd_gateway" {
  vpc_id = aws_vpc.qd_vpc.id

  tags = {
    Name = "QuaDevGateway"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "public_subnet" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.qd_vpc.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  tags = {
    Name = "PublicSubnet-${count.index}"
  }
}


resource "aws_subnet" "private_subnet" {
  count                   = length(var.private_subnet_cidrs)
  vpc_id                  = aws_vpc.qd_vpc.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  tags = {
    Name = "PrivateSubnet-${count.index}"
  }
}

# Route Table definition for public subnet
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.qd_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.qd_gateway.id
  }

  tags = {
    Name = "PublicRouteTable"
  }
}

resource "aws_route_table_association" "public_subnet_association" {
  count          = length(aws_subnet.public_subnet.*.id)
  subnet_id      = aws_subnet.public_subnet[count.index].id
  route_table_id = aws_route_table.public_route_table.id
}


# NAT Gateway definition for private subnet
resource "aws_eip" "nat_eip" {
  domain = "vpc"
}

resource "aws_nat_gateway" "qd_nat_gateway" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet[0].id

  tags = {
    Name = "QuaDevNatGateway"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.qd_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.qd_nat_gateway.id
  }

  tags = {
    Name = "PrivateRouteTable"
  }
}

resource "aws_route_table_association" "private_subnet_association" {
  count          = length(aws_subnet.private_subnet.*.id)
  subnet_id      = aws_subnet.private_subnet[count.index].id
  route_table_id = aws_route_table.private_route_table.id
}

# Security Groups definition
resource "aws_security_group" "public_sg" {
  vpc_id = aws_vpc.qd_vpc.id

  # Allows all outbound traffic 
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allows only inbound HTTPS traffic on port 443
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allows only inbound HTTP traffic on port 80 
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "PublicSecurityGroup"
  }
}

resource "aws_security_group" "private_sg" {
  vpc_id = aws_vpc.qd_vpc.id

  # Allows all outbound traffic   
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allows only inbound traffic from the public security group on port 80
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.public_sg.id]
  }

  tags = {
    Name = "PrivateSecurityGroup"
  }
}


#  Create ECR repositories
# resource "aws_ecr_repository" "qd_authentication_api_microservice_ecr" {
#   name                 = "${local.environment_domain_prefix}qd.authentication.api"
#   image_tag_mutability = "MUTABLE"

#   image_scanning_configuration {
#     scan_on_push = true
#   }

#   tags = {
#     Environment = "development"
#   }
# }

# resource "aws_ecr_repository" "qd_email_api_microservice_ecr" {
#   name                 = "${local.environment_domain_prefix}qd.email.api"
#   image_tag_mutability = "MUTABLE"

#   image_scanning_configuration {
#     scan_on_push = true
#   }

#   tags = {
#     Environment = "development"
#   }
# }

# resource "aws_ecr_repository" "qd_api_gateway_microservice_ecr" {
#   name                 = "${local.environment_domain_prefix}qd.api.gateway"
#   image_tag_mutability = "MUTABLE"

#   image_scanning_configuration {
#     scan_on_push = true
#   }

#   tags = {
#     Environment = "development"
#   }
# }

# ECS Cluster definition
resource "aws_ecs_cluster" "qd_cluster" {
  name = "qd-cluster-${local.environment_suffix}"
}

# EC2 launch configuration definition
data "aws_ssm_parameter" "ecs_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"
}

resource "aws_iam_role" "ecs_instance_role" {
  name = "ecsInstanceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_role_policy_attachment" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "ecs_instance_profile" {
  name = "ecs-instance-profile"
  role = aws_iam_role.ecs_instance_role.name
}

resource "aws_launch_configuration" "ecs_launch_private_configuration" {
  name          = "ecs-launch-private-configuration${local.environment_suffix}"
  image_id      = data.aws_ssm_parameter.ecs_ami.value
  instance_type = "t3.medium" # Adjust based on your needs

  # Associate with the ECS instance role that grants permissions for ECS
  iam_instance_profile = aws_iam_instance_profile.ecs_instance_profile.name

  security_groups = [aws_security_group.private_sg.id] # Adjust if you have a specific SG for ECS instances

  user_data = <<-EOF
              #!/bin/bash
              echo ECS_CLUSTER=${aws_ecs_cluster.qd_cluster.name} >> /etc/ecs/ecs.config
              EOF

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "ecs_private_autoscaling_group" {
  launch_configuration = aws_launch_configuration.ecs_launch_private_configuration.id
  min_size             = 1
  max_size             = 3
  desired_capacity     = 2
  vpc_zone_identifier  = aws_subnet.private_subnet.*.id

  tag {
    key                 = "Name"
    value               = "ecs-instance${local.environment_suffix}"
    propagate_at_launch = true
  }
}

resource "aws_launch_configuration" "ecs_launch_public_configuration" {
  name          = "ecs-launch-public-configuration${local.environment_suffix}"
  image_id      = data.aws_ssm_parameter.ecs_ami.value
  instance_type = "t3.medium" # Adjust based on your needs

  # Associate with the ECS instance role that grants permissions for ECS
  iam_instance_profile = aws_iam_instance_profile.ecs_instance_profile.name

  security_groups = [aws_security_group.public_sg.id] # Adjust if you have a specific SG for ECS instances

  user_data = <<-EOF
              #!/bin/bash
              echo ECS_CLUSTER=${aws_ecs_cluster.qd_cluster.name} >> /etc/ecs/ecs.config
              EOF

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "ecs_public_autoscaling_group" {
  launch_configuration = aws_launch_configuration.ecs_launch_public_configuration.id
  min_size             = 1
  max_size             = 3
  desired_capacity     = 2
  vpc_zone_identifier  = aws_subnet.public_subnet.*.id

  tag {
    key                 = "Name"
    value               = "ecs-instance${local.environment_suffix}"
    propagate_at_launch = true
  }
}

# ECS execution tasks definitions
resource "aws_iam_role" "ecs_tasks_execution_role" {
  name = "ecs_tasks_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        },
      },
    ],
  })
}

resource "aws_iam_role_policy_attachment" "ecs_tasks_execution_role_policy" {
  role       = aws_iam_role.ecs_tasks_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}


resource "aws_ecs_task_definition" "qd_authentication_api_microservice_ecs_task" {
  family                = "qd-authentication-api"
  network_mode          = "awsvpc"
  requires_compatibilities = ["EC2"]
  execution_role_arn       = aws_iam_role.ecs_tasks_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = "qd-authentication-api"
      image     = "116203835544.dkr.ecr.eu-west-1.amazonaws.com/qd.authentication.api${local.environment_domain_suffix}:${var.version_name}"
      cpu       = 256
      memory    = 512
      essential = true
      portMappings = [
        {
          containerPort = 443
          hostPort      = 443
        }
      ]
    }
  ])
}


resource "aws_ecs_task_definition" "qd_email_api_microservice_ecs_task" {
  family                = "qd-email-api"
  network_mode          = "awsvpc"
  requires_compatibilities = ["EC2"]
  execution_role_arn       = aws_iam_role.ecs_tasks_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = "qd-email-api"
      image     = "116203835544.dkr.ecr.eu-west-1.amazonaws.com/qd.email.api${local.environment_domain_suffix}:${var.version_name}"
      cpu       = 256
      memory    = 512
      essential = true
      portMappings = [
        {
          containerPort = 443
          hostPort      = 443
        }
      ]
    }
  ])
}

resource "aws_ecs_task_definition" "qd_api_gateway_microservice_ecs_task" {
  family                = "qd-api-gateway"
  network_mode          = "awsvpc"
  requires_compatibilities = ["EC2"]
  execution_role_arn       = aws_iam_role.ecs_tasks_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = "qd-api-gateway"
      image     = "116203835544.dkr.ecr.eu-west-1.amazonaws.com/qd.api.gateway${local.environment_domain_suffix}:${var.version_name}"
      cpu       = 256
      memory    = 512
      essential = true
      portMappings = [
        {
          containerPort = 443
          hostPort      = 443
        }
      ]
    }
  ])
}

# TODO: add environment variables to the discovery vars
# Internal DNS service mapping (private subnet)
resource "aws_service_discovery_private_dns_namespace" "qd_private_dns" {
  name        = "internal.dns"
  vpc         = aws_vpc.qd_vpc.id
  description = "Internal namespace for QD services"
}

resource "aws_service_discovery_service" "discovery_qd_authentication_api" {
  name = "discovery.qd.authentication.api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.qd_private_dns.id

    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "discovery_qd_email_api" {
  name = "discovery.qd.email.api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.qd_private_dns.id

    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

# ECS services definition
resource "aws_ecs_service" "qd_authentication_api_service" {
  name            = "qd-authentication-api-service${local.environment_suffix}"
  cluster         = aws_ecs_cluster.qd_cluster.id
  task_definition = aws_ecs_task_definition.qd_authentication_api_microservice_ecs_task.arn
  desired_count   = 2
  launch_type     = "EC2"

  network_configuration {
    subnets          = aws_subnet.private_subnet.*.id
    security_groups  = [aws_security_group.private_sg.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn   = aws_service_discovery_service.discovery_qd_authentication_api.arn
    container_name = "discovery.qd.authentication.api"
  }

  depends_on = [aws_autoscaling_group.ecs_private_autoscaling_group]
}

resource "aws_ecs_service" "qd_email_api_service" {
  name            = "qd-email-api-service${local.environment_suffix}"
  cluster         = aws_ecs_cluster.qd_cluster.id
  task_definition = aws_ecs_task_definition.qd_email_api_microservice_ecs_task.arn
  desired_count   = 2
  launch_type     = "EC2"

  network_configuration {
    subnets          = aws_subnet.private_subnet.*.id
    security_groups  = [aws_security_group.private_sg.id]
    assign_public_ip = false
  }
  
  service_registries {
    registry_arn   = aws_service_discovery_service.discovery_qd_email_api.arn
    container_name = "discovery.qd.email.api"
  }

  depends_on = [aws_autoscaling_group.ecs_private_autoscaling_group]
}

resource "aws_ecs_service" "qd_apigateway_service" {
  name            = "qd-api-gateway-service${local.environment_suffix}"
  cluster         = aws_ecs_cluster.qd_cluster.id
  task_definition = aws_ecs_task_definition.qd_api_gateway_microservice_ecs_task.arn
  desired_count   = 2
  launch_type     = "EC2"

  network_configuration {
    subnets          = aws_subnet.public_subnet.*.id
    security_groups  = [aws_security_group.public_sg.id]
  }

  depends_on = [aws_autoscaling_group.ecs_public_autoscaling_group]
}

# Load Balancers definition
resource "aws_lb" "qd_alb" {
  name               = "qd-alb${local.environment_suffix}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.public_sg.id]
  subnets            = aws_subnet.public_subnet.*.id

  tags = {
    Name = "QuaDevALB${local.environment_suffix}"
  }
}

resource "aws_lb_target_group" "tg_qd_api_gateway" {
  name     = "tg-qd-api-gateway${local.environment_suffix}"
  port     = 443
  protocol = "HTTP"
  vpc_id   = aws_vpc.qd_vpc.id

  health_check {
    protocol = "HTTP"
    path     = "/health"
    matcher  = "200"
  }
}

resource "aws_lb_listener" "frontend_http" {
  load_balancer_arn = aws_lb.qd_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_acm_certificate" "qd_api_gateway_cert" {
  domain_name               = "${local.environment_domain_prefix}qd-api-gateway.net"
  validation_method         = "DNS"
  subject_alternative_names = []

  tags = {
    Environment = "${var.environment_name}"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "frontend_https" {
  load_balancer_arn = aws_lb.qd_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.qd_api_gateway_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg_qd_api_gateway.arn
  }
}

# Api gateway internet discoverable
resource "aws_route53_zone" "qd_api_gateway_zone" {
  name = "qd-api-gateway.net"
}

resource "aws_route53_record" "qd_api_gateway_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.qd_api_gateway_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  name    = each.value.name
  records = [each.value.record]
  ttl     = 60
  type    = each.value.type
  zone_id = aws_route53_zone.qd_api_gateway_zone.zone_id
}

resource "aws_acm_certificate_validation" "qd_api_gateway_validation" {
  certificate_arn         = aws_acm_certificate.qd_api_gateway_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.qd_api_gateway_cert_validation : record.fqdn]
}

resource "aws_route53_record" "qd_api_gateway_dns" {
  zone_id = aws_route53_zone.qd_api_gateway_zone.id
  name    = "${local.environment_domain_prefix}qd-api-gateway.net"
  type    = "A"

  alias {
    name                   = aws_lb.qd_alb.dns_name
    zone_id                = aws_lb.qd_alb.zone_id
    evaluate_target_health = true
  }
}

