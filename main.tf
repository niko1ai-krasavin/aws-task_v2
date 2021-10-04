terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.59.0"
    }
  }
}

provider "aws" {
  region  = "eu-central-1"
  profile = "default"
}

resource "aws_instance" "nginx_with_teacher_key" {
  ami           = "ami-07df274a488ca9195"
  instance_type = "t2.micro"
  key_name      = "frankfurt-ec2"
  user_data     = file("./nginx-with-teacher-key.sh")
  tags = {
    Name = "Delete me (nginx with teacher key)"
  }
}

resource "aws_ami_from_instance" "ami_nginx" {
  name               = "nginx-with-teacher-key"
  source_instance_id = aws_instance.nginx_with_teacher_key.id
}

resource "aws_vpc" "vpc_1" {
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "vpc-1"
  }
}

resource "aws_vpc" "vpc_2" {
  cidr_block = "10.0.2.0/24"

  tags = {
    Name = "vpc-2"
  }
}

resource "aws_subnet" "pub_1_in_vpc_1" {
  vpc_id                  = aws_vpc.vpc_1.id
  cidr_block              = "10.0.1.0/26"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "pub-1-in-vpc-1 (eu-central-1a)"
  }
}

resource "aws_subnet" "pub_2_in_vpc_1" {
  vpc_id                  = aws_vpc.vpc_1.id
  cidr_block              = "10.0.1.64/26"
  availability_zone       = "eu-central-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "pub-2-in-vpc-1 (eu-central-1a)"
  }
}

resource "aws_subnet" "priv_1_in_vpc_1" {
  vpc_id            = aws_vpc.vpc_1.id
  cidr_block        = "10.0.1.128/26"
  availability_zone = "eu-central-1a"

  tags = {
    Name = "priv-1-in-vpc_1 (eu-central-1a)"
  }
}

resource "aws_subnet" "priv_2_in_vpc_1" {
  vpc_id            = aws_vpc.vpc_1.id
  cidr_block        = "10.0.1.192/26"
  availability_zone = "eu-central-1b"

  tags = {
    Name = "priv-2-in-vpc_1 (eu-central-1b)"
  }
}

resource "aws_subnet" "pub_in_vpc_2" {
  vpc_id                  = aws_vpc.vpc_2.id
  cidr_block              = "10.0.2.0/25"
  availability_zone       = "eu-central-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "pub-in-vpc-2 (eu-central-1b)"
  }
}

resource "aws_subnet" "priv_in_vpc_2" {
  vpc_id            = aws_vpc.vpc_2.id
  cidr_block        = "10.0.2.128/25"
  availability_zone = "eu-central-1b"

  tags = {
    Name = "priv-in-vpc_2 (eu-central-1b)"
  }
}

resource "aws_internet_gateway" "ig_for_vpc_1" {
  vpc_id = aws_vpc.vpc_1.id

  tags = {
    Name = "ig-for-vpc-1"
  }
}

resource "aws_internet_gateway" "ig_for_vpc_2" {
  vpc_id = aws_vpc.vpc_2.id

  tags = {
    Name = "ig-for-vpc-2"
  }
}

resource "aws_vpc_peering_connection" "peering_vpc1_vpc2" {
  peer_vpc_id = aws_vpc.vpc_1.id
  vpc_id      = aws_vpc.vpc_2.id
  auto_accept = true

  tags = {
    Name = "VPC Peering between VPC-1 and VPC-2"
  }
}

resource "aws_route_table" "rt_for_pub_subnets_in_vpc_1" {
  vpc_id = aws_vpc.vpc_1.id

  route {
    cidr_block                = aws_vpc.vpc_2.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.peering_vpc1_vpc2.id
  }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ig_for_vpc_1.id
  }

  tags = {
    Name = "rt-for-pub-subnets-in-vpc-1"
  }
}

resource "aws_route_table" "rt_for_pub_subnet_in_vpc_2" {
  vpc_id = aws_vpc.vpc_2.id

  route {
    cidr_block                = aws_vpc.vpc_1.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.peering_vpc1_vpc2.id
  }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ig_for_vpc_2.id
  }

  tags = {
    Name = "rt-for-pub-subnet-in-vpc-2"
  }
}

resource "aws_route_table_association" "rt_ass_for_pub_1_subnet_in_vpc_1" {
  subnet_id      = aws_subnet.pub_1_in_vpc_1.id
  route_table_id = aws_route_table.rt_for_pub_subnets_in_vpc_1.id
}

resource "aws_route_table_association" "rt_ass_for_pub_2_subnet_in_vpc_1" {
  subnet_id      = aws_subnet.pub_2_in_vpc_1.id
  route_table_id = aws_route_table.rt_for_pub_subnets_in_vpc_1.id
}

resource "aws_route_table_association" "rt_ass_for_pub_subnet_in_vpc_2" {
  subnet_id      = aws_subnet.pub_in_vpc_2.id
  route_table_id = aws_route_table.rt_for_pub_subnet_in_vpc_2.id
}

/*
resource "aws_eip" "eip_for_gw_nat" {
  vpc = true
}

resource "aws_nat_gateway" "gw_nat_for_vpc_1" {
  allocation_id = aws_eip.eip_for_gw_nat.id
  subnet_id     = aws_subnet.pub_in_vpc_1.id

  tags = {
    Name = "NAT-gw-in-vpc-1"
  }

  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.ig_for_vpc_1]
}

resource "aws_nat_gateway" "gw_nat_for_vpc_2" {
  allocation_id = aws_eip.eip_for_gw_nat.id
  subnet_id     = aws_subnet.pub_in_vpc_2.id

  tags = {
    Name = "NAT-gw-in-vpc-2"
  }

  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.ig_for_vpc_2]
}
*/

resource "aws_route_table" "rt_for_priv_subnets_in_vpc_1" {
  vpc_id = aws_vpc.vpc_1.id

  route {
    cidr_block                = aws_vpc.vpc_2.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.peering_vpc1_vpc2.id
  }
  /*
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.gw_nat_for_vpc_1.id
  }
  */

  tags = {
    Name = "rt-for-pub-subnets-in-vpc-1"
  }
}

resource "aws_route_table" "rt_for_priv_subnet_in_vpc_2" {
  vpc_id = aws_vpc.vpc_2.id

  route {
    cidr_block                = aws_vpc.vpc_1.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.peering_vpc1_vpc2.id
  }
  /*
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.gw_nat_for_vpc_2.id
  }
  */

  tags = {
    Name = "rt-for-pub-subnet-in-vpc-2"
  }
}

resource "aws_route_table_association" "rt_ass_for_priv_1_subnet_in_vpc_1" {
  subnet_id      = aws_subnet.priv_1_in_vpc_1.id
  route_table_id = aws_route_table.rt_for_priv_subnets_in_vpc_1.id
}

resource "aws_route_table_association" "rt_ass_for_priv_2_subnet_in_vpc_1" {
  subnet_id      = aws_subnet.priv_2_in_vpc_1.id
  route_table_id = aws_route_table.rt_for_priv_subnets_in_vpc_1.id
}

resource "aws_route_table_association" "rt_ass_for_priv_subnet_in_vpc_2" {
  subnet_id      = aws_subnet.priv_in_vpc_2.id
  route_table_id = aws_route_table.rt_for_priv_subnet_in_vpc_2.id
}

resource "aws_security_group" "sg_for_bastion_in_vpc_2" {
  name        = "sg_for_bastion_in_vpc_2_host"
  description = "Allow SSH access to bastion host"
  vpc_id      = aws_vpc.vpc_2.id

  ingress {
    description = "SSH access from anywhere"
    from_port   = 22
    to_port     = 22
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

resource "aws_security_group" "sg_for_nginx_in_vpc_1" {
  name        = "sg_for_nginx_in_vpc_1"
  description = "Allow 80, 22 port inbound traffic"
  vpc_id      = aws_vpc.vpc_1.id

  ingress {
    description = "icmp"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    /*
    cidr_blocks = [
      aws_subnet.pub_1_in_vpc_1.cidr_block,
      aws_subnet.pub_2_in_vpc_1.cidr_block,
      aws_subnet.pub_in_vpc_2.cidr_block
    ]
    */
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP access"
    from_port   = 8888
    to_port     = 8888
    protocol    = "tcp"
    /*
    cidr_blocks = [
      aws_subnet.pub_1_in_vpc_1.cidr_block,
      aws_subnet.pub_2_in_vpc_1.cidr_block,
      aws_subnet.pub_in_vpc_2.cidr_block
    ]
    */
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    /*
    cidr_blocks = [
      aws_subnet.pub_1_in_vpc_1.cidr_block,
      aws_subnet.pub_2_in_vpc_1.cidr_block,
      aws_subnet.pub_in_vpc_2.cidr_block
    ]
    */
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "sg_for_nginx_in_vpc_2" {
  name        = "sg_for_nginx_in_vpc_2"
  description = "Allow 80, 22 port inbound traffic"
  vpc_id      = aws_vpc.vpc_2.id

  ingress {
    description = "icmp"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    /*
    cidr_blocks = [
      aws_subnet.pub_in_vpc_2.cidr_block,
      aws_subnet.pub_1_in_vpc_1.cidr_block,
      aws_subnet.pub_2_in_vpc_1.cidr_block
    ]
    */
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP access"
    from_port   = 8888
    to_port     = 8888
    protocol    = "tcp"
    /*
    cidr_blocks = [
      aws_subnet.pub_in_vpc_2.cidr_block,
      aws_subnet.pub_1_in_vpc_1.cidr_block,
      aws_subnet.pub_2_in_vpc_1.cidr_block
    ]
    */
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    /*
    cidr_blocks = [
      aws_subnet.pub_in_vpc_2.cidr_block,
      aws_subnet.pub_1_in_vpc_1.cidr_block,
      aws_subnet.pub_2_in_vpc_1.cidr_block
    ]
    */
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "sg_for_elb_app" {
  name        = "sg_for_elb_app"
  description = "Allow traffic for ELB"
  vpc_id      = aws_vpc.vpc_1.id

  ingress {
    description = "HTTP on 80 port from the internet"
    from_port   = 80
    to_port     = 80
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "icmp"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8888
    to_port     = 8888
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  /*
  ingress {
    description = "icmp"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [
      aws_subnet.pub_1_in_vpc_1.cidr_block,
      aws_subnet.pub_2_in_vpc_1.cidr_block,
      aws_subnet.pub_in_vpc_2.cidr_block
    ]
  }

  ingress {
    description = "Allow all inbound traffic on the 80 port"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [
      aws_subnet.pub_1_in_vpc_1.cidr_block,
      aws_subnet.pub_2_in_vpc_1.cidr_block,
      aws_subnet.pub_in_vpc_2.cidr_block
    ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
*/
}

resource "aws_launch_configuration" "lc_for_bastion_in_vpc_2" {
  name                        = "lc_for_bastion_in_vpc_2"
  image_id                    = "ami-07df274a488ca9195"
  instance_type               = "t2.micro"
  security_groups             = [aws_security_group.sg_for_bastion_in_vpc_2.id]
  associate_public_ip_address = true
  key_name                    = "frankfurt-ec2"

  user_data = file("./add-teacher-key.sh")

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "ag_for_bastion" {
  name                      = "as_group_for_bastion"
  launch_configuration      = aws_launch_configuration.lc_for_bastion_in_vpc_2.name
  vpc_zone_identifier       = [aws_subnet.pub_in_vpc_2.id]
  min_size                  = 1
  max_size                  = 1
  desired_capacity          = 1
  health_check_grace_period = 60

  tag {
    key                 = "Name"
    value               = "bastion-host-in-vpc-2"
    propagate_at_launch = true
  }
}

resource "aws_instance" "nginx_in_priv_1_subnet_of_vpc_1" {
  ami                    = aws_ami_from_instance.ami_nginx.id
  instance_type          = "t2.micro"
  key_name               = "frankfurt-ec2"
  subnet_id              = aws_subnet.priv_1_in_vpc_1.id
  vpc_security_group_ids = [aws_security_group.sg_for_nginx_in_vpc_1.id]
  user_data              = file("./set-options-for-nginx.sh")
  iam_instance_profile   = aws_iam_instance_profile.iam_inst_profile_for_access_to_s3.name
  depends_on             = [aws_vpc_endpoint.endpoint_to_s3, aws_iam_instance_profile.iam_inst_profile_for_access_to_s3]
  tags = {
    "Name" = "nginx-in-priv-1-subnet-of-vpc-1"
  }
}

resource "aws_instance" "nginx_in_priv_2_subnet_of_vpc_1" {
  ami                    = aws_ami_from_instance.ami_nginx.id
  instance_type          = "t2.micro"
  key_name               = "frankfurt-ec2"
  subnet_id              = aws_subnet.priv_2_in_vpc_1.id
  vpc_security_group_ids = [aws_security_group.sg_for_nginx_in_vpc_1.id]
  user_data              = file("./set-options-for-nginx.sh")
  iam_instance_profile   = aws_iam_instance_profile.iam_inst_profile_for_access_to_s3.name
  depends_on             = [aws_vpc_endpoint.endpoint_to_s3, aws_iam_instance_profile.iam_inst_profile_for_access_to_s3]

  tags = {
    "Name" = "nginx-in-priv-2-subnet-of-vpc-1"
  }
}

resource "aws_lb" "alb" {
  name               = "alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.sg_for_elb_app.id]
  subnets            = [aws_subnet.pub_1_in_vpc_1.id, aws_subnet.pub_2_in_vpc_1.id] # aws_subnet.priv_1_in_vpc_1.id

  tags = {
    "name" = "alb"
  }
}

resource "aws_lb_listener" "alb_listener" {
  load_balancer_arn = aws_lb.alb.arn
  protocol          = "HTTP"
  port              = 80
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg_nginx.arn
  }
  depends_on = [aws_lb_target_group.tg_nginx]
}

resource "aws_lb_target_group" "tg_nginx" {
  name        = "tg-nginx"
  port        = 8888
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc_1.id
  target_type = "instance"
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = 8888
    path                = "/"
    matcher             = "200-299"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
  tags = {
    "Name" = "tg-nginx"
  }
}

resource "aws_lb_target_group_attachment" "tg_attach_nginx_in_ps1_of_vpc1" {
  target_group_arn = aws_lb_target_group.tg_nginx.arn
  target_id        = aws_instance.nginx_in_priv_1_subnet_of_vpc_1.id
  port             = 8888
}

resource "aws_lb_target_group_attachment" "tg_attach_nginx_in_ps2_of_vpc1" {
  target_group_arn = aws_lb_target_group.tg_nginx.arn
  target_id        = aws_instance.nginx_in_priv_2_subnet_of_vpc_1.id
  port             = 8888
}

resource "aws_launch_template" "lt_custom" {
  name                   = "lt-custom"
  image_id               = aws_ami_from_instance.ami_nginx.id
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.sg_for_nginx_in_vpc_1.id]
  user_data              = filebase64("set-options-for-nginx.sh")
  metadata_options {
    http_endpoint = "enabled"
  }
}

resource "aws_autoscaling_group" "auto_sg" {
  name                      = "auto-sg"
  target_group_arns         = [aws_lb_target_group.tg_nginx.arn]
  vpc_zone_identifier       = [aws_subnet.priv_1_in_vpc_1.id, aws_subnet.priv_2_in_vpc_1.id]
  desired_capacity          = 0
  max_size                  = 2
  min_size                  = 1
  health_check_grace_period = 120
  health_check_type         = "ELB"
  depends_on                = [aws_vpc_endpoint.endpoint_to_s3]

  launch_template {
    id = aws_launch_template.lt_custom.id
  }
}

resource "aws_autoscaling_policy" "as_p" {
  name        = "as-p"
  policy_type = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = "80"
  }
  autoscaling_group_name = aws_autoscaling_group.auto_sg.name
}

resource "aws_vpc_endpoint" "endpoint_to_s3" {
  vpc_id          = aws_vpc.vpc_1.id
  service_name    = "com.amazonaws.eu-central-1.s3"
  route_table_ids = [aws_route_table.rt_for_priv_subnets_in_vpc_1.id]

  tags = {
    Name = "endpoint-to-s3"
  }
}

resource "aws_vpc_endpoint_route_table_association" "vpc_endpoint_rt_asc" {
  route_table_id  = aws_route_table.rt_for_priv_subnets_in_vpc_1.id
  vpc_endpoint_id = aws_vpc_endpoint.endpoint_to_s3.id
}

resource "aws_s3_bucket" "krasavin_bucket1" {
  bucket_prefix = "s3-"
  acl           = "private"
  versioning {
    enabled = true
  }
  lifecycle_rule {
    enabled = true
    id      = "s3-lsr"
    prefix  = "/"
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    noncurrent_version_transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      days = 90
    }
  }
  tags = {
    Name = "krasavin-s3-bucket"
  }
}

resource "aws_s3_bucket_object" "s3_bucket_object_a" {
  bucket        = aws_s3_bucket.krasavin_bucket1.id
  key           = "krasavin-object"
  acl           = "private"
  storage_class = "STANDARD"
  source        = "./file_a.txt"
}

resource "aws_s3_bucket_object" "s3_bucket_object_b" {
  bucket        = aws_s3_bucket.krasavin_bucket1.id
  key           = "krasavin-object"
  acl           = "private"
  storage_class = "STANDARD"
  source        = "./file_b.txt"
}

resource "aws_iam_role" "custom_iam_role" {
  name        = "custom-iam-role"
  description = "custom-iam-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "custom_iam_role_policy" {
  name = "policy_for_acccess-to-s3"
  role = aws_iam_role.custom_iam_role.id
  policy = jsonencode({
    Version : "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:Get*",
          "s3:List*"
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_instance_profile" "iam_inst_profile_for_access_to_s3" {
  name = "iam-inst-profile-for-access-to-s3"
  role = aws_iam_role.custom_iam_role.name
}

resource "aws_iam_policy" "iam_policy_tags" {
  name        = "custom-iam-policy-tags"
  description = "custom-iam-policy-tags"
  path        = "/"
  policy      = file("./setup_policy.json")
}

resource "aws_route53_zone" "custom_route53_zone" {
  name = "krasavin.net"
  vpc {
    vpc_id = aws_vpc.vpc_1.id
  }
  vpc {
    vpc_id = aws_vpc.vpc_2.id
  }
}

resource "aws_route53_record" "route53_record_1" {
  zone_id = aws_route53_zone.custom_route53_zone.zone_id
  name    = "nginx1a.krasavin.net"
  type    = "A"
  ttl     = "500"
  records = [aws_instance.nginx_in_priv_1_subnet_of_vpc_1.private_ip]
}

resource "aws_route53_record" "route53_record_2" {
  zone_id = aws_route53_zone.custom_route53_zone.zone_id
  name    = "nginx1b.krasavin.net"
  type    = "A"
  ttl     = "500"
  records = [aws_instance.nginx_in_priv_2_subnet_of_vpc_1.private_ip]
}

resource "aws_route53_record" "load-balancer" {
  zone_id = aws_route53_zone.custom_route53_zone.zone_id
  name    = "alb.krasavin.net"
  type    = "A"
  alias {
    name                   = aws_lb.alb.dns_name
    zone_id                = aws_lb.alb.zone_id
    evaluate_target_health = true
  }
}
