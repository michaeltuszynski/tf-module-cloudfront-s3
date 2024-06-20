data "aws_cloudfront_response_headers_policy" "cors_policy" {
  name = "Managed-CORS-with-preflight-and-SecurityHeadersPolicy"
}

data "aws_cloudfront_cache_policy" "cache_selected" {
  name = var.cache_policy
}

data "aws_cloudfront_origin_request_policy" "cors_s3" {
  name = "Managed-CORS-S3Origin"
}

locals {
  s3_origin_id         = "s3_bucket_static_website"
  frontend_bucket_name = "${var.project_name}-frontend-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 5
  special = false
  upper   = false
  numeric = true
  lower   = true
}

resource "aws_s3_bucket" "frontend_bucket" {
  bucket        = local.frontend_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "frontend_bucket_ownership" {
  bucket = aws_s3_bucket.frontend_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "frontend_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.frontend_bucket_ownership]

  bucket = aws_s3_bucket.frontend_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "frontend_bucket_versioning" {
  bucket = aws_s3_bucket.frontend_bucket.id
  versioning_configuration {
    status = "Disabled"
  }
  mfa = "Disabled"
}

resource "aws_s3_bucket_cors_configuration" "frontend_bucket_cors" {
  bucket = aws_s3_bucket.frontend_bucket.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST", "GET"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

data "aws_iam_policy_document" "s3_policy_frontend" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.frontend_bucket.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.frontend.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "bucket_policy_frontend" {
  bucket = aws_s3_bucket.frontend_bucket.id
  policy = data.aws_iam_policy_document.s3_policy_frontend.json
}

resource "aws_s3_bucket" "frontend_bucket_cwlogs" {
  bucket        = "${var.project_name}-cwlogs-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "cw_bucket_versioning" {
  bucket = aws_s3_bucket.frontend_bucket_cwlogs.id
  versioning_configuration {
    status = "Disabled"
  }
  mfa = "Disabled"
}

resource "aws_s3_bucket_ownership_controls" "cw_bucket_ownership" {
  bucket = aws_s3_bucket.frontend_bucket_cwlogs.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "cw_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.cw_bucket_ownership]

  bucket = aws_s3_bucket.frontend_bucket_cwlogs.id
  acl    = "log-delivery-write"
}

data "aws_iam_policy_document" "s3_policy_cw" {
  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "s3:GetBucketAcl"
    ]
    resources = [
      "${aws_s3_bucket.frontend_bucket_cwlogs.arn}",
      "${aws_s3_bucket.frontend_bucket_cwlogs.arn}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudfront_distribution.frontend.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "bucket_policy_cw" {
  bucket = aws_s3_bucket.frontend_bucket_cwlogs.id
  policy = data.aws_iam_policy_document.s3_policy_cw.json
}

#Certificate
resource "aws_acm_certificate" "frontend_cert" {
  domain_name       = var.frontend_domain_name
  validation_method = "DNS"

  subject_alternative_names = [
    "www.${var.frontend_domain_name}", "${var.frontend_domain_name}", "*.${var.frontend_domain_name}"
  ]

  tags = {
    Type = "Frontend ACM Cert"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# resource "null_resource" "import_existing_record" {
#   for_each = {
#     for dvo in aws_acm_certificate.frontend_cert.domain_validation_options : dvo.domain_name => {
#       name   = dvo.resource_record_name
#       record = dvo.resource_record_value
#       type   = dvo.resource_record_type
#     }
#   }

#   provisioner "local-exec" {
#     when    = create
#     command = <<EOT
#       if aws route53 list-resource-record-sets --hosted-zone-id ${var.hosted_zone_id} --query "ResourceRecordSets[?Name == '${each.value.name}.'] | [0]" | grep -q '"Name":'; then
#         terraform import aws_route53_record.frontend_cert_validation["${each.key}"] ${var.hosted_zone_id}_${each.value.name}
#       fi
#     EOT
#   }
# }

# resource "aws_route53_record" "frontend_cert_validation" {
#   for_each = {
#     for dvo in aws_acm_certificate.frontend_cert.domain_validation_options : dvo.domain_name => {
#       name   = dvo.resource_record_name
#       record = dvo.resource_record_value
#       type   = dvo.resource_record_type
#     }
#   }

#   name    = each.value.name
#   records = [each.value.record]
#   ttl     = 60
#   type    = each.value.type
#   zone_id = var.hosted_zone_id

#   lifecycle {
#     create_before_destroy = true
#   }
# }

# resource "aws_acm_certificate_validation" "frontend_cert_validation" {
#   certificate_arn         = aws_acm_certificate.frontend_cert.arn
#   validation_record_fqdns = [for record in aws_route53_record.frontend_cert_validation : record.fqdn]
# }

resource "aws_cloudfront_origin_access_control" "s3_bucket_static_website" {
  name                              = "Managed-S3OriginPolicy"
  description                       = "Managed policy for S3 origin access"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "frontend" {
  enabled             = true
  http_version        = "http2and3"
  is_ipv6_enabled     = true
  price_class         = "PriceClass_All"
  retain_on_delete    = false
  wait_for_deployment = false
  comment             = "S3 bucket distribution"
  default_root_object = "index.html"

  aliases = ["www.${var.frontend_domain_name}", "${var.frontend_domain_name}"]

  origin {
    domain_name              = aws_s3_bucket.frontend_bucket.bucket_regional_domain_name
    origin_id                = local.s3_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.s3_bucket_static_website.id
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    viewer_protocol_policy     = "redirect-to-https"
    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.cors_policy.id
    cache_policy_id            = data.aws_cloudfront_cache_policy.cache_selected.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.cors_s3.id

    min_ttl     = var.min_ttl
    default_ttl = var.default_ttl
    max_ttl     = var.max_ttl
    compress    = true

  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.frontend_cert.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  logging_config {
    bucket          = aws_s3_bucket.frontend_bucket_cwlogs.bucket_regional_domain_name
    include_cookies = false
    prefix          = "cloudfront-logs/"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  depends_on = [aws_acm_certificate.frontend_cert]
}

resource "aws_route53_record" "frontend" {
  zone_id = var.hosted_zone_id
  name    = var.frontend_domain_name
  type    = "CNAME"
  ttl     = "300"
  records = [aws_cloudfront_distribution.frontend.domain_name]

  //depends_on = [aws_acm_certificate_validation.frontend_cert_validation]
}
