output "s3_bucket_static_website" {
  value = aws_s3_bucket.frontend_bucket.id
}

output "domain_url" {
  value = aws_cloudfront_distribution.frontend.domain_name
}