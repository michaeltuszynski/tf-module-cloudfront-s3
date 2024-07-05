output "s3_bucket_id" {
  value = aws_s3_bucket.frontend_bucket.id
}

output "domain_url" {
  value = aws_cloudfront_distribution.frontend.domain_name
}

output "distribution_id" {
  value = aws_cloudfront_distribution.frontend.id
}
