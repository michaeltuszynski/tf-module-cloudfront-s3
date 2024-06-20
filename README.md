# tf-module-cloudfront-s3

```hcl
module "cloudfront_s3" {
  source               = "git::https://github.com/harmonate/tf-module-cloudfront-s3.git?ref=main"
  project_name         = var.project_name
  frontend_domain_name = local.frontend_domain_name
  hosted_zone_id       = var.hosted_zone_id
  min_ttl              = 0
  max_ttl              = 0
  default_ttl          = 0
  cache_policy         = "Managed-CachingOptimized"  #or "Managed-CachingDisabled"
}
```
