variable "project_name" {
  description = "The name of the project"
  type        = string
}

variable "frontend_domain_name" {
  description = "The domain name for the frontend"
  type        = string
}

variable "hosted_zone_id" {
  description = "The ID of the hosted zone"
  type        = string
}

variable "min_ttl" {
  description = "The minimum TTL for the CloudFront distribution"
  type        = number
}

variable "default_ttl" {
  description = "The default TTL for the CloudFront distribution"
  type        = number
}

variable "max_ttl" {
  description = "The maximum TTL for the CloudFront distribution"
  type        = number
}

variable "cache_policy" {
  description = "The cache policy for the CloudFront distribution"
  type        = string
  default     = "Managed-CachingOptimized" #or "Managed-CachingDisabled"
}
