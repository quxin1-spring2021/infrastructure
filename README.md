# Infrastructure
Infrastructure for csye-6225.

## Infrastructure as Code with Terraform
* Clone repo to local.
* Run `terraform init` to initialize terraform environment.
* Demo creation of networking resources using `terraform apply` command.
* Demo cleanup of networking resources using `terraform destroy` command.

## Command to Import a Certificate
```
$ aws acm import-certificate --certificate fileb://Certificate.pem \
      --certificate-chain fileb://CertificateChain.pem \
      --private-key fileb://PrivateKey.pem 	
```
Use the ARN of certificate in the output of this command for SSL Connections.