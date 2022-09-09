# publish-egress-ip-lambda #

[![GitHub Build Status](https://github.com/cisagov/publish-egress-ip-lambda/workflows/build/badge.svg)](https://github.com/cisagov/publish-egress-ip-lambda/actions)

This repository contains code to create a Lambda function that can scan a set
of AWS accounts and publish files (to an S3 bucket) containing the public IP
addresses of EC2 instances or Elastic IPs that have been properly tagged.
Refer to the [Lambda inputs](#lambda-inputs) section below, specifically the
`publish_egress_tag`, for more information about how to tag an instance
or EIP for publication.

## Building the base Lambda image ##

The base Lambda image can be built with the following command:

```console
docker compose build
```

This base image is used both to build a deployment package and to run the
Lambda locally.

## Building a deployment package ##

You can build a deployment zipfile to use when creating a new AWS Lambda
function with the following command:

```console
docker compose up build_deployment_package
```

This will output the deployment zipfile in the root directory.

## Lambda inputs ##

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| account\_ids | The list of AWS accounts to query for egress IPs to publish. | `list(string)` | n/a | yes |
| application\_tag | The name of the AWS tag whose value represents the application associated with an IP address. | `string` | `"Application"` | no |
| bucket\_name | The name of the S3 bucket to publish egress IP address information to. | `string` | n/a | yes |
| domain | The domain hosting the published file(s) containing egress IPs. | `string` | `"example.gov"` | no |
| ec2\_read\_role\_name | The name of the IAM role that allows read access to the necessary EC2 attributes.  Note that this role must exist in each account that you want to query and it must be assumable by Lambda.  For an example policy, see [`cisagov/cool-accounts`](https://github.com/cisagov/cool-accounts/blob/develop/dynamic/ec2readonly_policy.tf). | `string` | `"EC2ReadOnly"` | no |
| file\_configs | A list of dictionaries that define the files to be published.  "app_regex" specifies a regular expression that is matched against the value of the application_tag to determine if the address should be included in the file.  "description" is the description of the published file.  "filename" is the name to assign the published file.  "static\_ips" is the list of CIDR blocks that will always be included in the published file. | `list(dict({ app_regex = string, description = string, filename = string, static_ips = list(string) }))` | n/a | yes |
| file\_header | The header template for each published file, comprised of a list of strings.  When the file is published, newline characters are automatically added between each item in the list.  The following variables are available within the template: `{domain}` - the domain where the published files are located, `{filename}` - the name of the published file, `{timestamp}` - the timestamp when the file was published, `{description}` - the description of the published file. | `list(string)` | `["###", "# https://{domain}/{filename}", "# {timestamp}", "# {description}", "###"]` | no |
| publish\_egress\_tag | The name of the AWS tag whose value represents whether the EC2 instance or elastic IP should have its public IP address published. | `string` | `"Publish Egress"` | no |
| region\_filters | A list of AWS EC2 region filters to use when querying for IP addresses to publish.  If a filter is not specified, the query will be performed in all regions.  An example filter to restrict to US regions looks like this: `[{ "Name" : "endpoint", "Values" : ["*.us-*"] }]`.  For more information, refer to the [AWS EC2 CLI documentation](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-regions.html). | `list(dict({ Name = string, Values = list(string) }))` | `[]` | no |
| task | The name of Lambda task to perform.  Currently, the only valid value is `"publish"`. | `string` | n/a | yes |

## Example Lambda input ##

The following is an example of the JSON input event that is expected by the
Lambda:

```json
{
    "accounts": [
        "123456789012",
        "234567890123"
    ],
    "bucket": "my-egress-ip-bucket",
    "domain": "egress.ips.example.gov",
    "file_configs": [
        {
            "app_regex": ".*",
            "description": "This file contains a list of all IP public addresses to be published.",
            "filename": "all.txt",
            "static_ips": []
        },
        {
            "app_regex": "^Vulnerability Scanning$",
            "description": "This file contains a list of all IPs used for Vulnerability Scanning.",
            "filename": "vs.txt",
            "static_ips": [
                "192.168.1.1/32",
                "192.168.2.2/32"
            ]
        }
    ],
    "region_filters": [{
        "Name": "endpoint",
        "Values": ["*.us-*"]
    }],
    "task": "publish"
}
```

## Deploying the Lambda ##

The easiest way to deploy the Lambda and related resources is to use the
[cisagov/publish-egress-ip-terraform](https://github.com/cisagov/publish-egress-ip-terraform)
repository.  Refer to the documentation in that project for more information.

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
