# publish-egress-ip-lambda #

[![GitHub Build Status](https://github.com/cisagov/publish-egress-ip-lambda/workflows/build/badge.svg)](https://github.com/cisagov/publish-egress-ip-lambda/actions)

This is a generic skeleton project that can be used to quickly get a
new [cisagov](https://github.com/cisagov) GitHub
[AWS Lambda](https://aws.amazon.com/lambda/) project using the Python runtimes
started. This skeleton project contains [licensing information](LICENSE), as
well as [pre-commit hooks](https://pre-commit.com) and
[GitHub Actions](https://github.com/features/actions) configurations
appropriate for the major languages that we use.

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

## Running the Lambda locally ##

The configuration in this repository allows you run the Lambda locally for
testing as long as you do not need explicit permissions for other AWS
services. This can be done with the following command:

```console
docker compose up run_lambda_locally
```

You can then invoke the Lambda using the following:

```console
 curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{}'
```

The `{}` in the command is the invocation event payload to send to the Lambda
and would be the value given as the `event` argument to the handler.

## New Repositories from a Skeleton ##

Please see our [Project Setup guide](https://github.com/cisagov/development-guide/tree/develop/project_setup)
for step-by-step instructions on how to start a new repository from
a skeleton. This will save you time and effort when configuring a
new repository!

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
