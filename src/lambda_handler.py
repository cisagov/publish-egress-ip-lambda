"""AWS Lambda handler to publish egress IPs from a provided list of AWS accounts."""

# Standard Python Libraries
from datetime import datetime, timezone
from ipaddress import collapse_addresses, ip_network
import logging
import re
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, TypedDict, Union

# Third-Party Libraries
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def assume_role(role_arn: str, session_name: str) -> Tuple[str, str, str]:
    """Assume the given role and return a tuple containing the assumed role's credentials."""
    # Create an STS session with current credentials
    sts: boto3.client = boto3.client("sts")

    # Assume the provided role
    response: Dict[str, Any] = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=session_name
    )

    return (
        response["Credentials"]["AccessKeyId"],
        response["Credentials"]["SecretAccessKey"],
        response["Credentials"]["SessionToken"],
    )


def create_assumed_aws_client(
    aws_service: str, role_arn: str, session_name: str
) -> boto3.client:
    """Assume the given role and return an AWS client for the given service using that role."""
    role_credentials: Tuple[str, str, str] = assume_role(role_arn, session_name)

    return boto3.client(
        aws_service,
        aws_access_key_id=role_credentials[0],
        aws_secret_access_key=role_credentials[1],
        aws_session_token=role_credentials[2],
    )


def create_assumed_aws_resource(
    aws_service: str, region: str, role_arn: str, session_name: str
) -> boto3.resource:
    """Assume the given role and return an AWS resource object for the given service using that role."""
    role_credentials: Tuple[str, str, str] = assume_role(role_arn, session_name)

    return boto3.resource(
        aws_service,
        region_name=region,
        aws_access_key_id=role_credentials[0],
        aws_secret_access_key=role_credentials[1],
        aws_session_token=role_credentials[2],
    )


def convert_tags(aws_resource: boto3.resource) -> Dict[str, str]:
    """Convert resource tags from an AWS dictionary into a Python dictionary."""
    try:
        tags: Dict[str, str] = {x["Key"]: x["Value"] for x in aws_resource.tags}
    except TypeError:
        # This happens if there are no tags associated with the resource
        tags = {}
    return tags


def get_ec2_ips(
    ec2: boto3.resource, application_tag_name: str, publish_egress_tag_name: str
) -> Iterator[Tuple[str, str]]:
    """Create a set of public EC2 IPs.

    Yields (application tag value, public_ip) tuples.
    """
    # Get list of running EC2 instances
    instances: boto3.resources.collection = ec2.instances.filter(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    )
    # Get list of elastic IPs in all VPCs
    vpc_addresses: boto3.resources.collection = ec2.vpc_addresses.all()

    for instance in instances:
        # If the instance doesn't have a public IP, we can skip it
        if instance.public_ip_address is None:
            continue

        # Convert instance tags from an AWS dictionary into a Python dictionary
        tags = convert_tags(instance)

        # If the publish egress tag doesn't exist or isn't set to True, skip it
        if tags.get(publish_egress_tag_name, str(False)) != str(True):
            continue
        # Send back a tuple associating the public IP to an application.
        # If application is unset, return "", so that the IP can be included
        # in a list of all IPs if desired (e.g. using app_regex=".*").
        yield (tags.get(application_tag_name, ""), instance.public_ip_address)

    for vpc_address in vpc_addresses:
        # Convert elastic IP tags from an AWS dictionary into a Python dictionary
        eip_tags = convert_tags(vpc_address)

        # If the publish egress tag doesn't exist or isn't set to True, skip it
        if eip_tags.get(publish_egress_tag_name, str(False)) != str(True):
            continue
        # Send back a tuple associating the public IP to an application.
        # If application is unset, return "", so that the IP can be included
        # in a list of all IPs if desired (e.g. using app_regex=".*").
        yield (eip_tags.get(application_tag_name, ""), vpc_address.public_ip)


def get_ec2_regions(
    ec2: boto3.client, filters: Optional[List[Dict[str, Union[str, List[str]]]]] = None
) -> List[str]:
    """Get a filtered list of all the regions with EC2 support."""
    if filters is None:
        filters = []

    response = ec2.describe_regions(Filters=filters)
    result = [x["RegionName"] for x in response["Regions"]]
    return result


def update_bucket(bucket_name: str, object_name: str, object_contents: str) -> None:
    """Update an object in a S3 bucket with new contents."""
    s3 = boto3.resource("s3")

    # Get the bucket
    bucket = s3.Bucket(bucket_name)

    # Get the object within the bucket
    b_object = bucket.Object(object_name)

    # Send the bytes contents to the object in the bucket
    # Prevent caching of this object
    b_object.put(
        Body=object_contents.encode("utf-8"),
        CacheControl="no-cache",
        ContentEncoding="utf-8",
        ContentType="text/plain",
    )

    # By default, new objects cannot be read by the public, but we want to
    # allow public reads of this object
    b_object.Acl().put(ACL="public-read")


def failed_task(result: Dict[str, Any], error_msg: str) -> None:
    """Update a given result because of a failure during processing."""
    result["success"] = False
    result["error_message"] = error_msg


def task_default(event):
    """Provide a result if no valid task was provided."""
    result = {}
    error_msg = 'Provided task "%s" is not supported.'

    task = event.get("task", None)
    logging.error(error_msg, task)
    failed_task(result, error_msg % task)

    return result


class FileConfig(TypedDict):
    """Define the type structure of the dictionary in the file_configs variable."""

    app_regex: re.Pattern[str]
    description: str
    filename: str
    # I'd prefer to define ip_set as Set[Union[IPv4Address, IPv6Address]],
    # but ipaddress.collapse_addresses() uses the type variable "_N" while
    # ip_network returns Union[IPv4Network, IPv6network] which causes
    # the mypy pre-commit hook to throw this error:
    #   Value of type variable "_N" of "collapse_addresses" cannot be
    #   "Union[IPv4Network, IPv6Network]"
    # My solution to this problem is to simply define ip_set as Set[Any].
    # For a similar issue and discussion, see
    # https://github.com/python/typeshed/issues/2080
    ip_set: Set[Any]
    static_ips: List[str]


def validate_event_data(
    event: Dict[str, Any]
) -> Tuple[Dict[str, Any], bool, List[str]]:
    """Validate the event data and return a tuple containing the validated event, a boolean result (True if valid, False if invalid), and a list of error message strings."""
    result = True
    errors = []

    # Account ID checks
    if "account_ids" not in event:
        errors.append('Missing required key "account_ids" in event.')
    elif event["account_ids"] == []:
        errors.append('"account_ids" must be a non-empty list.')
    else:
        account_ids: List[str] = event["account_ids"]
        try:
            # Ensure account_ids is a list of strings
            if not isinstance(account_ids, list):
                account_ids = [str(account_ids)]
            else:
                account_ids = [str(e) for e in account_ids]

            # Verify that each provided AWS account ID is 12 digits
            invalid_account_ids = []
            for account_id in account_ids.copy():
                if not re.match(r"^\d{12}$", account_id):
                    account_ids.remove(account_id)
                    invalid_account_ids.append(account_id)

            if invalid_account_ids:
                errors.append(
                    f'Invalid account ID(s) provided: "{", ".join(invalid_account_ids)}" - ID must be 12 digits.'
                )
        except Exception:
            errors.append("account_ids must be a list of strings.")
        event["account_ids"] = account_ids

    # Bucket name checks
    if "bucket_name" not in event:
        errors.append('Missing required key "bucket_name" in event.')
    elif not isinstance(event["bucket_name"], str):
        errors.append('"bucket_name" must be a string.')

    # File configuration checks
    file_configs: List[FileConfig] = event["file_configs"]
    for config in file_configs:
        # Verify that required keys are present
        for required_key in ["app_regex", "description", "filename"]:
            if required_key not in config:
                errors.append(
                    f'Missing required key "{required_key}" in file config: "{config}"'
                )

        # Verify that app_regex is valid and initialize if it is
        if "app_regex" in config:
            try:
                config["app_regex"] = re.compile(config["app_regex"])
            except (TypeError, re.error):
                errors.append(
                    f'Invalid app_regex "{config["app_regex"]}" provided in file config: "{config}"'
                )

        # Initialize the set of static IPs in this config
        config["ip_set"] = {ip_network(i) for i in config.get("static_ips", [])}
    event["file_configs"] = file_configs

    # File header checks
    if "file_header" in event:
        file_header: List[str] = event["file_header"]
        # Ensure file_header is a list of strings
        try:
            if not isinstance(file_header, list):
                file_header = [str(file_header)]
            else:
                file_header = [str(e) for e in file_header]
        except Exception:
            errors.append("file_header must be a list of strings.")
        event["file_header"] = file_header

    if errors:
        result = False

    return event, result, errors


def task_publish(event: Dict[str, Any]) -> Dict[str, Union[Optional[str], bool]]:
    """Publish the egress IP addresses in the given AWS accounts to an S3 bucket."""
    result: Dict[str, Union[Optional[str], bool]] = {"message": None, "success": True}

    # Validate all event data before going any further
    event_valid: bool
    event_errors: List[str]
    event, event_valid, event_errors = validate_event_data(event)
    if not event_valid:
        for e in event_errors:
            logging.error(e)
        failed_task(result, " ".join(event_errors))
        return result

    # The account IDs to examine for IP addresses
    account_ids: List[str] = event["account_ids"]

    # Name of the AWS resource tag whose value represents the application
    # associated with an IP address
    application_tag_name: str = event.get("application_tag", "Application")

    # The bucket to publish the files to
    bucket_name: str = event["bucket_name"]

    # Name of the IAM role to assume that can read the necessary EC2 data
    # in each AWS account. Note that this role must exist in each account.
    ec2_read_role_name: str = event.get("role_name", "EC2ReadOnly")

    # A list of dictionaries that define the files to be created and
    # published.  When an IP is to be published, its associated
    # application is compared to the app_regex field.  If it matches, it
    # will be included in the associated filename.  The required keys in
    # each dictionary are:
    #   - "app_regex" (string): a regular expression that will be compared to
    #       the application tag value to determine if the IP should be published
    #   - "description" (string): a description of the file
    #   - "filename" (string): the name of the file
    #   - "static_ips" (list(string)): a list of CIDR blocks that will always
    #       be included in the published file
    file_configs: List[FileConfig] = event.get("file_configs", [])

    # Header template for each file, comprised of a list of strings.
    # When the file is published, newline characters are automatically added
    # between each item in the list.
    # The following variables are available within the template:
    # {domain} - domain where the published files are located
    # {filename} - name of the published file
    # {timestamp} - timestamp when the file was published
    # {description} - description of the published file
    file_header: List[str] = event.get(
        "file_header",
        [
            "###",
            "# https://{domain}/{filename}",
            "# {timestamp}",
            "# {description}",
            "###",
        ],
    )

    # AWS resource tag name indicating whether an IP address should be published
    publish_egress_tag_name: str = event.get("publish_egress_tag", "Publish Egress")

    # An AWS-style filter definition to limit the queried regions
    region_filters: List[Dict[str, Union[str, List[str]]]] = event.get(
        "region_filters", []
    )

    for account_id in account_ids:
        logging.info("Examining account: %s", account_id)

        # Create an EC2 client with the assumed role
        ec2: boto3.client = create_assumed_aws_client(
            aws_service="ec2",
            role_arn=f"arn:aws:iam::{account_id}:role/{ec2_read_role_name}",
            session_name="publish-egress-ip-lambda",
        )

        # Get a list of all regions that match our filter
        regions: List[str] = get_ec2_regions(ec2, region_filters)

        logging.info("Gathering public IPs from %d regions", len(regions))

        # Loop through the region list and fetch the public EC2 IPs
        for region in regions:
            logging.info("Querying region: %s", region)

            # Create an EC2 resource with the assumed role in the specified
            # region
            ec2 = create_assumed_aws_resource(
                aws_service="ec2",
                region=region,
                role_arn=f"arn:aws:iam::{account_id}:role/{ec2_read_role_name}",
                session_name="publish-egress-ip-lambda",
            )

            # Get the public IPs of instances that are tagged to be published
            for application_tag_value, public_ip in get_ec2_ips(
                ec2, application_tag_name, publish_egress_tag_name
            ):
                # Loop through all regexes and add IP to set if matched
                for config in file_configs:
                    if config["app_regex"].match(application_tag_value):
                        config["ip_set"].add(ip_network(public_ip))

    # Use a single timestamp for all files
    now = "{:%a %b %d %H:%M:%S UTC %Y}".format(datetime.utcnow())

    # The domain to display in the header of each published file
    domain: str = event.get("domain", "example.gov")

    # Update each object (file) in the bucket
    for config in file_configs:
        # Initialize contents of object to be published
        object_contents = "\n".join(file_header) + "\n"
        for net in collapse_addresses(config["ip_set"]):
            object_contents += str(net) + "\n"

        # Fill in header template
        object_contents = object_contents.format(
            domain=domain,
            filename=config["filename"],
            timestamp=now,
            description=config["description"],
        )

        # Send the contents to the S3 bucket
        logging.info("Writing to bucket: {}/{}".format(bucket_name, config["filename"]))
        update_bucket(bucket_name, config["filename"], object_contents)

        # Print the contents for the user
        logging.info("")
        logging.info("-" * 40)
        logging.info(object_contents)
        logging.info("-" * 40)
        logging.info("")

    result["message"] = "Successfully published IP addresses."
    logging.info(result["message"])

    return result


def handler(event, context) -> Dict[str, Optional[str]]:
    """Process the event and generate a response.

    The event should have a task member that is one of the supported tasks.

    :param event: The event dict that contains the parameters sent when the function
                  is invoked.
    :param context: The context in which the function is called.
    :return: The result of the action.
    """
    response: Dict[str, Optional[str]] = {"timestamp": str(datetime.now(timezone.utc))}

    task_name = f"task_{event.get('task')}"
    task = globals().get(task_name, task_default)

    result: Dict[str, Any]
    if not callable(task):
        logging.error("Provided task is not a callable.")
        logging.error(task)
        result = task_default(event)
    else:
        result = task(event)

    response.update(result)
    return response
