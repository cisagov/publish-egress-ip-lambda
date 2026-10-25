"""Regression tests for publishing mixed IPv4 and IPv6 addresses."""

# Standard Python Libraries
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# cisagov Libraries
# Local Libraries
import lambda_handler  # noqa: E402


def event_with(static_ips):
    """Build the smallest valid publish event for a single output file."""
    return {
        "task": "publish",
        "account_ids": ["123456789012"],
        "bucket_name": "test-bucket",
        "file_configs": [
            {
                "app_regex": ".*",
                "description": "Test addresses",
                "filename": "ips.txt",
                "static_ips": static_ips,
            }
        ],
    }


def publish(event, dynamic_ips=()):
    """Run task_publish without contacting AWS and return rendered contents."""
    with patch.object(
        lambda_handler, "create_assumed_aws_client", return_value=object()
    ), patch.object(
        lambda_handler,
        "get_ec2_regions",
        return_value=["us-east-1"] if dynamic_ips else [],
    ), patch.object(
        lambda_handler, "create_assumed_aws_resource", return_value=object()
    ), patch.object(
        lambda_handler,
        "get_ec2_ips",
        return_value=[lambda_handler.Ec2Info("app", ip) for ip in dynamic_ips],
    ), patch.object(
        lambda_handler, "update_bucket"
    ) as update_bucket:
        result = lambda_handler.task_publish(event)

    assert result["success"] is True
    update_bucket.assert_called_once()
    return update_bucket.call_args.args[2]


def address_lines(contents):
    """Return non-comment, non-empty output lines."""
    return [line for line in contents.splitlines() if line and not line.startswith("#")]


def test_mixed_static_ipv4_ipv6():
    """Publish mixed static IPv4 and IPv6 host addresses."""
    contents = publish(event_with(["192.0.2.1", "2001:db8::1"]))
    assert address_lines(contents) == ["192.0.2.1/32", "2001:db8::1/128"]


def test_mixed_static_networks_collapse_per_family():
    """Collapse adjacent static networks independently by address family."""
    contents = publish(
        event_with(
            [
                "192.0.2.0/25",
                "192.0.2.128/25",
                "2001:db8::/65",
                "2001:db8:0:0:8000::/65",
            ]
        )
    )
    assert address_lines(contents) == ["192.0.2.0/24", "2001:db8::/64"]


def test_mixed_dynamic_ipv4_ipv6():
    """Publish mixed dynamically discovered IPv4 and IPv6 addresses."""
    contents = publish(event_with([]), ["198.51.100.9", "2001:db8::9"])
    assert address_lines(contents) == ["198.51.100.9/32", "2001:db8::9/128"]


def test_mixed_static_and_dynamic_addresses():
    """Publish different address families from static and dynamic sources."""
    contents = publish(event_with(["192.0.2.10"]), ["2001:db8::10"])
    assert address_lines(contents) == ["192.0.2.10/32", "2001:db8::10/128"]


def test_mixed_families_keep_ipv4_before_ipv6():
    """Render IPv4 networks before IPv6 networks for stable output."""
    contents = publish(event_with(["2001:db8::20", "192.0.2.20"]))
    assert address_lines(contents) == ["192.0.2.20/32", "2001:db8::20/128"]


def test_ipv4_only_still_collapses():
    """Preserve existing IPv4-only network collapsing."""
    contents = publish(event_with(["192.0.2.0/25", "192.0.2.128/25"]))
    assert address_lines(contents) == ["192.0.2.0/24"]


def test_ipv6_only_still_collapses():
    """Preserve existing IPv6-only network collapsing."""
    contents = publish(event_with(["2001:db8::/65", "2001:db8:0:0:8000::/65"]))
    assert address_lines(contents) == ["2001:db8::/64"]


def test_empty_address_set_still_publishes():
    """Preserve publication of a file when no addresses are present."""
    contents = publish(event_with([]))
    assert address_lines(contents) == []
