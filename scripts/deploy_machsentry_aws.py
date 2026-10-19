#!/usr/bin/env python3
"""Provision and operate the MachSentry analysis worker of the Unpacked pilot on AWS.

Designed for AWS CloudShell with the owner's session (Python 3.9+ and boto3);
it never asks for, stores or prints credentials. Every mutating command prints
what it will change first, and --dry-run stops there. Order of a first install:

  preflight, plan, deploy --yes, put-worker-token, site-params,
  associate-site-profile, release, bootstrap, site-env

A bootstrap or rollback tags the worker unpacked-analysis:maintenance while it
runs. When the operator process ends first (a closed CloudShell session), the
SSM command keeps running on the worker, and the next status, release,
bootstrap or rollback restores the CPU credits and removes the tag once that
command has ended.

deploy/worker/README.md is the operator guide; the Unpacked repository's
docs/ANALYSIS-SERVICE-CONTRACT.md (sections 1 and 9) is the specification.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = ROOT / "deploy/aws/worker.yaml"

ACCOUNT_ID = "835176962667"
DEFAULT_REGION = "us-east-2"
STACK_NAME = "unpacked-analysis"
PROJECT_TAG = {"Key": "Project", "Value": "unpacked-analysis"}
DEFAULT_BUCKET = "unpacked-analysis-835176962667-us-east-2"
SITE_INSTANCE_ID = "i-07c2e746122fe1b94"
SITE_PROFILE = "unpacked-site-analysis"
SITE_URL = "https://www.unpackedlab.com"
SSM_PREFIX = "/unpacked/analysis"
TOKEN_PARAMETER = SSM_PREFIX + "/worker/token"
SITE_URL_PARAMETER = SSM_PREFIX + "/worker/site-url"
RELEASE_PARAMETER = SSM_PREFIX + "/worker/release"
MODE_PARAMETER = SSM_PREFIX + "/worker/mode"
OPENAI_KEY_PARAMETER = SSM_PREFIX + "/openai/api-key"
OPENAI_MODEL_PARAMETER = SSM_PREFIX + "/openai/model"
OPENAI_MODEL = "gpt-5.4-mini-2026-03-17"
PARAMETER_NAMES = [TOKEN_PARAMETER, SITE_URL_PARAMETER, RELEASE_PARAMETER, MODE_PARAMETER, OPENAI_KEY_PARAMETER, OPENAI_MODEL_PARAMETER]
AMI_PARAMETER = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
CANONICAL_OWNER = "099720109477"
REPOSITORY_URL = "https://github.com/h4wk0x01/machsentry"
RELEASES_ROOT = "/opt/machsentry-worker/releases"
STATE_DIR = "/var/lib/machsentry-worker"
# Read by the site (it neither starts nor stops the worker while the tag is on) and by
# deploy/worker/maintenance-gate.py (the supervisor skips a boot while it is recent).
MAINTENANCE_TAG = "unpacked-analysis:maintenance"
# A tag without a finished SSM command counts as abandoned after this long: more than starting
# the instance and waiting for its SSM agent (900 s each). maintenance-gate.py uses the same age.
MAINTENANCE_START_SECONDS = 3600
EVENTS_SERVICE_ROLE = "AWSServiceRoleForCloudWatchEvents"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMPLETE_STACK_STATES = {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE"}
BROKEN_STACK_STATES = {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "DELETE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_ROLLBACK_FAILED"}
COMMAND_DONE = {"Success", "Cancelled", "TimedOut", "Failed"}
# Files a release must carry, and trees a git archive of the commit never contains.
RELEASE_REQUIRED = ("deploy/worker/bootstrap.sh", "deploy/worker/Dockerfile", "deploy/worker/maintenance-gate.py",
                    "scripts/machsentry_setup.py", "worker/requirements.lock.txt")
RELEASE_FORBIDDEN = ("amostras/", "reports/", ".tools/", ".venv-unpack/", "node_modules/", "dist/")

# Unpacked lib/config.ts: ANALYSIS_LIMITS.workerMonthlyHours and ANALYSIS_AI.monthLimitMicros.
WORKER_MONTHLY_HOURS = 40
AI_MONTH_LIMIT_USD = 3.0
# us-east-2 on-demand list prices in USD, checked on 2026-10-18 (EC2 price list
# published 2026-10-15). Confirm in the AWS Pricing Calculator before raising limits.
PRICES = {
    "ec2_hour": {"t3a.medium": 0.0376, "t3.medium": 0.0416, "t3a.large": 0.0752, "t3.large": 0.0832},
    "ipv4_hour": 0.005,
    "gp3_gb_month": 0.08,
    "alarm_month": 0.10,
    "s3_gb_month": 0.023,
    "unlimited_vcpu_hour": 0.05,
}


class DeployError(Exception):
    """A refusal or failure the operator can act on; printed without a traceback."""


class RemoteError(DeployError):
    """A remote script that failed; summary is its last JSON line, empty when it printed none."""

    def __init__(self, message: str, summary: dict) -> None:
        super().__init__(message)
        self.summary = summary


def error_code(error: BaseException) -> Optional[str]:
    """Code of a botocore ClientError (or a test double with the same shape)."""
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None


def boto3_client(name: str, region: str) -> Any:
    try:
        import boto3
        from botocore.config import Config
    except ImportError as error:
        raise DeployError("boto3 is required; AWS CloudShell has it, elsewhere run python3 -m pip install boto3") from error
    options: Dict[str, Any] = {"retries": {"max_attempts": 8, "mode": "standard"}}
    if name == "s3":
        options.update(signature_version="s3v4", s3={"addressing_style": "virtual"})
    return boto3.session.Session(region_name=region).client(name, region_name=region, config=Config(**options))


class Context:
    """Clients, clock and output of one command; tests replace every dependency."""

    def __init__(self, args: argparse.Namespace, clients: Optional[Callable[[str], Any]] = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 now: Optional[Callable[[], dt.datetime]] = None, run: Callable[..., Any] = subprocess.run,
                 out: Any = None, err: Any = None) -> None:
        self.args = args
        self.region = args.region
        self.stack_name = args.stack_name
        self.dry_run = getattr(args, "dry_run", False)
        self.sleep = sleep
        self.clock = clock
        self.now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self.run = run
        self.out = out or sys.stdout
        self.err = err or sys.stderr
        self._factory = clients
        self._clients: Dict[str, Any] = {}

    def client(self, name: str) -> Any:
        if name not in self._clients:
            self._clients[name] = self._factory(name) if self._factory else boto3_client(name, self.region)
        return self._clients[name]

    def say(self, text: str = "") -> None:
        print(text, file=self.out, flush=True)

    def warn(self, text: str) -> None:
        print(f"warning: {text}", file=self.err, flush=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def ensure_account(ctx: Context) -> dict:
    identity = ctx.client("sts").get_caller_identity()
    if identity.get("Account") != ACCOUNT_ID:
        raise DeployError(f"the AWS session belongs to account {identity.get('Account')}; this deployment is for {ACCOUNT_ID}")
    return identity


def describe_stack(ctx: Context) -> Optional[dict]:
    try:
        stacks = ctx.client("cloudformation").describe_stacks(StackName=ctx.stack_name)["Stacks"]
    except Exception as error:
        if error_code(error) == "ValidationError" and "does not exist" in str(error):
            return None
        raise
    return stacks[0] if stacks else None


def stack_outputs(ctx: Context) -> Dict[str, str]:
    stack = describe_stack(ctx)
    if stack is None:
        raise DeployError(f"stack {ctx.stack_name} does not exist; run plan and deploy first")
    if stack["StackStatus"] not in COMPLETE_STACK_STATES:
        raise DeployError(f"stack {ctx.stack_name} is {stack['StackStatus']}")
    return {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}


def parameter_value(ctx: Context, name: str, decrypt: bool = False) -> Optional[str]:
    try:
        return ctx.client("ssm").get_parameter(Name=name, WithDecryption=decrypt)["Parameter"]["Value"]
    except Exception as error:
        if error_code(error) == "ParameterNotFound":
            return None
        raise


def put_string_parameter(ctx: Context, name: str, value: str, exists: bool) -> None:
    ssm = ctx.client("ssm")
    if exists:
        ssm.put_parameter(Name=name, Value=value, Type="String", Overwrite=True)
    else:
        ssm.put_parameter(Name=name, Value=value, Type="String", Tags=[PROJECT_TAG])


def present_parameters(ctx: Context) -> List[str]:
    """Names only: values of SecureStrings are never read here."""
    ssm = ctx.client("ssm")
    found: List[str] = []
    request: Dict[str, Any] = {"ParameterFilters": [{"Key": "Name", "Option": "Equals", "Values": PARAMETER_NAMES}]}
    while True:
        page = ssm.describe_parameters(**request)
        found.extend(item["Name"] for item in page.get("Parameters", []))
        if not page.get("NextToken"):
            return found
        request["NextToken"] = page["NextToken"]


# --- EC2 and SSM plumbing -------------------------------------------------------


def describe_instance(ctx: Context, instance_id: str) -> dict:
    try:
        reservations = ctx.client("ec2").describe_instances(InstanceIds=[instance_id])["Reservations"]
    except Exception as error:
        if error_code(error) == "InvalidInstanceID.NotFound":
            raise DeployError(f"instance {instance_id} does not exist") from error
        raise
    instances = [item for reservation in reservations for item in reservation["Instances"]]
    if not instances:
        raise DeployError(f"instance {instance_id} does not exist")
    return instances[0]


def instance_state(ctx: Context, instance_id: str) -> str:
    return describe_instance(ctx, instance_id)["State"]["Name"]


def wait_instance_state(ctx: Context, instance_id: str, wanted: str, timeout: float = 900) -> None:
    deadline = ctx.clock() + timeout
    while True:
        state = instance_state(ctx, instance_id)
        if state == wanted:
            return
        if state in ("shutting-down", "terminated"):
            raise DeployError(f"instance {instance_id} is {state}")
        if ctx.clock() > deadline:
            raise DeployError(f"instance {instance_id} stayed {state} instead of {wanted}")
        ctx.sleep(10)


def start_instance(ctx: Context, instance_id: str) -> None:
    state = instance_state(ctx, instance_id)
    if state == "stopping":
        ctx.say(f"waiting for {instance_id} to finish stopping")
        wait_instance_state(ctx, instance_id, "stopped")
        state = "stopped"
    if state == "stopped":
        ctx.say(f"starting {instance_id}")
        ctx.client("ec2").start_instances(InstanceIds=[instance_id])
    elif state not in ("pending", "running"):
        raise DeployError(f"instance {instance_id} is {state}")
    wait_instance_state(ctx, instance_id, "running")
    ctx.say(f"{instance_id} is running")


def stop_instance(ctx: Context, instance_id: str) -> None:
    state = instance_state(ctx, instance_id)
    if state in ("stopped", "terminated"):
        return
    if state != "stopping":
        ctx.say(f"stopping {instance_id}")
        ctx.client("ec2").stop_instances(InstanceIds=[instance_id])
    wait_instance_state(ctx, instance_id, "stopped")
    ctx.say(f"{instance_id} is stopped")


def credit_specification(ctx: Context, instance_id: str) -> str:
    items = ctx.client("ec2").describe_instance_credit_specifications(InstanceIds=[instance_id])["InstanceCreditSpecifications"]
    return items[0]["CpuCredits"] if items else "unknown"


def set_credit_specification(ctx: Context, instance_id: str, credits: str) -> None:
    ctx.say(f"setting CPU credits of {instance_id} to {credits}")
    ctx.client("ec2").modify_instance_credit_specification(
        InstanceCreditSpecifications=[{"InstanceId": instance_id, "CpuCredits": credits}])


def run_cleanup(ctx: Context, steps: List[tuple]) -> bool:
    """Run every (label, action) even when an earlier one fails; True when all succeeded."""
    clean = True
    for label, action in steps:
        try:
            action()
        except Exception as error:
            clean = False
            ctx.warn(f"{label} failed: {error}")
    return clean


def format_maintenance(record: Dict[str, str]) -> str:
    """Tag value: the action, then key=value words (tag values allow letters, digits, spaces and _.:/=+-@).

    since is when the tag was set, command the SSM command once sent, credits the CPU credit
    specification to restore when the maintenance ends."""
    return " ".join([record["action"]] + [f"{key}={value}" for key, value in record.items() if key != "action"])


def parse_maintenance(value: str) -> Dict[str, str]:
    words = value.split()
    record = {"action": words[0] if words else "maintenance"}
    for word in words[1:]:
        key, separator, item = word.partition("=")
        if separator:
            record[key] = item
    return record


def parse_utc(value: Optional[str]) -> Optional[dt.datetime]:
    try:
        return dt.datetime.strptime(value or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def set_maintenance_tag(ctx: Context, instance_id: str, record: Dict[str, str]) -> None:
    ctx.client("ec2").create_tags(Resources=[instance_id], Tags=[{"Key": MAINTENANCE_TAG, "Value": format_maintenance(record)}])


def clear_maintenance_tag(ctx: Context, instance_id: str) -> None:
    ctx.client("ec2").delete_tags(Resources=[instance_id], Tags=[{"Key": MAINTENANCE_TAG}])


def command_status(ctx: Context, command_id: str, instance_id: str) -> Optional[str]:
    try:
        return ctx.client("ssm").get_command_invocation(CommandId=command_id, InstanceId=instance_id).get("Status")
    except Exception as error:
        if error_code(error) == "InvocationDoesNotExist":
            return None
        raise


def maintenance_busy(ctx: Context, instance_id: str, record: Dict[str, str]) -> Optional[str]:
    """Why the tagged bootstrap or rollback may still be running; None once its owner is gone."""
    command = record.get("command")
    if command:
        status = command_status(ctx, command, instance_id)
        if status is not None:
            return None if status in COMMAND_DONE else f"SSM command {command} is {status}"
    since = parse_utc(record.get("since"))
    if since is not None and (ctx.now() - since).total_seconds() < MAINTENANCE_START_SECONDS:
        return f"tagged at {record['since']}, its SSM command is not running yet"
    return None


def end_maintenance(ctx: Context, instance_id: str, record: Dict[str, str]) -> bool:
    """Restores what the record changed, then removes the tag. The tag stays while a restore
    fails, so the next status, release, bootstrap or rollback retries it."""
    if record.get("credits"):
        restore = ("restoring CPU credits", lambda: set_credit_specification(ctx, instance_id, record["credits"]))
        if not run_cleanup(ctx, [restore]):
            ctx.warn(f"{MAINTENANCE_TAG} stays on {instance_id} until the credits are restored")
            return False
    return run_cleanup(ctx, [("removing the maintenance tag", lambda: clear_maintenance_tag(ctx, instance_id))])


def recover_maintenance(ctx: Context, instance_id: str) -> Optional[str]:
    """Finishes the cleanup of a bootstrap or rollback whose operator process ended early (a
    CloudShell session closes after 20 to 30 idle minutes, and the SSM command keeps running).
    Returns why it waits while that command may still be running."""
    tags = {item["Key"]: item["Value"] for item in describe_instance(ctx, instance_id).get("Tags", [])}
    value = tags.get(MAINTENANCE_TAG)
    if value is None:
        return None
    record = parse_maintenance(value)
    busy = maintenance_busy(ctx, instance_id, record)
    if busy:
        return f"{record['action']} in progress on {instance_id}: {busy}"
    ctx.say(f"the {record['action']} tagged on {instance_id} ({value}) ended without its cleanup; finishing it:")
    if record.get("credits"):
        ctx.say(f"  restore {record['credits']} CPU credits")
    ctx.say(f"  remove the tag {MAINTENANCE_TAG}")
    if ctx.dry_run:
        return None
    if not end_maintenance(ctx, instance_id, record):
        raise DeployError("the interrupted cleanup is still incomplete; see the warnings above")
    return None


def wait_ssm_online(ctx: Context, instance_id: str, timeout: float = 900) -> None:
    launched = describe_instance(ctx, instance_id).get("LaunchTime")
    deadline = ctx.clock() + timeout
    while True:
        items = ctx.client("ssm").describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]).get("InstanceInformationList", [])
        info = items[0] if items else {}
        pinged = info.get("LastPingDateTime")
        if info.get("PingStatus") == "Online" and (launched is None or pinged is None or pinged >= launched):
            ctx.say(f"SSM agent on {instance_id} is online")
            return
        if ctx.clock() > deadline:
            raise DeployError(f"the SSM agent on {instance_id} did not come online")
        ctx.sleep(10)


def ssm_commands(script: str) -> List[str]:
    """AWS-RunShellScript runs its lines with sh; the bash script travels as base64."""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return [
        "set -eu",
        "script=$(mktemp /root/machsentry-ssm.XXXXXX)",
        f"printf '%s' '{encoded}' | base64 -d >\"$script\"",
        "status=0",
        "bash \"$script\" </dev/null || status=$?",
        "rm -f \"$script\"",
        "exit \"$status\"",
    ]


def send_script(ctx: Context, instance_id: str, script: str, timeout: int, comment: str) -> str:
    response = ctx.client("ssm").send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript", Comment=comment[:100], TimeoutSeconds=600,
        Parameters={"commands": ssm_commands(script), "executionTimeout": [str(timeout)]})
    command_id = response["Command"]["CommandId"]
    ctx.say(f"SSM command {command_id} sent to {instance_id}")
    return command_id


def wait_command(ctx: Context, command_id: str, instance_id: str, timeout: float) -> dict:
    deadline = ctx.clock() + timeout
    started = ctx.clock()
    last = None
    while True:
        try:
            invocation = ctx.client("ssm").get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except Exception as error:
            if error_code(error) != "InvocationDoesNotExist":
                raise
            invocation = {"Status": "Pending"}
        status = invocation.get("Status")
        if status != last:
            ctx.say(f"command {status} after {int(ctx.clock() - started)} s")
            last = status
        if status in COMMAND_DONE:
            return invocation
        if ctx.clock() > deadline:
            raise DeployError(f"SSM command {command_id} did not finish in {int(timeout)} s")
        ctx.sleep(15)


def last_json_line(text: str) -> Optional[dict]:
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    return None


def run_remote(ctx: Context, instance_id: str, script: str, timeout: int, comment: str,
               on_sent: Optional[Callable[[str], None]] = None) -> dict:
    """Send a bash script, wait, print its output and return its JSON summary."""
    command_id = send_script(ctx, instance_id, script, timeout, comment)
    if on_sent:
        on_sent(command_id)
    invocation = wait_command(ctx, command_id, instance_id, timeout + 300)
    output = invocation.get("StandardOutputContent", "")
    for line in output.strip().splitlines():
        ctx.say(f"  {line}")
    summary = last_json_line(output) or {}
    if invocation.get("Status") != "Success" or summary.get("ok") is False:
        errors = invocation.get("StandardErrorContent", "").strip()
        if errors:
            ctx.say("stderr:")
            for line in errors.splitlines()[-60:]:
                ctx.say(f"  {line}")
        raise RemoteError(f"remote command {command_id} ended {invocation.get('Status')}: {summary.get('error', 'see output above')}",
                          summary)
    return summary


# --- Discovery -------------------------------------------------------------------


def has_internet_route(subnet_id: str, tables: List[dict]) -> bool:
    explicit = [table for table in tables if any(item.get("SubnetId") == subnet_id for item in table.get("Associations", []))]
    main = [table for table in tables if any(item.get("Main") for item in table.get("Associations", []))]
    for table in explicit or main:
        for route in table.get("Routes", []):
            if (route.get("DestinationCidrBlock") == "0.0.0.0/0" and str(route.get("GatewayId", "")).startswith("igw-")
                    and route.get("State") != "blackhole"):
                return True
    return False


def discover_network(ctx: Context, vpc_id: Optional[str], subnet_id: Optional[str], instance_type: str) -> dict:
    """Default VPC and the first public subnet (Internet gateway route) whose zone offers the type."""
    ec2 = ctx.client("ec2")
    if subnet_id and not vpc_id:
        subnets = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"]
        if not subnets:
            raise DeployError(f"subnet {subnet_id} does not exist")
        vpc_id = subnets[0]["VpcId"]
    if not vpc_id:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
        if not vpcs:
            raise DeployError(f"{ctx.region} has no default VPC; pass --vpc-id and --subnet-id")
        vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    tables = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
    offerings = ec2.describe_instance_type_offerings(
        LocationType="availability-zone", Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]
    offered = {item["Location"] for item in offerings}
    candidates = []
    for subnet in sorted(subnets, key=lambda item: (item["AvailabilityZone"], item["SubnetId"])):
        if subnet_id and subnet["SubnetId"] != subnet_id:
            continue
        candidates.append({
            "subnetId": subnet["SubnetId"], "availabilityZone": subnet["AvailabilityZone"],
            "internetRoute": has_internet_route(subnet["SubnetId"], tables),
            "mapPublicIp": bool(subnet.get("MapPublicIpOnLaunch")), "offered": subnet["AvailabilityZone"] in offered,
        })
    usable = [item for item in candidates if item["offered"] and item["internetRoute"]]
    if not usable:
        usable = [item for item in candidates if item["offered"] and item["mapPublicIp"]]
        if usable:
            ctx.warn(f"no Internet gateway route found for {usable[0]['subnetId']}; it maps public IPs, check its routing")
    if not usable:
        wanted = f"subnet {subnet_id}" if subnet_id else f"a public subnet of {vpc_id}"
        raise DeployError(f"{wanted} in a zone that offers {instance_type} was not found")
    return {"vpcId": vpc_id, **usable[0]}


def resolve_ami(ctx: Context) -> dict:
    image_id = ctx.client("ssm").get_parameter(Name=AMI_PARAMETER)["Parameter"]["Value"]
    images = ctx.client("ec2").describe_images(ImageIds=[image_id])["Images"]
    image = images[0] if images else {}
    if image.get("OwnerId") != CANONICAL_OWNER or image.get("Architecture") != "x86_64":
        raise DeployError(f"{AMI_PARAMETER} resolved to {image_id}, which is not a Canonical x86_64 image")
    if image.get("RootDeviceName") != "/dev/sda1":
        raise DeployError(f"{image_id} uses root device {image.get('RootDeviceName')}; the template maps /dev/sda1")
    return {"imageId": image_id, "name": image.get("Name"), "created": image.get("CreationDate")}


def site_profile(ctx: Context) -> dict:
    instance = describe_instance(ctx, SITE_INSTANCE_ID)
    associations = ctx.client("ec2").describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [SITE_INSTANCE_ID]}])["IamInstanceProfileAssociations"]
    active = [item for item in associations if item.get("State") in ("associating", "associated")]
    arn = active[0]["IamInstanceProfile"]["Arn"] if active else None
    return {
        "state": instance["State"]["Name"], "profileArn": arn,
        "associationId": active[0]["AssociationId"] if active else None,
        "ours": bool(arn and arn.endswith("/" + SITE_PROFILE)),
        "httpTokens": instance.get("MetadataOptions", {}).get("HttpTokens"),
    }


def events_role_exists(ctx: Context) -> bool:
    try:
        ctx.client("iam").get_role(RoleName=EVENTS_SERVICE_ROLE)
        return True
    except Exception as error:
        if error_code(error) == "NoSuchEntity":
            return False
        raise


def bucket_status(ctx: Context, bucket: str) -> str:
    try:
        ctx.client("s3").head_bucket(Bucket=bucket)
        return "exists"
    except Exception as error:
        code = error_code(error)
        if code in ("404", "NoSuchBucket", "NotFound"):
            return "absent"
        if code in ("403", "AccessDenied"):
            return "owned by another account"
        raise


def account_budgets(ctx: Context) -> Optional[List[str]]:
    try:
        budgets = ctx.client("budgets").describe_budgets(AccountId=ACCOUNT_ID).get("Budgets", [])
    except Exception as error:
        if error_code(error) == "NotFoundException":
            return []
        return None
    return [f"{item['BudgetName']} ({item.get('BudgetLimit', {}).get('Amount', '?')} {item.get('BudgetLimit', {}).get('Unit', '')})"
            for item in budgets]


def cost_estimate(instance_type: str, volume_gb: int, hours: float, ai_cap_usd: float) -> List[tuple]:
    hourly = PRICES["ec2_hour"].get(instance_type)
    if hourly is None:
        raise DeployError(f"no price recorded for {instance_type}")
    return [
        (f"EC2 {instance_type}, {hours:g} h/month on demand", hourly * hours),
        (f"Public IPv4 while running, {hours:g} h", PRICES["ipv4_hour"] * hours),
        (f"EBS gp3 {volume_gb} GiB, billed while stopped too", PRICES["gp3_gb_month"] * volume_gb),
        ("CloudWatch idle alarm", PRICES["alarm_month"]),
        ("S3 standard, about 1 GB of releases and results", PRICES["s3_gb_month"]),
        ("AI stage, hard monthly cap (ANALYSIS_AI)", ai_cap_usd),
    ]


def print_costs(ctx: Context, rows: List[tuple], budget: Optional[float]) -> None:
    ctx.say("estimated monthly cost (USD, us-east-2 list prices of 2026-10-18):")
    for label, value in rows:
        ctx.say(f"  {label:<58} {value:8.2f}")
    total = sum(value for _, value in rows)
    ctx.say(f"  {'total':<58} {total:8.2f}")
    ctx.say("  SSM Parameter Store (standard), Run Command and the first 100 GB of transfer out are free.")
    ctx.say(f"  CPU credits switched to unlimited during a build cost up to US$ {PRICES['unlimited_vcpu_hour']:.2f} per vCPU-hour of surplus.")
    if budget is not None:
        ctx.say(f"  analysis share of the US$ {budget:g} account budget: {100 * total / budget:.0f} %")


# --- preflight -------------------------------------------------------------------


def cmd_preflight(ctx: Context) -> int:
    args = ctx.args
    identity = ensure_account(ctx)
    problems: List[str] = []
    ctx.say(f"account     {ACCOUNT_ID} ({identity.get('Arn')})")
    ctx.say(f"region      {ctx.region}")
    stack = describe_stack(ctx)
    status = stack["StackStatus"] if stack else "absent"
    ctx.say(f"stack       {ctx.stack_name}: {status}")
    if status in BROKEN_STACK_STATES or (status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS"):
        problems.append(f"stack {ctx.stack_name} is {status}")
    previous = {item["ParameterKey"]: item.get("ParameterValue") for item in (stack or {}).get("Parameters", [])}
    try:
        network = discover_network(ctx, args.vpc_id or previous.get("VpcId"), args.subnet_id or previous.get("SubnetId"), args.instance_type)
        ctx.say(f"network     {network['vpcId']} / {network['subnetId']} ({network['availabilityZone']}, "
                f"Internet route {'yes' if network['internetRoute'] else 'no'}, maps public IPv4 {'yes' if network['mapPublicIp'] else 'no'})")
        ctx.say(f"instance    {args.instance_type} offered in {network['availabilityZone']}")
    except DeployError as error:
        problems.append(str(error))
    ami = resolve_ami(ctx)
    ctx.say(f"ami         {ami['imageId']} {ami['name']} ({ami['created']})")
    if previous.get("AmiId") and previous["AmiId"] != ami["imageId"]:
        ctx.say(f"            the stack keeps {previous['AmiId']}; plan --refresh-ami would replace the worker instance")
    bucket = previous.get("BucketName") or DEFAULT_BUCKET
    state = bucket_status(ctx, bucket)
    ctx.say(f"bucket      {bucket}: {state}")
    if state == "owned by another account" or (state == "exists" and stack is None):
        problems.append(f"bucket {bucket} already exists outside this stack; choose --bucket-name or import it")
    try:
        site = site_profile(ctx)
        profile = site["profileArn"] or "none"
        ctx.say(f"site        {SITE_INSTANCE_ID}: {site['state']}, instance profile {profile}, IMDS tokens {site['httpTokens']}")
        if site["profileArn"] and not site["ours"]:
            ctx.warn(f"the site instance already uses {site['profileArn']}; associate-site-profile will refuse to replace it")
    except DeployError as error:
        problems.append(str(error))
    present = set(present_parameters(ctx))
    for name in PARAMETER_NAMES:
        ctx.say(f"parameter   {name}: {'present' if name in present else 'missing'}")
    if OPENAI_KEY_PARAMETER not in present:
        ctx.say(f"            create {OPENAI_KEY_PARAMETER} (SecureString) yourself in the Systems Manager console")
    ctx.say(f"alarm role  {EVENTS_SERVICE_ROLE}: {'present' if events_role_exists(ctx) else 'missing (deploy creates it)'}")
    budgets = account_budgets(ctx)
    ctx.say("budgets     " + ("unknown (no budgets:ViewBudget)" if budgets is None else ", ".join(budgets) or "none"))
    print_costs(ctx, cost_estimate(args.instance_type, args.volume_size, args.worker_hours, args.ai_cap_usd), args.budget_limit)
    if problems:
        for problem in problems:
            ctx.say(f"problem: {problem}")
        return 1
    ctx.say("preflight passed; next: plan")
    return 0


# --- plan and deploy -------------------------------------------------------------


def stack_parameters(ctx: Context, stack: Optional[dict]) -> List[dict]:
    """Explicit flags win, then the stack's previous values, then discovery or template defaults."""
    args = ctx.args
    previous = {}
    if stack and stack["StackStatus"] != "REVIEW_IN_PROGRESS":  # a CREATE change set takes no previous values
        previous = {item["ParameterKey"]: item.get("ParameterValue") for item in stack.get("Parameters", [])}
    values: Dict[str, Optional[str]] = {
        "SiteOrigin": args.site_origin, "InstanceType": args.instance_type,
        "VolumeSize": None if args.volume_size is None else str(args.volume_size),
        "BucketName": args.bucket_name, "BudgetLimitUsd": None if args.budget_limit is None else f"{args.budget_limit:g}",
        "VpcId": args.vpc_id, "SubnetId": args.subnet_id, "AmiId": args.ami_id,
        "CreateBudget": None, "BudgetEmail": None,
    }
    if args.budget_email:
        values.update(CreateBudget="true", BudgetEmail=args.budget_email)
    elif args.no_budget:
        values.update(CreateBudget="false", BudgetEmail="")
    network_given = bool(values["VpcId"] or values["SubnetId"])
    if (network_given or "SubnetId" not in previous) and not (values["VpcId"] and values["SubnetId"]):
        instance_type = args.instance_type or previous.get("InstanceType") or "t3a.medium"
        network = discover_network(ctx, values["VpcId"], values["SubnetId"], instance_type)
        values["VpcId"], values["SubnetId"] = network["vpcId"], network["subnetId"]
    if not values["AmiId"] and (args.refresh_ami or "AmiId" not in previous):
        values["AmiId"] = resolve_ami(ctx)["imageId"]
    parameters = []
    for key, value in values.items():
        if value is not None:
            parameters.append({"ParameterKey": key, "ParameterValue": value})
        elif key in previous:
            parameters.append({"ParameterKey": key, "UsePreviousValue": True})
    return parameters


def check_stack_state(stack: Optional[dict]) -> None:
    status = stack["StackStatus"] if stack else None
    if status in BROKEN_STACK_STATES:
        raise DeployError(f"stack is {status}; inspect its events, then run destroy --confirm-destroy before deploying again")
    if status and status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        raise DeployError(f"stack is {status}; wait for it to finish")


def create_change_set(ctx: Context, stack: Optional[dict], parameters: List[dict]) -> Optional[dict]:
    cfn = ctx.client("cloudformation")
    change_type = "CREATE" if stack is None or stack["StackStatus"] == "REVIEW_IN_PROGRESS" else "UPDATE"
    name = f"{ctx.stack_name}-{ctx.now().strftime('%Y%m%d%H%M%S')}"
    template = Path(ctx.args.template).read_text(encoding="utf-8")
    cfn.create_change_set(
        StackName=ctx.stack_name, ChangeSetName=name, ChangeSetType=change_type, TemplateBody=template,
        Parameters=parameters, Capabilities=["CAPABILITY_NAMED_IAM"], Tags=[PROJECT_TAG],
        Description="scripts/deploy_machsentry_aws.py")
    deadline = ctx.clock() + 600
    while True:
        described = cfn.describe_change_set(StackName=ctx.stack_name, ChangeSetName=name)
        if described["Status"] in ("CREATE_COMPLETE", "FAILED"):
            break
        if ctx.clock() > deadline:
            raise DeployError(f"change set {name} is still {described['Status']}")
        ctx.sleep(5)
    if described["Status"] == "FAILED":
        reason = described.get("StatusReason", "")
        discard_change_set(ctx, name, change_type)
        if "didn't contain changes" in reason or "No updates are to be performed" in reason:
            return None
        raise DeployError(f"change set {name} failed: {reason}")
    changes = list(described.get("Changes", []))
    while described.get("NextToken"):
        described = cfn.describe_change_set(StackName=ctx.stack_name, ChangeSetName=name, NextToken=described["NextToken"])
        changes.extend(described.get("Changes", []))
    return {"name": name, "type": change_type, "changes": [item["ResourceChange"] for item in changes if "ResourceChange" in item]}


def discard_change_set(ctx: Context, name: str, change_type: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_change_set(StackName=ctx.stack_name, ChangeSetName=name)
    if change_type == "CREATE":
        # A CREATE change set leaves an empty REVIEW_IN_PROGRESS stack behind.
        cfn.delete_stack(StackName=ctx.stack_name)


def print_parameters(ctx: Context, parameters: List[dict]) -> None:
    ctx.say("parameters:")
    for item in parameters:
        value = "(previous value)" if item.get("UsePreviousValue") else item["ParameterValue"]
        ctx.say(f"  {item['ParameterKey']:<16} {value}")


def print_changes(ctx: Context, change: dict) -> bool:
    ctx.say(f"change set {change['name']} ({change['type']}):")
    replaces_worker = False
    for item in change["changes"]:
        replacement = item.get("Replacement")
        note = f" replacement={replacement}" if item.get("Action") == "Modify" else ""
        ctx.say(f"  {str(item.get('Action')):<7} {str(item.get('ResourceType')):<28} {item.get('LogicalResourceId')}{note}")
        if item.get("LogicalResourceId") == "WorkerInstance" and item.get("Action") == "Modify" and replacement in ("True", "Conditional"):
            replaces_worker = True
    if replaces_worker:
        ctx.say("  the worker instance would be replaced: its id changes and the site env must follow (site-env)")
    return replaces_worker


def plan_change(ctx: Context) -> tuple:
    ensure_account(ctx)
    stack = describe_stack(ctx)
    check_stack_state(stack)
    parameters = stack_parameters(ctx, stack)
    print_parameters(ctx, parameters)
    change = create_change_set(ctx, stack, parameters)
    if change is None:
        ctx.say("no changes: the stack already matches the template and parameters")
        return None, False
    return change, print_changes(ctx, change)


def cmd_plan(ctx: Context) -> int:
    change, _ = plan_change(ctx)
    if change is None:
        return 0
    if ctx.args.keep:
        ctx.say(f"kept change set {change['name']}; deploy creates a fresh one")
    else:
        discard_change_set(ctx, change["name"], change["type"])
        ctx.say("change set discarded (plan never executes)")
    return 0


def wait_stack(ctx: Context, since: dt.datetime, timeout: float = 2700) -> dict:
    cfn = ctx.client("cloudformation")
    deadline = ctx.clock() + timeout
    seen = set()
    while True:
        try:
            events = cfn.describe_stack_events(StackName=ctx.stack_name).get("StackEvents", [])
        except Exception as error:
            if error_code(error) != "ValidationError":
                raise
            events = []  # the stack is gone (destroy)
        for event in reversed(events):
            if event["EventId"] in seen or event["Timestamp"] < since:
                continue
            seen.add(event["EventId"])
            reason = f" {event['ResourceStatusReason']}" if event.get("ResourceStatusReason") else ""
            ctx.say(f"  {event['LogicalResourceId']:<24} {event['ResourceStatus']}{reason}")
        stack = describe_stack(ctx)
        status = stack["StackStatus"] if stack else "DELETE_COMPLETE"
        if not status.endswith("_IN_PROGRESS"):
            return {"StackStatus": status, **(stack or {})}
        if ctx.clock() > deadline:
            raise DeployError(f"stack still {status} after {int(timeout)} s")
        ctx.sleep(15)


def ensure_events_role(ctx: Context) -> None:
    if events_role_exists(ctx):
        return
    ctx.say(f"creating service-linked role {EVENTS_SERVICE_ROLE}, which CloudWatch needs for the alarm's EC2 stop action")
    ctx.client("iam").create_service_linked_role(AWSServiceName="events.amazonaws.com")


def cmd_deploy(ctx: Context) -> int:
    args = ctx.args
    change, replaces_worker = plan_change(ctx)
    if change is None:
        return 0
    if ctx.dry_run or not args.yes:
        discard_change_set(ctx, change["name"], change["type"])
        if ctx.dry_run:
            ctx.say("dry run: change set discarded")
            return 0
        raise DeployError("review the change set above and run deploy again with --yes to execute it")
    if replaces_worker and not args.allow_worker_replacement:
        discard_change_set(ctx, change["name"], change["type"])
        raise DeployError("this change replaces the worker instance; pass --allow-worker-replacement as well")
    ensure_events_role(ctx)
    since = ctx.now() - dt.timedelta(seconds=5)
    ctx.say(f"executing change set {change['name']}")
    ctx.client("cloudformation").execute_change_set(StackName=ctx.stack_name, ChangeSetName=change["name"])
    result = wait_stack(ctx, since)
    if result["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
        raise DeployError(f"stack ended {result['StackStatus']}")
    ctx.say(f"stack {ctx.stack_name}: {result['StackStatus']}")
    for item in result.get("Outputs", []):
        ctx.say(f"  {item['OutputKey']:<24} {item['OutputValue']}")
    if change["type"] == "CREATE":
        ctx.say("the new worker instance is running until bootstrap stops it (the idle alarm stops it after 15 min otherwise)")
        ctx.say("next: put-worker-token, site-params, associate-site-profile, release, bootstrap")
    return 0


# --- parameters and site profile -------------------------------------------------


def cmd_put_worker_token(ctx: Context) -> int:
    ensure_account(ctx)
    existing = parameter_value(ctx, TOKEN_PARAMETER, decrypt=True)
    if existing is not None and not ctx.args.rotate:
        ctx.say(f"{TOKEN_PARAMETER} exists and stays as is (--rotate replaces it)")
        ctx.say(f"ANALYSIS_WORKER_TOKEN_SHA256={sha256_text(existing)}")
        return 0
    action = "replace" if existing is not None else "create"
    ctx.say(f"will {action} SecureString {TOKEN_PARAMETER}: 32 random bytes, base64url; the value is never printed")
    if ctx.dry_run:
        return 0
    token = secrets.token_urlsafe(32)
    ssm = ctx.client("ssm")
    if existing is None:
        ssm.put_parameter(Name=TOKEN_PARAMETER, Value=token, Type="SecureString", Tags=[PROJECT_TAG],
                          Description="Unpacked analysis worker bearer token")
    else:
        ssm.put_parameter(Name=TOKEN_PARAMETER, Value=token, Type="SecureString", Overwrite=True)
    ctx.say(f"ANALYSIS_WORKER_TOKEN_SHA256={sha256_text(token)}")
    if existing is not None:
        ctx.say("put the new hash in the site env and restart the site; the worker reads the token when it starts")
    return 0


def cmd_site_params(ctx: Context) -> int:
    args = ctx.args
    ensure_account(ctx)
    if not re.match(r"^https://[a-z0-9.-]+(:[0-9]+)?$", args.site_url):
        raise DeployError("--site-url must be an https origin without a path")
    plan = []
    for name, wanted, replace in ((SITE_URL_PARAMETER, args.site_url, True), (MODE_PARAMETER, "active", False),
                                  (OPENAI_MODEL_PARAMETER, args.model, True)):
        current = parameter_value(ctx, name)
        if current == wanted or (current is not None and not replace):
            ctx.say(f"unchanged {name} = {current}")
            continue
        ctx.say(f"{'update' if current is not None else 'create'} {name}: {current} -> {wanted}")
        plan.append((name, wanted, current is not None))
    if ctx.dry_run:
        return 0
    for name, wanted, exists in plan:
        put_string_parameter(ctx, name, wanted, exists)
    if plan:
        ctx.say("parameters written")
    return 0


def cmd_associate_site_profile(ctx: Context) -> int:
    ensure_account(ctx)
    site = site_profile(ctx)
    if site["ours"]:
        ctx.say(f"{SITE_INSTANCE_ID} already uses {SITE_PROFILE}")
        return 0
    if site["profileArn"]:
        raise DeployError(f"{SITE_INSTANCE_ID} already uses {site['profileArn']}; refusing to replace it. "
                          "Add the analysis statements to that role or detach it yourself first")
    profile = ctx.client("iam").get_instance_profile(InstanceProfileName=SITE_PROFILE)["InstanceProfile"]
    ctx.say(f"will associate instance profile {profile['Arn']} with the site instance {SITE_INSTANCE_ID} ({site['state']})")
    if ctx.dry_run:
        return 0
    ctx.client("ec2").associate_iam_instance_profile(IamInstanceProfile={"Name": SITE_PROFILE}, InstanceId=SITE_INSTANCE_ID)
    ctx.say("associated; the site's AWS SDK reads these credentials from IMDS, no restart needed")
    return 0


# --- release ---------------------------------------------------------------------


def git(ctx: Context, repo: Path, *arguments: str) -> str:
    result = ctx.run(["git", "-C", str(repo), *arguments], capture_output=True, text=True)
    if result.returncode != 0:
        raise DeployError(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def check_archive(path: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        names = {member.name[2:] if member.name.startswith("./") else member.name for member in archive.getmembers()}
    missing = [name for name in RELEASE_REQUIRED if name not in names]
    if missing:
        raise DeployError(f"the commit lacks {', '.join(missing)}")
    forbidden = sorted(name for name in names if name.startswith(RELEASE_FORBIDDEN) and name not in ("amostras/", "amostras/README.md"))
    if forbidden:
        raise DeployError(f"the archive contains {forbidden[0]}; samples, reports and local runtimes never go into a release")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cmd_release(ctx: Context) -> int:
    args = ctx.args
    ensure_account(ctx)
    outputs = stack_outputs(ctx)
    bucket = outputs["BucketName"]
    pending = recover_maintenance(ctx, outputs["WorkerInstanceId"])
    if pending:
        ctx.say(f"note: {pending}; it keeps the release it started with")
    with tempfile.TemporaryDirectory(prefix="machsentry-release-") as scratch:
        if args.repo:
            repo = Path(args.repo).resolve()
        else:
            repo = Path(scratch) / "machsentry"
            ctx.say(f"cloning {REPOSITORY_URL}")
            result = ctx.run(["git", "clone", "--quiet", "--no-checkout", REPOSITORY_URL, str(repo)], capture_output=True, text=True)
            if result.returncode != 0:
                raise DeployError(f"git clone failed: {result.stderr.strip()}")
        resolved = ctx.run(["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{args.commit}^{{commit}}"],
                           capture_output=True, text=True)
        commit = resolved.stdout.strip()
        if resolved.returncode != 0 or not COMMIT_PATTERN.match(commit):
            source = args.repo or REPOSITORY_URL
            raise DeployError(f"{args.commit} is not a commit of {source}; push it or pass --repo with a clone that has it")
        subject = git(ctx, repo, "log", "-1", "--format=%s", commit)
        archive = Path(scratch) / f"machsentry-{commit}.tar.gz"
        git(ctx, repo, "archive", "--format=tar.gz", "-o", str(archive), commit)
        check_archive(archive)
        digest = file_sha256(archive)
        key = f"releases/machsentry-{commit}.tar.gz"
        record = {"commit": commit, "s3Key": key, "sha256": digest}
        ctx.say(f"release {commit} {subject}")
        ctx.say(f"  archive  {archive.stat().st_size} bytes, sha256 {digest}")
        ctx.say(f"  upload   s3://{bucket}/{key}")
        ctx.say(f"  record   {RELEASE_PARAMETER} = {json.dumps(record)}")
        if ctx.dry_run:
            return 0
        s3 = ctx.client("s3")
        try:
            uploaded = s3.head_object(Bucket=bucket, Key=key).get("Metadata", {}).get("sha256")
        except Exception as error:
            if error_code(error) not in ("404", "NoSuchKey", "NotFound"):
                raise
            uploaded = None
        if uploaded == digest:
            ctx.say("  the same archive is already uploaded")
        else:
            with archive.open("rb") as body:
                s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/gzip",
                              ChecksumSHA256=base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
                              Metadata={"sha256": digest, "commit": commit})
            ctx.say("  uploaded")
    current = parameter_value(ctx, RELEASE_PARAMETER)
    put_string_parameter(ctx, RELEASE_PARAMETER, json.dumps(record, separators=(",", ":")), current is not None)
    ctx.say(f"next: bootstrap installs {commit[:12]} on the worker")
    return 0


# --- worker operations -----------------------------------------------------------

# Downloads and unpacks the release, then hands over to its bootstrap.sh. It stops
# nothing: bootstrap.sh checks for a job in progress before it touches the units.
BOOTSTRAP_SCRIPT = r"""set -euo pipefail
commit=@COMMIT@
sha256=@SHA256@
url=@URL@
releases=@RELEASES@
state=@STATE@
release=$releases/$commit
incoming=''
step='preparing the release directory'
message=''
fail() {
  message=$1
  exit 1
}
on_exit() {
  local status=$? running=false
  [ -z "$incoming" ] || rm -rf "$incoming"
  [ "$status" -ne 0 ] || return 0
  if systemctl is-active --quiet machsentry-supervisor.service 2>/dev/null; then
    running=true
  fi
  python3 -c 'import json, sys; print(json.dumps({"ok": False, "action": "bootstrap", "stage": "download", "error": sys.argv[1], "exitStatus": int(sys.argv[2]), "supervisorRunning": sys.argv[3] == "true"}))' \
    "${message:-$step failed (exit $status)}" "$status" "$running"
}
trap on_exit EXIT
install -d -m 0755 "$(dirname "$releases")" "$releases"
install -d -m 0750 "$state"
# bootstrap.sh takes this lock again; holding it here keeps a second run from
# replacing the release directory that a first one builds from.
exec 9>"$state/bootstrap.lock"
flock -n 9 || fail "another bootstrap.sh run holds $state/bootstrap.lock"
if [ "$(cat "$release.sha256" 2>/dev/null || true)" != "$sha256" ] || [ ! -f "$release/deploy/worker/bootstrap.sh" ]; then
  step='downloading the release archive'
  incoming=$(mktemp -d "$releases/.incoming-XXXXXX")
  python3 - "$url" "$incoming/release.tar.gz" "$sha256" <<'PY'
import hashlib
import sys
import urllib.request

url, target, expected = sys.argv[1:4]
digest = hashlib.sha256()
with urllib.request.urlopen(url, timeout=120) as response, open(target, "wb") as output:
    for chunk in iter(lambda: response.read(1 << 20), b""):
        digest.update(chunk)
        output.write(chunk)
if digest.hexdigest() != expected:
    sys.exit("release archive sha256 mismatch: " + digest.hexdigest())
PY
  step='unpacking the release archive'
  mkdir "$incoming/source"
  tar -xzf "$incoming/release.tar.gz" -C "$incoming/source" --no-same-owner
  rm -rf "$release"
  mv "$incoming/source" "$release"
  printf '%s\n' "$sha256" >"$release.sha256"
  rm -rf "$incoming"
  incoming=''
  echo "release $commit unpacked at $release"
fi
exec 9>&-
trap - EXIT
exec bash "$release/deploy/worker/bootstrap.sh" --release-dir "$release" --commit "$commit" --region @REGION@ @EXTRA@ </dev/null
"""

ROLLBACK_SCRIPT = r"""set -euo pipefail
commit=$(python3 -c 'import json; print(json.load(open("/etc/machsentry-worker/release.json"))["commit"])')
exec bash "@RELEASES@/$commit/deploy/worker/bootstrap.sh" --rollback </dev/null
"""


def fill(template: str, **values: str) -> str:
    for key, value in values.items():
        template = template.replace(f"@{key}@", value)
    return template


def read_release(ctx: Context) -> dict:
    raw = parameter_value(ctx, RELEASE_PARAMETER)
    if raw is None:
        raise DeployError(f"{RELEASE_PARAMETER} is missing; run release first")
    release = json.loads(raw)
    if not COMMIT_PATTERN.match(str(release.get("commit"))) or not SHA256_PATTERN.match(str(release.get("sha256"))):
        raise DeployError(f"{RELEASE_PARAMETER} is malformed: {raw}")
    if release.get("s3Key") != f"releases/machsentry-{release['commit']}.tar.gz":
        raise DeployError(f"{RELEASE_PARAMETER} names an unexpected key: {release.get('s3Key')}")
    return release


def begin_maintenance(ctx: Context, instance_id: str, action: str, **record: str) -> Dict[str, str]:
    """Tags the worker before anything changes, so the site holds off, the supervisor skips
    the boot that start_instance causes, and a later command can finish an interrupted cleanup."""
    record = {"action": action, **record, "since": ctx.now().strftime("%Y-%m-%dT%H:%M:%SZ")}
    set_maintenance_tag(ctx, instance_id, record)
    return record


def note_command(ctx: Context, instance_id: str, record: Dict[str, str], command_id: str) -> None:
    """Adds the SSM command to the tag; recover_maintenance waits for it to end."""
    record["command"] = command_id
    try:
        set_maintenance_tag(ctx, instance_id, record)
    except Exception as error:
        ctx.warn(f"recording {command_id} in {MAINTENANCE_TAG} failed: {error}")


def finish_worker_command(ctx: Context, instance_id: str, record: Dict[str, str], *, succeeded: bool, sent: bool,
                          was_running: bool, supervisor_running: bool, keep_on_failure: bool) -> bool:
    """Stops the worker unless it must stay on, then ends the maintenance; True when all of it succeeded.

    After a success the new units start at the next boot, so the instance stops either way."""
    reason = None
    if not succeeded:
        if supervisor_running:
            reason = "stays on: the remote script stopped nothing and the supervisor stops the instance when idle"
        elif not sent and was_running:
            reason = "stays on as it was: nothing reached the worker"
        elif keep_on_failure:
            reason = "left running for inspection; the idle alarm stops it after 15 min below 2 % CPU"
    stopped = True
    if reason:
        ctx.say(f"{instance_id} {reason}")
    else:
        stopped = run_cleanup(ctx, [("stopping the worker", lambda: stop_instance(ctx, instance_id))])
    ended = end_maintenance(ctx, instance_id, record)
    return stopped and ended


def run_on_worker(ctx: Context, instance_id: str, record: Dict[str, str], script: Callable[[], str], timeout: int,
                  comment: str, *, was_running: bool, keep_on_failure: bool = False) -> bool:
    """Starts the worker, runs a bootstrap.sh mode through SSM and finishes the maintenance.
    Returns whether the cleanup succeeded; a remote failure raises after the cleanup."""
    succeeded = sent = supervisor_running = False

    def sent_command(command_id: str) -> None:
        nonlocal sent
        sent = True
        note_command(ctx, instance_id, record, command_id)

    try:
        # A record that names credits to restore asked for unlimited ones during the run.
        if record.get("credits"):
            set_credit_specification(ctx, instance_id, "unlimited")
        start_instance(ctx, instance_id)
        wait_ssm_online(ctx, instance_id)
        try:
            summary = run_remote(ctx, instance_id, script(), timeout, comment, on_sent=sent_command)
        except RemoteError as error:
            supervisor_running = error.summary.get("supervisorRunning") is True
            raise
        ctx.say(json.dumps(summary, indent=2))
        succeeded = True
    finally:
        clean = finish_worker_command(ctx, instance_id, record, succeeded=succeeded, sent=sent, was_running=was_running,
                                      supervisor_running=supervisor_running, keep_on_failure=keep_on_failure)
    return clean


def cmd_bootstrap(ctx: Context) -> int:
    args = ctx.args
    ensure_account(ctx)
    outputs = stack_outputs(ctx)
    instance_id, bucket = outputs["WorkerInstanceId"], outputs["BucketName"]
    release = read_release(ctx)
    pending = recover_maintenance(ctx, instance_id)
    if pending:
        raise DeployError(f"{pending}; wait for it to end, then run bootstrap again")
    state = instance_state(ctx, instance_id)
    credits = credit_specification(ctx, instance_id)
    switch_credits = args.unlimited_during_build and credits != "unlimited"
    extra = [flag for flag, wanted in (("--rebuild", args.rebuild), ("--force", args.force)) if wanted]
    ctx.say(f"bootstrap {release['commit']} on {instance_id} ({state}, CPU credits {credits})")
    ctx.say(f"  tag {MAINTENANCE_TAG} while it runs; start the instance if stopped; wait for SSM")
    if switch_credits:
        ctx.say("  CPU credits unlimited during the build, standard again afterwards")
    ctx.say(f"  download s3://{bucket}/{release['s3Key']} through a 1-hour presigned URL, check sha256 {release['sha256']}")
    ctx.say(f"  run {' '.join(['deploy/worker/bootstrap.sh', *extra])} from {RELEASES_ROOT}/{release['commit']}, then stop the instance")
    if state == "running":
        ctx.warn("the worker is running: the bootstrap refuses while a job is in progress (--force ends that attempt as "
                 "worker_lost); run drain or pause admissions on the site first")
    if ctx.dry_run:
        return 0
    restore = {"credits": "standard"} if switch_credits else {}
    record = begin_maintenance(ctx, instance_id, "bootstrap", commit=release["commit"][:12], **restore)

    def script() -> str:
        url = ctx.client("s3").generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": release["s3Key"]}, ExpiresIn=3600)
        return fill(BOOTSTRAP_SCRIPT, COMMIT=release["commit"], SHA256=release["sha256"], URL=shlex.quote(url),
                    RELEASES=RELEASES_ROOT, STATE=STATE_DIR, REGION=shlex.quote(ctx.region), EXTRA=" ".join(extra))

    if not run_on_worker(ctx, instance_id, record, script, args.timeout, f"machsentry bootstrap {release['commit'][:12]}",
                         was_running=state in ("pending", "running"), keep_on_failure=args.keep_running_on_failure):
        raise DeployError("the release is installed but a cleanup step failed; see the warnings above and run status")
    return 0


def cmd_rollback(ctx: Context) -> int:
    args = ctx.args
    ensure_account(ctx)
    instance_id = stack_outputs(ctx)["WorkerInstanceId"]
    pending = recover_maintenance(ctx, instance_id)
    if pending:
        raise DeployError(f"{pending}; wait for it to end, then run rollback again")
    state = instance_state(ctx, instance_id)
    ctx.say(f"rollback on {instance_id} ({state}): machsentry-analyzer:previous becomes :current, release.json swaps; "
            "the instance stops and the rolled-back release starts at its next boot")
    if ctx.dry_run:
        return 0
    record = begin_maintenance(ctx, instance_id, "rollback")
    if not run_on_worker(ctx, instance_id, record, lambda: fill(ROLLBACK_SCRIPT, RELEASES=RELEASES_ROOT), args.timeout,
                         "machsentry rollback", was_running=state in ("pending", "running")):
        raise DeployError("the rollback finished but a cleanup step failed; see the warnings above and run status")
    ctx.say(f"{RELEASE_PARAMETER} still names the newer upload; run release with the commit you keep")
    return 0


def cmd_status(ctx: Context) -> int:
    ensure_account(ctx)
    stack = describe_stack(ctx)
    ctx.say(f"stack       {ctx.stack_name}: {stack['StackStatus'] if stack else 'absent'}")
    if not stack:
        return 0
    outputs = {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}
    for key, value in sorted(outputs.items()):
        ctx.say(f"  {key:<24} {value}")
    instance_id = outputs.get("WorkerInstanceId")
    if instance_id:
        pending = recover_maintenance(ctx, instance_id)
        instance = describe_instance(ctx, instance_id)
        tags = {item["Key"]: item["Value"] for item in instance.get("Tags", [])}
        ctx.say(f"worker      {instance_id}: {instance['State']['Name']}, {instance.get('InstanceType')}, "
                f"CPU credits {credit_specification(ctx, instance_id)}, launched {instance.get('LaunchTime')}")
        if MAINTENANCE_TAG in tags:
            ctx.say(f"maintenance {tags[MAINTENANCE_TAG]}")
        if pending:
            ctx.say(f"            {pending}")
        commands = ctx.client("ssm").list_commands(InstanceId=instance_id, MaxResults=1).get("Commands", [])
        if commands:
            last = commands[0]
            ctx.say(f"last cmd    {last['CommandId']} {last.get('Comment', '')}: {last.get('Status')} at {last.get('RequestedDateTime')}")
    ctx.say(f"release     {parameter_value(ctx, RELEASE_PARAMETER)}")
    ctx.say(f"mode        {parameter_value(ctx, MODE_PARAMETER)}")
    return 0


def cmd_logs(ctx: Context) -> int:
    args = ctx.args
    ensure_account(ctx)
    instance_id = stack_outputs(ctx)["WorkerInstanceId"]
    state = instance_state(ctx, instance_id)
    if state != "running":
        ctx.say(f"{instance_id} is {state}; journald keeps 7 days on its disk and is readable the next time it runs")
        return 0
    script = (f"journalctl --no-pager -o short-iso -u machsentry-supervisor.service -u machsentry-watchdog.service "
              f"--since {shlex.quote(args.since)} | tail -n {int(args.lines)}\n"
              "echo '--- /var/log/machsentry-worker'\nls -1t /var/log/machsentry-worker 2>/dev/null | head -n 10\n")
    command_id = send_script(ctx, instance_id, script, 300, "machsentry logs")
    invocation = wait_command(ctx, command_id, instance_id, 600)
    ctx.say(invocation.get("StandardOutputContent", "").rstrip())
    return 0 if invocation.get("Status") == "Success" else 1


def set_mode(ctx: Context, mode: str) -> int:
    ensure_account(ctx)
    current = parameter_value(ctx, MODE_PARAMETER)
    if current == mode:
        ctx.say(f"{MODE_PARAMETER} is already {mode}")
        return 0
    ctx.say(f"{MODE_PARAMETER}: {current} -> {mode}")
    if ctx.dry_run:
        return 0
    put_string_parameter(ctx, MODE_PARAMETER, mode, current is not None)
    if mode == "drain":
        ctx.say("the worker finishes its current job and claims no new one; pause admissions on the site as well")
    return 0


def cmd_site_env(ctx: Context) -> int:
    ensure_account(ctx)
    outputs = stack_outputs(ctx)
    token = parameter_value(ctx, TOKEN_PARAMETER, decrypt=True)
    if token is None:
        raise DeployError(f"{TOKEN_PARAMETER} is missing; run put-worker-token first")
    digest = sha256_text(token)
    del token
    ctx.say("# Lines for /srv/unpacked/shared/env (./scripts/deploy.sh --env), then redeploy:")
    ctx.say("# ANALYSIS_BUCKET is read at build time for the CSP connect-src.")
    ctx.say("ANALYSIS_SERVICE=aws")
    ctx.say(f"ANALYSIS_AWS_REGION={ctx.region}")
    ctx.say(f"ANALYSIS_BUCKET={outputs['BucketName']}")
    ctx.say(f"ANALYSIS_WORKER_INSTANCE_ID={outputs['WorkerInstanceId']}")
    ctx.say(f"ANALYSIS_WORKER_TOKEN_SHA256={digest}")
    ctx.say("# ANALYSIS_RECONCILE_TOKEN is generated on the site itself (openssl rand -hex 32) and never stored in AWS.")
    return 0


def cmd_destroy(ctx: Context) -> int:
    ensure_account(ctx)
    stack = describe_stack(ctx)
    if stack is None:
        ctx.say(f"stack {ctx.stack_name} does not exist")
        return 0
    resources = ctx.client("cloudformation").describe_stack_resources(StackName=ctx.stack_name).get("StackResources", [])
    outputs = {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}
    ctx.say(f"destroy {ctx.stack_name} ({stack['StackStatus']}):")
    for item in resources:
        kept = " (retained)" if item["LogicalResourceId"] == "AnalysisBucket" else ""
        ctx.say(f"  delete {item['ResourceType']:<28} {item.get('PhysicalResourceId', '')}{kept}")
    site = site_profile(ctx)
    if site["ours"]:
        ctx.say(f"  disassociate {SITE_PROFILE} from the site instance {SITE_INSTANCE_ID}")
    ctx.say(f"  keep the bucket {outputs.get('BucketName', DEFAULT_BUCKET)} and its objects, and the SSM parameters under {SSM_PREFIX}")
    ctx.say("  set ANALYSIS_SERVICE to anything but aws on the site first, or its analysis routes fail")
    if ctx.dry_run:
        return 0
    if not ctx.args.confirm_destroy:
        raise DeployError("nothing was changed; pass --confirm-destroy to delete the stack")
    if site["ours"]:
        ctx.client("ec2").disassociate_iam_instance_profile(AssociationId=site["associationId"])
    since = ctx.now() - dt.timedelta(seconds=5)
    ctx.client("cloudformation").delete_stack(StackName=ctx.stack_name)
    result = wait_stack(ctx, since)
    if result["StackStatus"] != "DELETE_COMPLETE":
        raise DeployError(f"stack ended {result['StackStatus']}")
    ctx.say("stack deleted; the bucket name stays taken while the retained bucket exists")
    return 0


COMMANDS: Dict[str, Callable[[Context], int]] = {
    "preflight": cmd_preflight,
    "plan": cmd_plan,
    "deploy": cmd_deploy,
    "put-worker-token": cmd_put_worker_token,
    "site-params": cmd_site_params,
    "associate-site-profile": cmd_associate_site_profile,
    "release": cmd_release,
    "bootstrap": cmd_bootstrap,
    "status": cmd_status,
    "logs": cmd_logs,
    "drain": lambda ctx: set_mode(ctx, "drain"),
    "resume": lambda ctx: set_mode(ctx, "active"),
    "rollback": cmd_rollback,
    "site-env": cmd_site_env,
    "destroy": cmd_destroy,
}


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--region", default=DEFAULT_REGION)
    common.add_argument("--stack-name", default=STACK_NAME)
    common.add_argument("--dry-run", action="store_true", help="print the changes without making them")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    preflight = commands.add_parser("preflight", parents=[common], help="check account, network, AMI, site and parameters")
    preflight.add_argument("--vpc-id")
    preflight.add_argument("--subnet-id")
    preflight.add_argument("--instance-type", default="t3a.medium", choices=sorted(PRICES["ec2_hour"]))
    preflight.add_argument("--volume-size", type=int, default=20)
    preflight.add_argument("--worker-hours", type=float, default=WORKER_MONTHLY_HOURS)
    preflight.add_argument("--ai-cap-usd", type=float, default=AI_MONTH_LIMIT_USD)
    preflight.add_argument("--budget-limit", type=float, default=72)

    for name, text in (("plan", "create and print a change set without executing it"),
                       ("deploy", "create, show and execute a change set (needs --yes)")):
        sub = commands.add_parser(name, parents=[common], help=text)
        sub.add_argument("--template", default=str(TEMPLATE_PATH))
        sub.add_argument("--vpc-id")
        sub.add_argument("--subnet-id")
        sub.add_argument("--ami-id")
        sub.add_argument("--refresh-ami", action="store_true", help="resolve the current Canonical AMI (replaces the worker)")
        sub.add_argument("--instance-type", choices=sorted(PRICES["ec2_hour"]))
        sub.add_argument("--volume-size", type=int)
        sub.add_argument("--site-origin")
        sub.add_argument("--bucket-name")
        sub.add_argument("--budget-limit", type=float)
        budget = sub.add_mutually_exclusive_group()
        budget.add_argument("--budget-email", help="create the account budget with alerts to this address")
        budget.add_argument("--no-budget", action="store_true", help="remove or skip the account budget")
        if name == "plan":
            sub.add_argument("--keep", action="store_true", help="keep the change set instead of discarding it")
        else:
            sub.add_argument("--yes", action="store_true", help="execute the change set shown")
            sub.add_argument("--allow-worker-replacement", action="store_true")

    token = commands.add_parser("put-worker-token", parents=[common], help="create the worker token SecureString")
    token.add_argument("--rotate", action="store_true")
    site = commands.add_parser("site-params", parents=[common], help="write site-url, mode and the AI model parameters")
    site.add_argument("--site-url", default=SITE_URL)
    site.add_argument("--model", default=OPENAI_MODEL)
    commands.add_parser("associate-site-profile", parents=[common], help=f"associate {SITE_PROFILE} with the site instance")
    release = commands.add_parser("release", parents=[common], help="upload a git archive of a commit and record it")
    release.add_argument("--commit", default="HEAD")
    release.add_argument("--repo", help=f"local clone; default: a fresh clone of {REPOSITORY_URL}")
    bootstrap = commands.add_parser("bootstrap", parents=[common], help="install the recorded release on the worker")
    bootstrap.add_argument("--unlimited-during-build", action="store_true")
    bootstrap.add_argument("--rebuild", action="store_true", help="build the image even if it exists on the worker")
    bootstrap.add_argument("--force", action="store_true", help="continue while a job is in progress; its attempt ends as worker_lost")
    bootstrap.add_argument("--keep-running-on-failure", action="store_true")
    bootstrap.add_argument("--timeout", type=int, default=7200, help="remote execution timeout in seconds")
    commands.add_parser("status", parents=[common],
                        help="stack, worker, release and last command; finishes the cleanup of an interrupted bootstrap")
    logs = commands.add_parser("logs", parents=[common], help="supervisor and watchdog journal (worker running)")
    logs.add_argument("--since", default="1 hour ago")
    logs.add_argument("--lines", type=int, default=300)
    commands.add_parser("drain", parents=[common], help="set the worker mode to drain")
    commands.add_parser("resume", parents=[common], help="set the worker mode to active")
    rollback = commands.add_parser("rollback", parents=[common], help="make the previous analyzer image current again")
    rollback.add_argument("--timeout", type=int, default=1800)
    commands.add_parser("site-env", parents=[common], help="print the site env lines (token hash only)")
    destroy = commands.add_parser("destroy", parents=[common], help="delete the stack; the bucket is retained")
    destroy.add_argument("--confirm-destroy", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None, **dependencies: Any) -> int:
    args = build_parser().parse_args(argv)
    ctx = Context(args, **dependencies)
    try:
        return COMMANDS[args.command](ctx)
    except DeployError as error:
        print(f"error: {error}", file=ctx.err, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
