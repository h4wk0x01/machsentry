from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deploy_machsentry_aws as deploy

try:
    import yaml
except ImportError:  # PyYAML is optional; CloudShell and most dev machines have it.
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
WORKER_ID = "i-0123456789abcdef0"
NOW = dt.datetime(2026, 10, 18, 12, 0, tzinfo=dt.timezone.utc)
AMI_ID = "ami-0abc1234def567890"
COMMIT = "a" * 40
DIGEST = "b" * 64


class AwsError(Exception):
    """Same shape as botocore's ClientError for error_code()."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.response = {"Error": {"Code": code, "Message": message or code}}


class FakeSts:
    def __init__(self, account: str = deploy.ACCOUNT_ID) -> None:
        self.account = account

    def get_caller_identity(self):
        return {"Account": self.account, "Arn": f"arn:aws:iam::{self.account}:user/owner"}


class FakeSsm:
    def __init__(self, ec2: "FakeEc2") -> None:
        self.ec2 = ec2
        self.parameters = {}
        self.puts = []
        self.reads = []
        self.commands = []
        self.online = True
        self.invocation = {"Status": "Success", "StandardOutputContent": '{"ok": true}\n', "StandardErrorContent": ""}
        self.invocations = {}  # by command id; other ids get self.invocation

    def get_parameter(self, Name, WithDecryption=False):
        self.reads.append((Name, WithDecryption))
        if Name == deploy.AMI_PARAMETER:
            return {"Parameter": {"Value": AMI_ID}}
        if Name not in self.parameters:
            raise AwsError("ParameterNotFound")
        kind, value = self.parameters[Name]
        if kind == "SecureString" and not WithDecryption:
            value = "AQICAH-ciphertext"
        return {"Parameter": {"Value": value, "Type": kind}}

    def put_parameter(self, Name, Value, Type, Overwrite=False, Tags=None, Description=None):
        if Name in self.parameters and not Overwrite:
            raise AwsError("ParameterAlreadyExists")
        if Overwrite and Tags:
            raise AwsError("ValidationException", "Tags cannot be combined with Overwrite")
        self.puts.append({"Name": Name, "Type": Type, "Overwrite": Overwrite, "Tags": Tags})
        self.parameters[Name] = (Type, Value)
        return {"Version": 1}

    def describe_parameters(self, ParameterFilters, NextToken=None):
        wanted = ParameterFilters[0]["Values"]
        return {"Parameters": [{"Name": name} for name in wanted if name in self.parameters]}

    def describe_instance_information(self, Filters):
        instance = self.ec2.instances[Filters[0]["Values"][0]]
        if instance["State"]["Name"] != "running" or not self.online:
            return {"InstanceInformationList": []}
        return {"InstanceInformationList": [{"PingStatus": "Online", "LastPingDateTime": instance["LaunchTime"] + dt.timedelta(seconds=30)}]}

    def send_command(self, **kwargs):
        self.commands.append(kwargs)
        return {"Command": {"CommandId": f"cmd-{len(self.commands)}"}}

    def get_command_invocation(self, CommandId, InstanceId):
        return self.invocations.get(CommandId, self.invocation)

    def list_commands(self, InstanceId, MaxResults):
        return {"Commands": []}

    def script(self, index: int = -1) -> str:
        """The bash script carried by a sent command, decoded from the sh wrapper."""
        lines = self.commands[index]["Parameters"]["commands"]
        encoded = re.search(r"printf '%s' '([A-Za-z0-9+/=]+)'", "\n".join(lines)).group(1)
        return base64.b64decode(encoded).decode("utf-8")


class FakeEc2:
    def __init__(self) -> None:
        self.instances = {
            WORKER_ID: {"InstanceId": WORKER_ID, "State": {"Name": "stopped"}, "LaunchTime": NOW - dt.timedelta(days=1),
                        "InstanceType": "t3a.medium", "Tags": []},
            deploy.SITE_INSTANCE_ID: {"InstanceId": deploy.SITE_INSTANCE_ID, "State": {"Name": "running"},
                                      "LaunchTime": NOW - dt.timedelta(days=30), "MetadataOptions": {"HttpTokens": "required"}},
        }
        self.credits = {WORKER_ID: "standard"}
        self.credit_changes = []
        self.credit_failures = set()
        self.tag_values = []
        self.events = []
        self.associations = []
        self.subnets = [
            {"SubnetId": "subnet-private", "VpcId": "vpc-default", "AvailabilityZone": "us-east-2a", "MapPublicIpOnLaunch": False},
            {"SubnetId": "subnet-public-c", "VpcId": "vpc-default", "AvailabilityZone": "us-east-2c", "MapPublicIpOnLaunch": True},
            {"SubnetId": "subnet-public-b", "VpcId": "vpc-default", "AvailabilityZone": "us-east-2b", "MapPublicIpOnLaunch": True},
        ]
        self.route_tables = [
            {"Associations": [{"Main": True}], "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "active"}]},
            {"Associations": [{"SubnetId": "subnet-private"}], "Routes": [{"DestinationCidrBlock": "172.31.0.0/16", "GatewayId": "local"}]},
        ]
        self.offered_zones = ["us-east-2a", "us-east-2c"]
        self.image = {"ImageId": AMI_ID, "OwnerId": deploy.CANONICAL_OWNER, "Architecture": "x86_64", "RootDeviceName": "/dev/sda1",
                      "Name": "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20261001", "CreationDate": "2026-10-01T00:00:00Z"}
        self.describe_vpc_calls = 0

    def describe_instances(self, InstanceIds):
        instance = self.instances.get(InstanceIds[0])
        if instance is None:
            raise AwsError("InvalidInstanceID.NotFound")
        state = instance["State"]["Name"]
        if state in ("pending", "stopping"):  # the next look sees the transition finished
            instance["State"] = {"Name": "running" if state == "pending" else "stopped"}
            return {"Reservations": [{"Instances": [dict(instance, State={"Name": state})]}]}
        return {"Reservations": [{"Instances": [instance]}]}

    def start_instances(self, InstanceIds):
        self.events.append(("start", InstanceIds[0]))
        self.instances[InstanceIds[0]].update(State={"Name": "pending"}, LaunchTime=NOW)

    def stop_instances(self, InstanceIds):
        self.events.append(("stop", InstanceIds[0]))
        self.instances[InstanceIds[0]]["State"] = {"Name": "stopping"}

    def describe_instance_credit_specifications(self, InstanceIds):
        return {"InstanceCreditSpecifications": [{"InstanceId": InstanceIds[0], "CpuCredits": self.credits[InstanceIds[0]]}]}

    def modify_instance_credit_specification(self, InstanceCreditSpecifications):
        item = InstanceCreditSpecifications[0]
        if item["CpuCredits"] in self.credit_failures:
            raise AwsError("RequestLimitExceeded")
        self.events.append(("credits", item["CpuCredits"]))
        self.credits[item["InstanceId"]] = item["CpuCredits"]
        self.credit_changes.append(item["CpuCredits"])

    def create_tags(self, Resources, Tags):
        self.events.append(("tag", Tags[0]["Key"]))
        self.tag_values.append(Tags[0]["Value"])
        instance = self.instances[Resources[0]]
        instance["Tags"] = [item for item in instance.get("Tags", []) if item["Key"] != Tags[0]["Key"]] + [dict(Tags[0])]

    def delete_tags(self, Resources, Tags):
        self.events.append(("untag", Tags[0]["Key"]))
        instance = self.instances[Resources[0]]
        instance["Tags"] = [item for item in instance.get("Tags", []) if item["Key"] != Tags[0]["Key"]]

    def tags(self, instance_id: str = WORKER_ID) -> dict:
        return {item["Key"]: item["Value"] for item in self.instances[instance_id].get("Tags", [])}

    def describe_iam_instance_profile_associations(self, Filters):
        return {"IamInstanceProfileAssociations": self.associations}

    def associate_iam_instance_profile(self, IamInstanceProfile, InstanceId):
        self.events.append(("associate", IamInstanceProfile["Name"], InstanceId))

    def disassociate_iam_instance_profile(self, AssociationId):
        self.events.append(("disassociate", AssociationId))

    def describe_vpcs(self, Filters):
        self.describe_vpc_calls += 1
        return {"Vpcs": [{"VpcId": "vpc-default"}]}

    def describe_subnets(self, Filters=None, SubnetIds=None):
        if SubnetIds:
            return {"Subnets": [item for item in self.subnets if item["SubnetId"] in SubnetIds]}
        return {"Subnets": [item for item in self.subnets if item["VpcId"] == Filters[0]["Values"][0]]}

    def describe_route_tables(self, Filters):
        return {"RouteTables": self.route_tables}

    def describe_instance_type_offerings(self, LocationType, Filters):
        return {"InstanceTypeOfferings": [{"Location": zone} for zone in self.offered_zones]}

    def describe_images(self, ImageIds):
        return {"Images": [self.image]}


class FakeCfn:
    def __init__(self) -> None:
        self.stack = None
        self.change_sets = []
        self.changes = [{"ResourceChange": {"Action": "Add", "ResourceType": "AWS::S3::Bucket", "LogicalResourceId": "AnalysisBucket"}}]
        self.change_status = {"Status": "CREATE_COMPLETE"}
        self.deleted_change_sets = []
        self.deleted_stacks = 0
        self.executed = []

    def describe_stacks(self, StackName):
        if self.stack is None:
            raise AwsError("ValidationError", f"Stack with id {StackName} does not exist")
        return {"Stacks": [self.stack]}

    def create_change_set(self, **kwargs):
        self.change_sets.append(kwargs)
        if self.stack is None:
            self.stack = {"StackName": kwargs["StackName"], "StackStatus": "REVIEW_IN_PROGRESS"}
        return {"Id": "arn:change-set"}

    def describe_change_set(self, StackName, ChangeSetName, NextToken=None):
        return dict(self.change_status, Changes=self.changes)

    def delete_change_set(self, StackName, ChangeSetName):
        self.deleted_change_sets.append(ChangeSetName)

    def delete_stack(self, StackName):
        self.deleted_stacks += 1
        self.stack = None

    def execute_change_set(self, StackName, ChangeSetName):
        self.executed.append(ChangeSetName)
        self.stack = complete_stack()

    def describe_stack_events(self, StackName):
        return {"StackEvents": [{"EventId": "1", "Timestamp": NOW, "LogicalResourceId": "AnalysisBucket", "ResourceStatus": "CREATE_COMPLETE"}]}

    def describe_stack_resources(self, StackName):
        return {"StackResources": [{"LogicalResourceId": "AnalysisBucket", "ResourceType": "AWS::S3::Bucket", "PhysicalResourceId": deploy.DEFAULT_BUCKET},
                                   {"LogicalResourceId": "WorkerInstance", "ResourceType": "AWS::EC2::Instance", "PhysicalResourceId": WORKER_ID}]}


class FakeS3:
    def __init__(self) -> None:
        self.objects = {}
        self.bucket_exists = False

    def head_bucket(self, Bucket):
        if not self.bucket_exists:
            raise AwsError("404")
        return {}

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            raise AwsError("404")
        return {"Metadata": self.objects[Key]["Metadata"]}

    def put_object(self, Bucket, Key, Body, ContentType, ChecksumSHA256, Metadata):
        self.objects[Key] = {"Body": Body.read(), "ChecksumSHA256": ChecksumSHA256, "Metadata": Metadata}

    def generate_presigned_url(self, operation, Params, ExpiresIn):
        return f"https://{Params['Bucket']}.s3.us-east-2.amazonaws.com/{Params['Key']}?X-Amz-Expires={ExpiresIn}&X-Amz-Signature=abc"


class FakeIam:
    def __init__(self) -> None:
        self.events_role = False
        self.created = []

    def get_role(self, RoleName):
        if not self.events_role:
            raise AwsError("NoSuchEntity")
        return {"Role": {"RoleName": RoleName}}

    def create_service_linked_role(self, AWSServiceName):
        self.created.append(AWSServiceName)
        self.events_role = True

    def get_instance_profile(self, InstanceProfileName):
        return {"InstanceProfile": {"Arn": f"arn:aws:iam::{deploy.ACCOUNT_ID}:instance-profile/{InstanceProfileName}"}}


class FakeBudgets:
    def describe_budgets(self, AccountId):
        return {"Budgets": []}


def complete_stack(parameters=None):
    return {
        "StackName": deploy.STACK_NAME, "StackStatus": "CREATE_COMPLETE",
        "Parameters": parameters or [],
        "Outputs": [{"OutputKey": "BucketName", "OutputValue": deploy.DEFAULT_BUCKET},
                    {"OutputKey": "WorkerInstanceId", "OutputValue": WORKER_ID}],
    }


class World:
    def __init__(self) -> None:
        self.ec2 = FakeEc2()
        self.clients = {"sts": FakeSts(), "ec2": self.ec2, "ssm": FakeSsm(self.ec2), "cloudformation": FakeCfn(),
                        "s3": FakeS3(), "iam": FakeIam(), "budgets": FakeBudgets()}
        self.ticks = 0

    def __getattr__(self, name):
        clients = self.__dict__.get("clients", {})
        if name in clients:
            return clients[name]
        raise AttributeError(name)

    def clock(self) -> float:
        self.ticks += 1
        return float(self.ticks)

    def run(self, *argv: str) -> tuple:
        out, err = io.StringIO(), io.StringIO()
        code = deploy.main(list(argv), clients=self.clients.__getitem__, sleep=lambda seconds: None, clock=self.clock,
                           now=lambda: NOW, out=out, err=err)
        return code, out.getvalue(), err.getvalue()


def git_available() -> bool:
    return shutil.which("git") is not None


class DeployScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_every_command_refuses_another_account(self):
        self.world.clients["sts"] = FakeSts("111122223333")
        for command in ("preflight", "put-worker-token", "status", "site-env"):
            code, _, err = self.world.run(command)
            self.assertEqual(code, 1, command)
            self.assertIn("111122223333", err)
        self.assertEqual(self.world.ssm.puts, [])

    def test_preflight_picks_a_public_subnet_in_an_offering_zone_and_reads_parameter_names_only(self):
        self.world.ssm.parameters[deploy.TOKEN_PARAMETER] = ("SecureString", "secret-token-value")
        code, out, _ = self.world.run("preflight")
        self.assertEqual(code, 0, out)
        self.assertIn("vpc-default / subnet-public-c (us-east-2c", out)
        self.assertIn(f"{deploy.TOKEN_PARAMETER}: present", out)
        self.assertIn(f"{deploy.OPENAI_KEY_PARAMETER}: missing", out)
        self.assertNotIn("secret-token-value", out)
        self.assertTrue(all(name == deploy.AMI_PARAMETER for name, _ in self.world.ssm.reads))
        self.assertRegex(out, r"EC2 t3a\.medium, 40 h/month on demand\s+1\.50")
        self.assertRegex(out, r"EBS gp3 20 GiB, billed while stopped too\s+1\.60")
        self.assertRegex(out, r"total\s+6\.43")

    def test_preflight_fails_when_the_bucket_exists_outside_the_stack(self):
        self.world.s3.bucket_exists = True
        code, out, _ = self.world.run("preflight")
        self.assertEqual(code, 1)
        self.assertIn("already exists outside this stack", out)

    def test_put_worker_token_creates_a_secure_string_and_prints_only_its_hash(self):
        code, out, _ = self.world.run("put-worker-token")
        self.assertEqual(code, 0)
        kind, token = self.world.ssm.parameters[deploy.TOKEN_PARAMETER]
        self.assertEqual(kind, "SecureString")
        self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")
        self.assertEqual(len(base64.urlsafe_b64decode(token + "=")), 32)
        self.assertNotIn(token, out)
        self.assertIn(f"ANALYSIS_WORKER_TOKEN_SHA256={hashlib.sha256(token.encode()).hexdigest()}", out)
        self.assertEqual(self.world.ssm.puts[0]["Tags"], [deploy.PROJECT_TAG])

    def test_put_worker_token_keeps_an_existing_token_unless_rotated(self):
        self.world.ssm.parameters[deploy.TOKEN_PARAMETER] = ("SecureString", "existing-token")
        code, out, _ = self.world.run("put-worker-token")
        self.assertEqual((code, self.world.ssm.puts), (0, []))
        self.assertIn(hashlib.sha256(b"existing-token").hexdigest(), out)
        self.assertNotIn("existing-token\n", out)
        code, out, _ = self.world.run("put-worker-token", "--rotate")
        self.assertEqual(code, 0)
        self.assertTrue(self.world.ssm.puts[0]["Overwrite"])
        self.assertNotEqual(self.world.ssm.parameters[deploy.TOKEN_PARAMETER][1], "existing-token")

    def test_dry_run_prints_without_writing(self):
        code, out, _ = self.world.run("put-worker-token", "--dry-run")
        self.assertEqual((code, self.world.ssm.puts), (0, []))
        self.assertIn("will create SecureString", out)

    def test_site_params_create_missing_values_and_keep_a_drained_mode(self):
        self.world.ssm.parameters[deploy.MODE_PARAMETER] = ("String", "drain")
        code, _, _ = self.world.run("site-params")
        self.assertEqual(code, 0)
        self.assertEqual(self.world.ssm.parameters[deploy.SITE_URL_PARAMETER], ("String", deploy.SITE_URL))
        self.assertEqual(self.world.ssm.parameters[deploy.OPENAI_MODEL_PARAMETER], ("String", deploy.OPENAI_MODEL))
        self.assertEqual(self.world.ssm.parameters[deploy.MODE_PARAMETER], ("String", "drain"))
        self.assertEqual(self.world.run("site-params", "--site-url", "http://www.unpackedlab.com")[0], 1)

    def test_associate_site_profile_only_when_the_site_has_no_profile(self):
        code, _, _ = self.world.run("associate-site-profile")
        self.assertEqual(code, 0)
        self.assertIn(("associate", deploy.SITE_PROFILE, deploy.SITE_INSTANCE_ID), self.world.ec2.events)

        self.world.ec2.events.clear()
        self.world.ec2.associations = [{"AssociationId": "a-1", "State": "associated",
                                        "IamInstanceProfile": {"Arn": f"arn:aws:iam::1:instance-profile/{deploy.SITE_PROFILE}"}}]
        self.assertEqual(self.world.run("associate-site-profile")[0], 0)
        self.assertEqual(self.world.ec2.events, [])

        self.world.ec2.associations[0]["IamInstanceProfile"]["Arn"] = "arn:aws:iam::1:instance-profile/site-backups"
        code, _, err = self.world.run("associate-site-profile")
        self.assertEqual(code, 1)
        self.assertIn("refusing to replace", err)
        self.assertEqual(self.world.ec2.events, [])

    def test_deploy_shows_the_change_set_and_needs_yes(self):
        code, out, err = self.world.run("deploy")
        self.assertEqual(code, 1)
        self.assertIn("Add     AWS::S3::Bucket", out)
        self.assertIn("--yes", err)
        self.assertEqual(self.world.cloudformation.executed, [])
        self.assertEqual(len(self.world.cloudformation.deleted_change_sets), 1)
        self.assertIsNone(self.world.cloudformation.stack, "the empty REVIEW_IN_PROGRESS stack is removed")
        parameters = {item["ParameterKey"]: item["ParameterValue"] for item in self.world.cloudformation.change_sets[0]["Parameters"]}
        self.assertEqual(parameters, {"VpcId": "vpc-default", "SubnetId": "subnet-public-c", "AmiId": AMI_ID})
        self.assertEqual(self.world.cloudformation.change_sets[0]["Capabilities"], ["CAPABILITY_NAMED_IAM"])

    def test_deploy_with_yes_creates_the_alarm_role_and_executes(self):
        code, out, _ = self.world.run("deploy", "--yes", "--budget-email", "owner@example.com")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.world.iam.created, ["events.amazonaws.com"])
        self.assertEqual(len(self.world.cloudformation.executed), 1)
        parameters = {item["ParameterKey"]: item.get("ParameterValue") for item in self.world.cloudformation.change_sets[0]["Parameters"]}
        self.assertEqual((parameters["CreateBudget"], parameters["BudgetEmail"]), ("true", "owner@example.com"))
        self.assertIn(f"WorkerInstanceId         {WORKER_ID}", out)

    def test_update_keeps_previous_network_and_ami_and_refuses_worker_replacement(self):
        previous = [{"ParameterKey": key, "ParameterValue": value} for key, value in
                    (("VpcId", "vpc-1"), ("SubnetId", "subnet-1"), ("AmiId", "ami-old"), ("SiteOrigin", deploy.SITE_URL))]
        self.world.cloudformation.stack = complete_stack(previous)
        self.world.cloudformation.changes = [{"ResourceChange": {"Action": "Modify", "ResourceType": "AWS::EC2::Instance",
                                                                 "LogicalResourceId": "WorkerInstance", "Replacement": "True"}}]
        code, out, err = self.world.run("deploy", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("--allow-worker-replacement", err)
        self.assertEqual(self.world.cloudformation.executed, [])
        self.assertEqual(self.world.cloudformation.deleted_stacks, 0)
        self.assertEqual(self.world.ec2.describe_vpc_calls, 0)
        sent = self.world.cloudformation.change_sets[0]["Parameters"]
        self.assertTrue(all(item.get("UsePreviousValue") for item in sent))
        self.assertEqual({item["ParameterKey"] for item in sent}, {"VpcId", "SubnetId", "AmiId", "SiteOrigin"})

    def test_plan_without_changes_reports_and_discards(self):
        self.world.cloudformation.stack = complete_stack()
        self.world.cloudformation.change_status = {"Status": "FAILED", "StatusReason": "The submitted information didn't contain changes."}
        code, out, _ = self.world.run("plan", "--vpc-id", "vpc-default", "--subnet-id", "subnet-public-b", "--ami-id", AMI_ID)
        self.assertEqual(code, 0)
        self.assertIn("no changes", out)
        self.assertEqual(len(self.world.cloudformation.deleted_change_sets), 1)
        self.assertEqual(self.world.cloudformation.deleted_stacks, 0)

    def bootstrap_world(self, stdout: str, status: str = "Success") -> None:
        self.world.cloudformation.stack = complete_stack()
        self.world.ssm.parameters[deploy.RELEASE_PARAMETER] = (
            "String", json.dumps({"commit": COMMIT, "s3Key": f"releases/machsentry-{COMMIT}.tar.gz", "sha256": DIGEST}))
        self.world.ssm.invocation = {"Status": status, "StandardOutputContent": stdout, "StandardErrorContent": "build log tail"}

    def test_bootstrap_starts_the_worker_runs_the_release_and_stops_it(self):
        summary = {"ok": True, "action": "bootstrap", "commit": COMMIT, "verify": {"elapsed": 61.2, "peakMemoryBytes": 2147483648}}
        self.bootstrap_world("12:00:01Z building\n" + json.dumps(summary) + "\n")
        code, out, err = self.world.run("bootstrap", "--unlimited-during-build")
        self.assertEqual(code, 0, out + err)
        # The tag goes on before anything changes and names what to restore; it gains the command once sent.
        self.assertEqual([event[0] for event in self.world.ec2.events],
                         ["tag", "credits", "start", "tag", "stop", "credits", "untag"])
        self.assertEqual(self.world.ec2.tag_values, [
            f"bootstrap commit={COMMIT[:12]} credits=standard since=2026-10-18T12:00:00Z",
            f"bootstrap commit={COMMIT[:12]} credits=standard since=2026-10-18T12:00:00Z command=cmd-1"])
        self.assertEqual(self.world.ec2.credit_changes, ["unlimited", "standard"])
        self.assertEqual(self.world.ec2.instances[WORKER_ID]["State"]["Name"], "stopped")
        self.assertEqual(self.world.ec2.tags(), {})
        command = self.world.ssm.commands[0]
        self.assertEqual(command["DocumentName"], "AWS-RunShellScript")
        self.assertEqual(command["Parameters"]["executionTimeout"], ["7200"])
        script = self.world.ssm.script()
        self.assertIn(f"commit={COMMIT}", script)
        self.assertIn(f"sha256={DIGEST}", script)
        self.assertIn(f"url='https://{deploy.DEFAULT_BUCKET}.s3.us-east-2.amazonaws.com/releases/machsentry-{COMMIT}.tar.gz?X-Amz-Expires=3600&X-Amz-Signature=abc'", script)
        self.assertIn('bootstrap.sh" --release-dir "$release" --commit "$commit" --region us-east-2  </dev/null', script)
        self.assertIn(f"state={deploy.STATE_DIR}", script)
        # The wrapper stops nothing and leaves no flag behind: bootstrap.sh checks for a job first.
        self.assertNotIn("maintenance", script)
        self.assertNotIn("systemctl stop", script)
        self.assertNotRegex(script, r"(?i)aws_secret|aws_access_key|secret_access")
        self.assertIn('"peakMemoryBytes": 2147483648', out)
        completed = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True) if shutil.which("bash") else None
        if completed is not None:
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_failed_bootstrap_reports_restores_credits_and_stops_the_worker(self):
        failure = {"ok": False, "action": "bootstrap", "stage": "verify", "error": "verification failed (exit 1)"}
        self.bootstrap_world(json.dumps(failure) + "\n", status="Failed")
        code, out, err = self.world.run("bootstrap", "--unlimited-during-build")
        self.assertEqual(code, 1)
        self.assertIn("verification failed (exit 1)", err)
        self.assertIn("build log tail", out)
        self.assertEqual(self.world.ec2.credit_changes, ["unlimited", "standard"])
        self.assertEqual(self.world.ec2.events[-3:], [("stop", WORKER_ID), ("credits", "standard"), ("untag", deploy.MAINTENANCE_TAG)])

    def test_bootstrap_refuses_a_malformed_release_record(self):
        self.bootstrap_world("{}")
        self.world.ssm.parameters[deploy.RELEASE_PARAMETER] = ("String", json.dumps({"commit": "HEAD", "s3Key": "x", "sha256": DIGEST}))
        code, _, err = self.world.run("bootstrap")
        self.assertEqual(code, 1)
        self.assertIn("malformed", err)
        self.assertEqual(self.world.ec2.events, [])

    def test_rollback_restores_the_stopped_state(self):
        self.bootstrap_world(json.dumps({"ok": True, "action": "rollback", "commit": COMMIT}) + "\n")
        code, _, _ = self.world.run("rollback")
        self.assertEqual(code, 0)
        self.assertIn("--rollback", self.world.ssm.script())
        self.assertEqual([event[0] for event in self.world.ec2.events], ["tag", "start", "tag", "stop", "untag"])
        self.assertEqual(self.world.ec2.tag_values[0], "rollback since=2026-10-18T12:00:00Z")

    def test_bootstrap_refused_while_a_job_runs_leaves_the_worker_on(self):
        refusal = {"ok": False, "action": "bootstrap", "stage": "maintenance", "supervisorRunning": True,
                   "error": "job j-1 attempt 1 is in progress; drain the worker first or pass --force"}
        self.bootstrap_world(json.dumps(refusal) + "\n", status="Failed")
        self.world.ec2.instances[WORKER_ID]["State"] = {"Name": "running"}
        code, out, err = self.world.run("bootstrap", "--unlimited-during-build")
        self.assertEqual(code, 1)
        self.assertIn("job j-1 attempt 1 is in progress", err)
        self.assertIn(f"{WORKER_ID} stays on", out)
        names = [event[0] for event in self.world.ec2.events]
        self.assertNotIn("stop", names)
        self.assertEqual(names[-2:], ["credits", "untag"])
        self.assertEqual(self.world.ec2.tags(), {})

    def test_bootstrap_passes_rebuild_and_force_to_bootstrap_sh(self):
        self.bootstrap_world('{"ok": true}\n')
        code, out, err = self.world.run("bootstrap", "--rebuild", "--force")
        self.assertEqual(code, 0, out + err)
        self.assertIn("--region us-east-2 --rebuild --force </dev/null", self.world.ssm.script())
        self.assertIn("run deploy/worker/bootstrap.sh --rebuild --force from", out)

    def test_a_failure_before_the_command_leaves_a_running_worker_as_it_was(self):
        self.bootstrap_world('{"ok": true}\n')
        self.world.ec2.instances[WORKER_ID]["State"] = {"Name": "running"}
        self.world.ssm.online = False
        code, out, err = self.world.run("bootstrap")
        self.assertEqual(code, 1)
        self.assertIn("did not come online", err)
        self.assertIn("nothing reached the worker", out)
        self.assertEqual([event[0] for event in self.world.ec2.events], ["tag", "untag"])

    def interrupted(self, value: str) -> None:
        """A bootstrap whose operator process ended before its cleanup (a closed CloudShell session)."""
        self.bootstrap_world('{"ok": true}\n')
        self.world.ec2.instances[WORKER_ID]["Tags"] = [{"Key": deploy.MAINTENANCE_TAG, "Value": value}]
        self.world.ec2.credits[WORKER_ID] = "unlimited"

    def test_status_finishes_the_cleanup_of_a_bootstrap_whose_operator_left(self):
        self.interrupted(f"bootstrap commit={COMMIT[:12]} credits=standard since=2026-10-18T10:00:00Z command=cmd-9")
        self.world.ssm.invocations["cmd-9"] = {"Status": "Success"}
        code, out, err = self.world.run("status", "--dry-run")
        self.assertEqual((code, self.world.ec2.events), (0, []), err)
        self.assertIn("restore standard CPU credits", out)
        code, out, err = self.world.run("status")
        self.assertEqual(code, 0, err)
        self.assertIn("ended without its cleanup", out)
        self.assertEqual(self.world.ec2.credit_changes, ["standard"])
        self.assertEqual(self.world.ec2.tags(), {})
        self.assertNotRegex(out, r"(?m)^maintenance ")

    def test_recovery_waits_for_a_command_that_still_runs(self):
        self.interrupted(f"bootstrap commit={COMMIT[:12]} credits=standard since=2026-10-18T10:00:00Z command=cmd-9")
        self.world.ssm.invocations["cmd-9"] = {"Status": "InProgress"}
        code, out, _ = self.world.run("status")
        self.assertEqual(code, 0)
        self.assertIn("SSM command cmd-9 is InProgress", out)
        code, _, err = self.world.run("bootstrap", "--unlimited-during-build")
        self.assertEqual(code, 1)
        self.assertIn("wait for it to end", err)
        self.assertEqual(self.world.ec2.events, [])
        self.assertEqual(self.world.ssm.commands, [])

    def test_a_tag_without_a_command_waits_out_the_start_window(self):
        self.interrupted(f"bootstrap commit={COMMIT[:12]} credits=standard since=2026-10-18T11:50:00Z")
        code, out, _ = self.world.run("status")
        self.assertEqual(code, 0)
        self.assertIn("its SSM command is not running yet", out)
        self.assertEqual(self.world.ec2.events, [])
        self.world.ec2.instances[WORKER_ID]["Tags"][0]["Value"] = f"bootstrap commit={COMMIT[:12]} credits=standard since=2026-10-18T10:59:59Z"
        code, out, err = self.world.run("status")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.ec2.credit_changes, ["standard"])
        self.assertEqual(self.world.ec2.tags(), {})

    def test_the_next_bootstrap_restores_the_credits_before_switching_them_again(self):
        self.interrupted(f"bootstrap commit={COMMIT[:12]} credits=standard since=2026-10-18T10:00:00Z command=cmd-9")
        self.world.ssm.invocations["cmd-9"] = {"Status": "Failed"}
        code, out, err = self.world.run("bootstrap", "--unlimited-during-build")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.world.ec2.credit_changes, ["standard", "unlimited", "standard"])
        self.assertEqual(self.world.ec2.credits[WORKER_ID], "standard")
        self.assertEqual(self.world.ec2.tags(), {})

    def test_a_failed_credit_restore_keeps_the_tag_for_the_next_command(self):
        self.bootstrap_world('{"ok": true}\n')
        self.world.ec2.credit_failures.add("standard")
        code, _, err = self.world.run("bootstrap", "--unlimited-during-build")
        self.assertEqual(code, 1)
        self.assertIn("a cleanup step failed", err)
        self.assertIn("command=cmd-1", self.world.ec2.tags()[deploy.MAINTENANCE_TAG])
        self.assertEqual(self.world.ec2.instances[WORKER_ID]["State"]["Name"], "stopped")
        self.world.ec2.credit_failures.clear()
        code, _, err = self.world.run("status")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.ec2.credits[WORKER_ID], "standard")
        self.assertEqual(self.world.ec2.tags(), {})

    def test_logs_need_a_running_worker(self):
        self.world.cloudformation.stack = complete_stack()
        code, out, _ = self.world.run("logs")
        self.assertEqual(code, 0)
        self.assertIn("is stopped", out)
        self.assertEqual(self.world.ssm.commands, [])

    def test_drain_and_resume_set_the_worker_mode(self):
        self.assertEqual(self.world.run("drain")[0], 0)
        self.assertEqual(self.world.ssm.parameters[deploy.MODE_PARAMETER], ("String", "drain"))
        self.assertEqual(self.world.run("resume")[0], 0)
        self.assertEqual(self.world.ssm.parameters[deploy.MODE_PARAMETER], ("String", "active"))

    def test_site_env_prints_the_token_hash_and_never_the_token(self):
        self.world.cloudformation.stack = complete_stack()
        self.world.ssm.parameters[deploy.TOKEN_PARAMETER] = ("SecureString", "worker-token-value")
        code, out, _ = self.world.run("site-env")
        self.assertEqual(code, 0)
        self.assertNotIn("worker-token-value", out)
        lines = [line for line in out.splitlines() if not line.startswith("#")]
        self.assertEqual(lines, [
            "ANALYSIS_SERVICE=aws", "ANALYSIS_AWS_REGION=us-east-2", f"ANALYSIS_BUCKET={deploy.DEFAULT_BUCKET}",
            f"ANALYSIS_WORKER_INSTANCE_ID={WORKER_ID}",
            f"ANALYSIS_WORKER_TOKEN_SHA256={hashlib.sha256(b'worker-token-value').hexdigest()}",
        ])

    def test_destroy_needs_confirmation_and_disassociates_the_site_profile_first(self):
        self.world.cloudformation.stack = complete_stack()
        self.world.ec2.associations = [{"AssociationId": "a-1", "State": "associated",
                                        "IamInstanceProfile": {"Arn": f"arn:aws:iam::1:instance-profile/{deploy.SITE_PROFILE}"}}]
        code, out, err = self.world.run("destroy")
        self.assertEqual(code, 1)
        self.assertIn("(retained)", out)
        self.assertIn("--confirm-destroy", err)
        self.assertEqual(self.world.cloudformation.deleted_stacks, 0)
        code, out, _ = self.world.run("destroy", "--confirm-destroy")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.world.ec2.events, [("disassociate", "a-1")])
        self.assertEqual(self.world.cloudformation.deleted_stacks, 1)

    def test_ssm_wrapper_runs_the_script_with_bash(self):
        lines = deploy.ssm_commands("echo 'quoted'; exit 3\n")
        self.assertIn('bash "$script" </dev/null || status=$?', lines)
        encoded = re.search(r"printf '%s' '([A-Za-z0-9+/=]+)'", "\n".join(lines)).group(1)
        self.assertEqual(base64.b64decode(encoded).decode(), "echo 'quoted'; exit 3\n")

    def test_last_json_line_skips_progress_output(self):
        self.assertEqual(deploy.last_json_line('12:00Z step\n{"ok": true}\n\n'), {"ok": True})
        self.assertIsNone(deploy.last_json_line("no summary"))


@unittest.skipUnless(git_available(), "git is not installed")
class ReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()
        self.world.cloudformation.stack = complete_stack()
        self.scratch = tempfile.TemporaryDirectory()
        self.repo = Path(self.scratch.name) / "machsentry"
        self.repo.mkdir()
        self.git("init", "-q")
        for name in deploy.RELEASE_REQUIRED + ("amostras/README.md",):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def git(self, *arguments: str) -> str:
        command = ["git", "-C", str(self.repo), "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                   "-c", "commit.gpgsign=false", *arguments]
        return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()

    def commit(self) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "synthetic release")
        return self.git("rev-parse", "HEAD")

    def test_release_uploads_the_archive_with_its_checksum_and_records_it(self):
        commit = self.commit()
        code, out, err = self.world.run("release", "--repo", str(self.repo))
        self.assertEqual(code, 0, out + err)
        key = f"releases/machsentry-{commit}.tar.gz"
        stored = self.world.s3.objects[key]
        digest = hashlib.sha256(stored["Body"]).hexdigest()
        self.assertEqual(base64.b64decode(stored["ChecksumSHA256"]).hex(), digest)
        self.assertEqual(stored["Metadata"], {"sha256": digest, "commit": commit})
        record = json.loads(self.world.ssm.parameters[deploy.RELEASE_PARAMETER][1])
        self.assertEqual(record, {"commit": commit, "s3Key": key, "sha256": digest})
        with tarfile.open(fileobj=io.BytesIO(stored["Body"])) as archive:
            self.assertIn("deploy/worker/bootstrap.sh", archive.getnames())
        code, out, _ = self.world.run("release", "--repo", str(self.repo))
        self.assertIn("already uploaded", out)

    def test_release_refuses_an_archive_with_a_sample(self):
        (self.repo / "amostras/sample.macho").write_bytes(b"\xcf\xfa\xed\xfe synthetic")
        self.commit()
        code, _, err = self.world.run("release", "--repo", str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("amostras/sample.macho", err)
        self.assertEqual(self.world.s3.objects, {})
        self.assertNotIn(deploy.RELEASE_PARAMETER, self.world.ssm.parameters)

    def test_release_finishes_an_interrupted_cleanup(self):
        self.commit()
        self.world.ec2.instances[WORKER_ID]["Tags"] = [{"Key": deploy.MAINTENANCE_TAG, "Value": "rollback since=2026-10-18T09:00:00Z"}]
        code, out, err = self.world.run("release", "--repo", str(self.repo))
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.world.ec2.tags(), {})

    def test_release_rejects_an_unknown_commit(self):
        self.commit()
        code, _, err = self.world.run("release", "--repo", str(self.repo), "--commit", "f" * 40)
        self.assertEqual(code, 1)
        self.assertIn("is not a commit", err)


def cloudformation_loader():
    class Loader(yaml.SafeLoader):
        pass

    def construct(loader, suffix, node):
        name = "Ref" if suffix == "Ref" else f"Fn::{suffix}"
        if isinstance(node, yaml.ScalarNode):
            value = loader.construct_scalar(node)
            if suffix == "GetAtt":
                value = value.split(".", 1)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        else:
            value = loader.construct_mapping(node, deep=True)
        return {name: value}

    Loader.add_multi_constructor("!", construct)
    return Loader


@unittest.skipUnless(yaml is not None, "PyYAML is not installed")
class TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.template = yaml.load((ROOT / "deploy/aws/worker.yaml").read_text(encoding="utf-8"), Loader=cloudformation_loader())
        cls.resources = cls.template["Resources"]

    def properties(self, name: str) -> dict:
        return self.resources[name]["Properties"]

    def statements(self, role: str) -> list:
        return self.properties(role)["Policies"][0]["PolicyDocument"]["Statement"]

    def test_defaults_match_the_contract_and_the_deploy_script(self):
        parameters = self.template["Parameters"]
        self.assertEqual(parameters["SiteOrigin"]["Default"], deploy.SITE_URL)
        self.assertEqual(parameters["BucketName"]["Default"], deploy.DEFAULT_BUCKET)
        self.assertEqual(parameters["InstanceType"]["Default"], "t3a.medium")
        self.assertEqual(parameters["VolumeSize"]["Default"], 20)
        self.assertEqual(parameters["BudgetLimitUsd"]["Default"], 72)
        self.assertNotIn("Default", parameters["AmiId"])
        self.assertEqual(set(parameters["InstanceType"]["AllowedValues"]), set(deploy.PRICES["ec2_hour"]))

    def test_bucket_is_private_encrypted_retained_and_expires_by_prefix(self):
        bucket = self.resources["AnalysisBucket"]
        self.assertEqual((bucket["DeletionPolicy"], bucket["UpdateReplacePolicy"]), ("Retain", "Retain"))
        properties = bucket["Properties"]
        self.assertTrue(all(properties["PublicAccessBlockConfiguration"].values()))
        self.assertEqual(len(properties["PublicAccessBlockConfiguration"]), 4)
        self.assertEqual(properties["OwnershipControls"]["Rules"], [{"ObjectOwnership": "BucketOwnerEnforced"}])
        encryption = properties["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]
        self.assertEqual(encryption["ServerSideEncryptionByDefault"]["SSEAlgorithm"], "AES256")
        self.assertNotIn("VersioningConfiguration", properties)
        rules = properties["LifecycleConfiguration"]["Rules"]
        expiry = {rule["Prefix"]: rule["ExpirationInDays"] for rule in rules if "ExpirationInDays" in rule}
        self.assertEqual(expiry, {"uploads/": 1, "sealed/": 1, "results/": 31})
        self.assertIn({"DaysAfterInitiation": 1}, [rule.get("AbortIncompleteMultipartUpload") for rule in rules])
        self.assertFalse(any(rule.get("Prefix", "").startswith("releases") for rule in rules))
        cors = properties["CorsConfiguration"]["CorsRules"]
        self.assertEqual(cors, [{"Id": "site-upload", "AllowedMethods": ["POST"], "AllowedOrigins": [{"Ref": "SiteOrigin"}],
                                 "AllowedHeaders": ["*"], "MaxAge": 600}])

    def test_bucket_policy_denies_plain_http(self):
        statement = self.properties("AnalysisBucketPolicy")["PolicyDocument"]["Statement"][0]
        self.assertEqual((statement["Effect"], statement["Action"]), ("Deny", "s3:*"))
        self.assertEqual(statement["Condition"], {"Bool": {"aws:SecureTransport": "false"}})

    def test_worker_instance_hardening(self):
        instance = self.properties("WorkerInstance")
        self.assertEqual(instance["MetadataOptions"], {"HttpEndpoint": "enabled", "HttpTokens": "required", "HttpPutResponseHopLimit": 1,
                                                       "InstanceMetadataTags": "enabled"})
        self.assertEqual(instance["CreditSpecification"], {"CPUCredits": "standard"})
        self.assertEqual(instance["InstanceInitiatedShutdownBehavior"], "stop")
        volume = instance["BlockDeviceMappings"][0]["Ebs"]
        self.assertEqual((volume["VolumeType"], volume["Encrypted"], volume["DeleteOnTermination"]), ("gp3", True, True))
        interface = instance["NetworkInterfaces"][0]
        self.assertEqual((interface["AssociatePublicIpAddress"], interface["SubnetId"]), (True, {"Ref": "SubnetId"}))
        self.assertNotIn("KeyName", instance)
        user_data = instance["UserData"]["Fn::Base64"]
        self.assertIn("bootstrap-pending", user_data)
        self.assertNotRegex(user_data, r"(?i)token|secret|password|key")
        self.assertIn({"Key": "Name", "Value": "unpacked-analysis-worker"}, instance["Tags"])

    def test_worker_security_group_has_no_ingress_and_only_web_egress(self):
        group = self.properties("WorkerSecurityGroup")
        self.assertNotIn("SecurityGroupIngress", group)
        egress = {(rule["IpProtocol"], rule["FromPort"], rule["ToPort"], rule["CidrIp"]) for rule in group["SecurityGroupEgress"]}
        self.assertEqual(egress, {("tcp", 443, 443, "0.0.0.0/0"), ("tcp", 80, 80, "0.0.0.0/0")})
        self.assertFalse([name for name, resource in self.resources.items() if resource["Type"] == "AWS::EC2::SecurityGroupIngress"])

    def test_idle_alarm_stops_the_worker(self):
        alarm = self.properties("WorkerIdleAlarm")
        self.assertEqual(alarm["AlarmActions"], [{"Fn::Sub": "arn:${AWS::Partition}:automate:${AWS::Region}:ec2:stop"}])
        self.assertEqual((alarm["MetricName"], alarm["Statistic"], alarm["Period"], alarm["EvaluationPeriods"]),
                         ("CPUUtilization", "Average", 300, 3))
        self.assertEqual((alarm["ComparisonOperator"], alarm["Threshold"]), ("LessThanThreshold", 2))
        self.assertEqual(alarm["Dimensions"], [{"Name": "InstanceId", "Value": {"Ref": "WorkerInstance"}}])

    def test_site_role_is_limited_to_the_three_prefixes_and_the_worker(self):
        self.assertEqual(self.properties("SiteRole")["RoleName"], deploy.SITE_PROFILE)
        self.assertEqual(self.properties("SiteInstanceProfile")["InstanceProfileName"], deploy.SITE_PROFILE)
        by_sid = {statement["Sid"]: statement for statement in self.statements("SiteRole")}
        objects = by_sid["AnalysisObjects"]
        self.assertEqual(sorted(objects["Action"]), ["s3:DeleteObject", "s3:GetObject", "s3:PutObject"])
        self.assertEqual([item["Fn::Sub"] for item in objects["Resource"]],
                         ["${AnalysisBucket.Arn}/uploads/*", "${AnalysisBucket.Arn}/sealed/*", "${AnalysisBucket.Arn}/results/*"])
        self.assertEqual(by_sid["AnalysisListing"]["Condition"]["StringLike"]["s3:prefix"], ["uploads/*", "sealed/*", "results/*"])
        power = by_sid["WorkerPower"]
        self.assertEqual(sorted(power["Action"]), ["ec2:StartInstances", "ec2:StopInstances"])
        self.assertTrue(power["Resource"]["Fn::Sub"].endswith(":instance/${WorkerInstance}"))
        self.assertEqual((by_sid["WorkerState"]["Action"], by_sid["WorkerState"]["Resource"]), ("ec2:DescribeInstances", "*"))
        for statement in self.statements("SiteRole") + self.statements("WorkerRole"):
            actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
            self.assertFalse([action for action in actions if action.endswith("*")], statement["Sid"])

    def test_worker_role_reads_only_its_parameters_and_releases(self):
        self.assertEqual(self.properties("WorkerRole")["RoleName"], "unpacked-analysis-worker")
        self.assertEqual(self.properties("WorkerRole")["ManagedPolicyArns"],
                         [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"}])
        by_sid = {statement["Sid"]: statement for statement in self.statements("WorkerRole")}
        prefixes = [item["Fn::Sub"].split(":parameter")[1] for item in by_sid["WorkerParameters"]["Resource"]]
        self.assertEqual(prefixes, ["/unpacked/analysis/worker/*", "/unpacked/analysis/openai/*"])
        deny = by_sid["OnlyWorkerParameters"]
        self.assertEqual(deny["Effect"], "Deny")
        self.assertEqual(deny["NotResource"], by_sid["WorkerParameters"]["Resource"])
        self.assertIn("ssm:GetParameters", deny["Action"])
        self.assertEqual((by_sid["Releases"]["Action"], by_sid["Releases"]["Resource"]),
                         ("s3:GetObject", {"Fn::Sub": "${AnalysisBucket.Arn}/releases/*"}))
        self.assertEqual(set(by_sid), {"WorkerParameters", "OnlyWorkerParameters", "Releases"})

    def test_budget_is_optional_and_alerts_on_actual_and_forecast(self):
        budget = self.resources["AccountBudget"]
        self.assertEqual(budget["Condition"], "WithBudget")
        notifications = {(item["Notification"]["NotificationType"], item["Notification"]["Threshold"])
                         for item in budget["Properties"]["NotificationsWithSubscribers"]}
        self.assertEqual(notifications, {("ACTUAL", 90), ("ACTUAL", 100), ("FORECASTED", 100)})
        self.assertNotIn("CostFilters", budget["Properties"]["Budget"])
        self.assertIn("BudgetNeedsEmail", self.template["Rules"])

    def test_taggable_resources_carry_the_project_tag(self):
        for name, resource in self.resources.items():
            tags = resource["Properties"].get("Tags") or resource["Properties"].get("ResourceTags")
            if resource["Type"] in ("AWS::S3::BucketPolicy", "AWS::IAM::InstanceProfile"):
                continue
            self.assertIn(deploy.PROJECT_TAG, tags, name)

    def test_outputs(self):
        self.assertEqual(set(self.template["Outputs"]), {"BucketName", "WorkerInstanceId", "SiteInstanceProfileName",
                                                         "SiteRoleArn", "WorkerRoleArn", "WorkerSecurityGroupId"})


class WorkerFilesTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8")

    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_bootstrap_script_parses(self):
        completed = subprocess.run(["bash", "-n", str(ROOT / "deploy/worker/bootstrap.sh")], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_verification_container_uses_the_job_isolation_of_contract_section_9(self):
        script = self.read("deploy/worker/bootstrap.sh")
        run = script[script.index("run_analyzer() {"):script.index("verify_image() {")]
        for flag in ("--network none", "--read-only", "--init", '--user "$ANALYZER_UID:$ANALYZER_UID"', "--cap-drop ALL",
                     "--security-opt no-new-privileges", "--pids-limit 256", "--memory 3g", "--memory-swap 3g", "--cpus 2",
                     "--tmpfs /tmp:rw,nosuid,nodev,size=64m", "--env HOME=/work/home", "--env TMPDIR=/work/tmp",
                     "--env GHIDRA_HEADLESS_MAXMEM=1536M", "--env REA_GHIDRA_STARTUP_TIMEOUT_MS=780000",
                     "--env PYTHONDONTWRITEBYTECODE=1", "--env LANG=C.UTF-8"):
            self.assertIn(flag, run)
        self.assertEqual(len(re.findall(r"--env ", run)), 6)
        self.assertIn("readonly ANALYZER_UID=10001", script)
        self.assertNotIn("docker.sock", script)
        self.assertIn("scripts/verify-machsentry-ghidra.py --output /work/verify", script)
        self.assertIn("node scripts/rea.mjs doctor --provider ghidra --json", script)
        self.assertIn("memory.peak", script)
        self.assertIn("docker kill --signal SIGINT", run)

    def test_bootstrap_pins_docker_and_promotes_only_after_verification(self):
        script = self.read("deploy/worker/bootstrap.sh")
        self.assertIn("readonly DOCKER_VERSION=29.1.3-0ubuntu3~24.04.2", script)
        self.assertIn("--require-hashes", script)
        sequence = script[script.index("  bootstrap)\n"):script.index("  rollback)\n")]
        self.assertLess(sequence.index("verify_image"), sequence.index("promote"))
        for key in ('commit:', 'image_id:', 'built_at:', 'verified_at:', 'peakMemoryBytes:', 'ssmPrefix: "/unpacked/analysis"',
                    'heartbeatFile:', 'releaseFile:', 'stateDir: "/var/lib/machsentry-worker"'):
            self.assertIn(key, script)

    def test_dockerfile_pins_the_base_by_digest_and_runs_unprivileged(self):
        dockerfile = self.read("deploy/worker/Dockerfile")
        bases = re.findall(r"^FROM (\S+)", dockerfile, re.M)
        self.assertEqual(bases[0], "ubuntu:24.04@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc")
        self.assertEqual(bases[1:], ["base", "base"])
        self.assertIn("COPY --from=build /opt/machsentry /opt/machsentry", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        for name in ("GHIDRA_INSTALL_DIR=/opt/machsentry/.tools/", "JAVA_HOME=/opt/machsentry/.tools/",
                     "PATH=/opt/machsentry/.venv-unpack/bin:"):
            self.assertIn(name, dockerfile)
        self.assertIn("drift", dockerfile, "the image environment is checked against runtime.json")
        self.assertIn("python3 scripts/machsentry_setup.py", dockerfile)
        self.assertIn("rm -rf .tools/downloads", dockerfile)
        self.assertNotRegex(dockerfile, r"(?im)^(ENV|ARG)\s+\S*(TOKEN|SECRET|PASSWORD|API_KEY)")
        final = dockerfile[dockerfile.index("AS analyzer"):]
        self.assertNotIn("apt-get", final)

    def test_dockerignore_keeps_samples_runtimes_and_credentials_out(self):
        entries = {line.strip() for line in self.read(".dockerignore").splitlines() if line.strip() and not line.startswith("#")}
        for entry in (".git", "amostras", "reports", ".tools", ".venv-unpack", "node_modules", "dist", ".cache", ".turbo",
                      "website", "experiments", "**/.env", "**/*.pem"):
            self.assertIn(entry, entries)
        for needed in ("src", "scripts", "bridge", "macos_static", ".agents", "licenses", "package.json", "package-lock.json"):
            self.assertNotIn(needed, entries)

    def test_systemd_units_and_host_configuration(self):
        supervisor = self.read("deploy/worker/systemd/machsentry-supervisor.service")
        self.assertIn("After=docker.service network-online.target", supervisor)
        self.assertIn("Restart=on-failure", supervisor)
        self.assertIn("ExecStart=/opt/machsentry-worker/venv/bin/python -m machsentry_worker.supervisor", supervisor)
        # On tmpfs: a bootstrap stopped midway cannot keep the units down across boots.
        self.assertIn("ConditionPathExists=!/run/machsentry-worker-maintenance", supervisor)
        self.assertIn("ExecCondition=/usr/bin/python3 -I /opt/machsentry-worker/bin/maintenance-gate.py", supervisor)
        watchdog = self.read("deploy/worker/systemd/machsentry-watchdog.service")
        self.assertIn("ExecStart=/opt/machsentry-worker/venv/bin/python -m machsentry_worker.watchdog", watchdog)
        self.assertIn("ConditionPathExists=!/run/machsentry-worker-maintenance", watchdog)
        self.assertNotIn("ExecCondition", watchdog)
        script = self.read("deploy/worker/bootstrap.sh")
        self.assertIn("readonly MAINTENANCE_FILE=/run/machsentry-worker-maintenance", script)
        self.assertIn('install_if_changed "$script_dir/maintenance-gate.py" "$GATE_FILE" 0755', script)
        self.assertIn("readonly GATE_FILE=$WORKER_ROOT/bin/maintenance-gate.py", script)
        # systemd skips a unit whose ExecCondition cannot run, so every release must carry the gate.
        self.assertIn("deploy/worker/maintenance-gate.py", deploy.RELEASE_REQUIRED)
        self.assertIn("deploy/worker/maintenance-gate.py", script[script.index("validate_release() {"):script.index("enter_maintenance() {")])
        timer = self.read("deploy/worker/systemd/machsentry-watchdog.timer")
        self.assertIn("OnBootSec=60s", timer)
        self.assertIn("OnCalendar=*-*-* *:*:00", timer)
        daemon = json.loads(self.read("deploy/worker/docker-daemon.json"))
        self.assertEqual(daemon, {"log-driver": "json-file", "log-opts": {"max-size": "10m", "max-file": "2"},
                                  "no-new-privileges": True, "icc": False, "userland-proxy": False, "live-restore": False})
        journald = self.read("deploy/worker/journald.conf")
        self.assertIn("MaxRetentionSec=7day", journald)
        self.assertIn("SystemMaxUse=200M", journald)


def load_gate():
    spec = importlib.util.spec_from_file_location("maintenance_gate", ROOT / "deploy/worker/maintenance-gate.py")
    module = importlib.util.module_from_spec(spec)
    with unittest.mock.patch.object(sys, "dont_write_bytecode", True):  # no __pycache__ next to the release files
        spec.loader.exec_module(module)
    return module


class FakeImds:
    """urlopen double for IMDSv2: a token, then the tag (404 when absent)."""

    def __init__(self, tag=None, error=None) -> None:
        self.tag, self.error, self.requests = tag, error, []

    def __call__(self, request, timeout):
        self.requests.append((request.get_method(), request.full_url, dict(request.header_items())))
        if self.error:
            raise self.error
        if request.full_url.endswith("/api/token"):
            return io.BytesIO(b"imds-token")
        if self.tag is None:
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", None, None)
        return io.BytesIO(self.tag.encode())


@unittest.skipUnless(sys.version_info >= (3, 10), "the gate runs on the worker's Python 3.12")
class MaintenanceGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = load_gate()

    def run_gate(self, imds: FakeImds) -> int:
        with unittest.mock.patch("sys.stderr", io.StringIO()):
            return self.gate.main(urlopen=imds, now=NOW)

    def test_shares_the_tag_and_the_window_with_the_deploy_script(self):
        self.assertEqual(self.gate.TAG, deploy.MAINTENANCE_TAG)
        self.assertEqual(self.gate.MAX_AGE_SECONDS, deploy.MAINTENANCE_START_SECONDS)

    def test_a_recent_tag_skips_the_start(self):
        value = deploy.format_maintenance({"action": "bootstrap", "commit": COMMIT[:12], "since": "2026-10-18T11:50:00Z"})
        imds = FakeImds(value)
        self.assertEqual(self.run_gate(imds), 1)
        (method, url, _), (_, tag_url, headers) = imds.requests
        self.assertEqual((method, url), ("PUT", "http://169.254.169.254/latest/api/token"))
        self.assertEqual(tag_url, f"http://169.254.169.254/latest/meta-data/tags/instance/{deploy.MAINTENANCE_TAG}")
        self.assertEqual(headers["X-aws-ec2-metadata-token"], "imds-token")

    def test_everything_else_starts_the_supervisor(self):
        server_error = urllib.error.HTTPError("http://imds", 500, "error", None, None)
        self.addCleanup(server_error.close)
        for imds in (FakeImds(None), FakeImds("bootstrap since=2026-10-18T10:59:59Z"), FakeImds("bootstrap commit=abc"),
                     FakeImds("bootstrap since=yesterday"), FakeImds(error=urllib.error.URLError("no route")),
                     FakeImds(error=server_error)):
            self.assertEqual(self.run_gate(imds), 0, imds.tag or imds.error)


def shell_functions(names) -> str:
    """bash sources of the named bootstrap.sh functions, to run them against stubs."""
    source = (ROOT / "deploy/worker/bootstrap.sh").read_text(encoding="utf-8")
    parts = []
    for name in names:
        match = re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.M | re.S)
        assert match, name
        parts.append(match.group(0))
    return "\n\n".join(parts)


SYSTEMCTL_STUB = r"""#!/bin/sh
printf '%s\n' "$*" >>"$STUB_LOG"
command=$1
shift
case $command in
  is-active) [ "$1" != --quiet ] || shift; [ -e "$UNITS/$1" ] ;;
  start) for unit; do touch "$UNITS/$unit"; [ "$unit" != machsentry-supervisor.service ] || { mkdir -p "$(dirname "$HEARTBEAT")"; touch "$HEARTBEAT"; }; done ;;
  stop) for unit; do rm -f "$UNITS/$unit"; done ;;
esac
"""
DOCKER_STUB = r"""#!/bin/sh
printf 'docker %s\n' "$*" >>"$STUB_LOG"
[ "$1" != ps ] || cat "$DOCKER_JOBS" 2>/dev/null
exit 0
"""
PYTHON_STUB = r"""#!/bin/sh
if [ "$1" = -m ] && [ "$2" = venv ]; then
  mkdir -p "$3/bin"
  cp "$VENV_PYTHON" "$3/bin/python"
  chmod +x "$3/bin/python"
  exit 0
fi
exec "$REAL_PYTHON" "$@"
"""
# The venv's python: pip fails on the lock when PIP_FAIL=1; the package build writes into its source.
VENV_PYTHON_STUB = r"""#!/bin/sh
case "$*" in
  *" -r "*) [ "${PIP_FAIL:-0}" = 0 ] || exit 1 ;;
  *--no-deps*) for last; do :; done; mkdir -p "$last/build"; touch "$(dirname "$0")/../installed" ;;
esac
exit 0
"""


@unittest.skipUnless(os.name == "posix" and shutil.which("bash") and shutil.which("flock") and shutil.which("sha256sum"),
                     "needs Linux bash, flock and coreutils")
class WorkerShellTests(unittest.TestCase):
    """The SSM wrapper and bootstrap.sh's maintenance, venv and exit paths, with systemctl, docker and venv stubs."""

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name)
        stubs = self.root / "bin"
        stubs.mkdir()
        for name, body in (("systemctl", SYSTEMCTL_STUB), ("docker", DOCKER_STUB), ("python3", PYTHON_STUB),
                           ("venv-python", VENV_PYTHON_STUB)):
            (stubs / name).write_text(body, encoding="utf-8")
            (stubs / name).chmod(0o755)
        self.units = self.root / "units"
        self.units.mkdir()
        self.log = self.root / "stub.log"
        self.heartbeat = self.root / "run/machsentry-worker/heartbeat"
        self.env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}", ROOT=str(self.root), STUB_LOG=str(self.log),
                        UNITS=str(self.units), HEARTBEAT=str(self.heartbeat), DOCKER_JOBS=str(self.root / "jobs.txt"),
                        VENV_PYTHON=str(stubs / "venv-python"), REAL_PYTHON=sys.executable,
                        WRAPPER_ARGS=str(self.root / "wrapper-args.txt"))

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def active(self, *units: str) -> None:
        for unit in units:
            (self.units / unit).touch()

    def stub_log(self) -> list:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def bootstrap(self, scenario: str, mode: str = "bootstrap", force: int = 0) -> subprocess.CompletedProcess:
        harness = "\n".join([
            "set -euo pipefail",
            "exec 3>&1 4>&2",
            'STATE_DIR=$ROOT/state; WORKER_ROOT=$ROOT/opt; MAINTENANCE_FILE=$ROOT/run/machsentry-worker-maintenance',
            "HEARTBEAT_FILE=$HEARTBEAT; log_file=$ROOT/bootstrap.log",
            f"mode={mode}; force={force}; commit={COMMIT}; release_dir=$ROOT/release",
            "stage=init; error_message=''; maintenance_entered=0; supervisor_was_active=0; watchdog_was_active=0",
            "venv_incoming=''; active_container=''; verify_root=''; verify_work=''",
            'mkdir -p "$STATE_DIR" "$WORKER_ROOT/venvs" "$ROOT/run"; : >"$log_file"',
            shell_functions(("progress", "die", "failure_summary", "cleanup_verify_root", "wait_heartbeat", "restore_units",
                             "on_exit", "job_in_progress", "enter_maintenance", "install_supervisor")),
            "trap on_exit EXIT",
            scenario,
        ])
        return subprocess.run(["bash", "-c", harness], env=self.env, capture_output=True, text=True, timeout=120)

    def maintenance_file(self) -> Path:
        return self.root / "run/machsentry-worker-maintenance"

    def test_a_job_in_progress_is_refused_before_anything_stops(self):
        self.active("machsentry-supervisor.service", "machsentry-watchdog.timer")
        (self.root / "jobs.txt").write_text("machsentry-job-1\n", encoding="utf-8")
        completed = self.bootstrap("enter_maintenance")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        summary = deploy.last_json_line(completed.stdout)
        self.assertEqual((summary["stage"], summary["supervisorRunning"]), ("maintenance", True))
        self.assertTrue(summary["error"].startswith("analysis container machsentry-job-1 is in progress"), summary)
        self.assertFalse([line for line in self.stub_log() if line.startswith("stop")])
        self.assertFalse(self.maintenance_file().exists())
        self.assertEqual(self.bootstrap("enter_maintenance", force=1).returncode, 0)

    def test_the_ai_phase_counts_as_a_job_while_the_supervisor_runs(self):
        (self.root / "state").mkdir()
        (self.root / "state/state.json").write_text(json.dumps({"schema": 1, "active": {"jobId": "j-1", "attempt": 2}}), encoding="utf-8")
        self.active("machsentry-supervisor.service")
        completed = self.bootstrap("enter_maintenance")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("job j-1 attempt 2 is in progress", deploy.last_json_line(completed.stdout)["error"])
        # Without a running supervisor the recorded attempt is a leftover that its next boot reports.
        (self.units / "machsentry-supervisor.service").unlink()
        self.assertEqual(self.bootstrap("enter_maintenance").returncode, 0)

    def test_a_failed_bootstrap_removes_its_flag_and_leaves_the_watchdog_off(self):
        self.active("machsentry-supervisor.service", "machsentry-watchdog.timer")
        completed = self.bootstrap('enter_maintenance\n[ -e "$MAINTENANCE_FILE" ]\nstage=build\ndie "docker build failed"')
        self.assertEqual(completed.returncode, 1, completed.stderr)
        summary = deploy.last_json_line(completed.stdout)
        self.assertEqual((summary["stage"], summary["error"], summary["supervisorRunning"]), ("build", "docker build failed", False))
        self.assertIn("stop machsentry-supervisor.service machsentry-watchdog.timer machsentry-watchdog.service", self.stub_log())
        self.assertFalse([line for line in self.stub_log() if line.startswith("start")])
        self.assertFalse(self.maintenance_file().exists())
        self.assertEqual(list(self.units.iterdir()), [])

    def test_a_verification_restarts_the_supervisor_before_the_watchdog(self):
        self.active("machsentry-supervisor.service", "machsentry-watchdog.timer")
        completed = self.bootstrap("enter_maintenance", mode="verify")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        starts = [line for line in self.stub_log() if line.startswith("start")]
        self.assertEqual(starts, ["start machsentry-supervisor.service", "start machsentry-watchdog.timer"])
        self.assertTrue(self.heartbeat.exists())
        self.assertFalse(self.maintenance_file().exists())

    def test_a_verification_leaves_stopped_units_stopped(self):
        completed = self.bootstrap("enter_maintenance", mode="verify")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse([line for line in self.stub_log() if line.startswith("start")])

    def release_tree(self) -> None:
        worker = self.root / "release/worker"
        (worker / "machsentry_worker").mkdir(parents=True)
        (worker / "pyproject.toml").write_text("[project]\nname = 'machsentry-worker'\n", encoding="utf-8")
        (worker / "requirements.lock.txt").write_text("# synthetic\n", encoding="utf-8")
        (worker / "machsentry_worker/__init__.py").write_text("", encoding="utf-8")

    def venv(self) -> Path:
        return self.root / "opt/venvs" / COMMIT

    def leftovers(self) -> list:
        return sorted(path.name for path in (self.root / "opt/venvs").iterdir() if path.name.startswith("."))

    def test_the_supervisor_venv_is_built_from_a_copy_and_reused(self):
        self.release_tree()
        completed = self.bootstrap("install_supervisor\ninstall_supervisor")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"supervisor venv for {COMMIT} already installed", completed.stdout)
        self.assertTrue((self.venv() / "installed").exists())
        self.assertRegex((self.venv() / ".machsentry-complete").read_text(encoding="utf-8"), r"^[0-9a-f]{64}\n$")
        self.assertFalse((self.root / "release/worker/build").exists(), "the release stays a plain git archive")
        self.assertEqual(self.leftovers(), [])

    def test_a_failed_install_keeps_the_active_venv(self):
        self.release_tree()
        self.venv().mkdir(parents=True)
        (self.venv() / ".machsentry-complete").write_text("stale\n", encoding="utf-8")
        (self.venv() / "sentinel").touch()
        self.env["PIP_FAIL"] = "1"
        completed = self.bootstrap("install_supervisor")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(deploy.last_json_line(completed.stdout)["stage"], "supervisor")
        self.assertTrue((self.venv() / "sentinel").exists())
        self.assertEqual((self.venv() / ".machsentry-complete").read_text(encoding="utf-8"), "stale\n")
        self.assertEqual(self.leftovers(), [])
        self.env["PIP_FAIL"] = "0"
        self.assertEqual(self.bootstrap("install_supervisor").returncode, 0)
        self.assertFalse((self.venv() / "sentinel").exists())
        self.assertTrue((self.venv() / "installed").exists())
        self.assertEqual(self.leftovers(), [])

    def wrapper(self, digest=None) -> subprocess.CompletedProcess:
        source = self.root / "source"
        stub = source / "deploy/worker/bootstrap.sh"
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text('printf "%s\\n" "$@" >"$WRAPPER_ARGS"\n', encoding="utf-8")
        archive = self.root / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(source / "deploy", arcname="deploy")
        self.digest = deploy.file_sha256(archive)
        script = deploy.fill(deploy.BOOTSTRAP_SCRIPT, COMMIT=COMMIT, SHA256=digest or self.digest, URL=shlex.quote(archive.as_uri()),
                             RELEASES=str(self.root / "opt/releases"), STATE=str(self.root / "state"), REGION="us-east-2", EXTRA="")
        return subprocess.run(["bash", "-c", script], env=self.env, capture_output=True, text=True, timeout=120)

    def test_the_wrapper_hands_a_checked_release_to_bootstrap_sh(self):
        completed = self.wrapper()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        releases = self.root / "opt/releases"
        self.assertEqual((self.root / "wrapper-args.txt").read_text(encoding="utf-8").splitlines(),
                         ["--release-dir", f"{releases}/{COMMIT}", "--commit", COMMIT, "--region", "us-east-2"])
        self.assertEqual((releases / f"{COMMIT}.sha256").read_text(encoding="utf-8"), self.digest + "\n")
        self.assertEqual(self.stub_log(), [])

    def test_a_failed_download_stops_nothing_and_leaves_nothing_behind(self):
        self.active("machsentry-supervisor.service")
        completed = self.wrapper(DIGEST)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("sha256 mismatch", completed.stderr)
        summary = deploy.last_json_line(completed.stdout)
        self.assertEqual(summary, {"ok": False, "action": "bootstrap", "stage": "download", "exitStatus": 1,
                                   "error": "downloading the release archive failed (exit 1)", "supervisorRunning": True})
        self.assertEqual(list((self.root / "opt/releases").iterdir()), [])
        self.assertFalse((self.root / "wrapper-args.txt").exists())
        self.assertEqual(self.stub_log(), ["is-active --quiet machsentry-supervisor.service"])
        self.assertEqual([path for path in self.root.rglob("*maintenance*")], [])

    def test_the_wrapper_refuses_while_another_run_holds_the_lock(self):
        import fcntl
        (self.root / "state").mkdir()
        with open(self.root / "state/bootstrap.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            completed = self.wrapper()
        self.assertEqual(completed.returncode, 1)
        self.assertIn("another bootstrap.sh run holds", deploy.last_json_line(completed.stdout)["error"])
        self.assertFalse((self.root / "wrapper-args.txt").exists())


if __name__ == "__main__":
    unittest.main()
