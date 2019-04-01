import boto3
import collections
import dataclasses
import enum
import itertools
import os
import socket
import sys
import time
import pssh.clients
import gevent
import subprocess
import random
import math
from pprint import pprint
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Union

TESTING = False

REFRESH_INTERVAL = 5.0

# ordered in the order we want to place instances in

NUM_NODES = 5

print()
print(sys.argv)
if len(sys.argv) == 2:
    NUM_NODES = int(sys.argv[1])
print(f"setting NUM_NODES={NUM_NODES}")


REGIONS = {
    "eu-west-3": "EU (Paris, eu-west-3)",
    "us-east-1": "USA Ost (Nord-Virginia, us-east1)",
    "us-west-1": "USA West (Nordkalifornien, us-west-1)",
    "ap-southeast-1": "Asien-Pazifik (Singapur, ap-southeast-1)",
    "ap-northeast-1": "Asien-Pazifik (Tokio, ap-northeast-1)",
    "eu-west-1": "EU (Irland, eu-west-1)",
    "ca-central-1": "Kanada (Central, ca-central-1)",
    "eu-west-2": "EU (London, eu-west-2)",

    # "ap-south-1": "Asien-Pazifik (Mumbai, ap-south-1)",             # limited to 10 micro
    # "sa-east-1": "Südamerika (São Paulo, sa-east-1)",               # limited to 5 micro!
    # "eu-central-1": "EU (Frankfurt, eu-central-1)",                 # limited to 10 micro
    # "eu-north-1": "EU (Stockholm, eu-north-1)",        # instance configuration not supported
    # "us-east-2": "USA Ost (Ohio, us-east-2)",
    # "us-west-2": "USA West (Oregon, us-west-2)",
    # "ap-northeast-2": "Asien-Pazifik (Seoul, ap-northeast-2)",
    # "ap-southeast-2": "Asien-Pazifik (Sydney, ap-southeast-2)",       # limited to 5 micro
    # "eu-west-2": "EU (London, eu-west-2)",
}

if TESTING:
    REGIONS = {
        "eu-central-1": "EU (Frankfurt, eu-central-1)",
        "us-east-1": "USA Ost (Nord-Virginia, us-east1)",
        "us-west-1": "USA West (Nordkalifornien, us-west-1)",
        "ap-southeast-1": "Asien-Pazifik (Singapur, ap-southeast-1)",
        "ap-northeast-1": "Asien-Pazifik (Tokio, ap-northeast-1)",
    }

INSTANCE_COUNT_PER_REGION: Dict[str, int] = collections.defaultdict(int)
_t_num_nodes = NUM_NODES
while _t_num_nodes:
    for r in REGIONS:
        INSTANCE_COUNT_PER_REGION[r] += 1
        _t_num_nodes -= 1
        if _t_num_nodes == 0:
            break

AMI_IMAGE_ID_PER_REGION: Dict[str, str] = {}

AWS_DIR = os.path.abspath(os.path.dirname(__file__))
NETWORK_CONFIG_PATH = os.path.abspath(os.path.join(AWS_DIR, '..', 'config', 'network', 'amazon.txt'))
PACK_SCRIPT_PATH = os.path.join(AWS_DIR, "pack-hydrand.sh")
SETUP_INSTANCE_SCRIPT_PATH = os.path.join(AWS_DIR, "setup-instance.sh")
with open(SETUP_INSTANCE_SCRIPT_PATH, 'r') as f:
    SETUP_INSTANCE_SCRIPT = f.read()

DATA_PATH = os.path.join(AWS_DIR, 'data')
RESULTS_PATH = os.path.join(AWS_DIR, 'data', 'results.csv')

ec2 = {region: boto3.resource("ec2", region_name=region) for region in REGIONS}
ec2_clients = {region: boto3.client("ec2", region_name=region) for region in REGIONS}

ssh: pssh.clients.ParallelSSHClient = None  # parallel ssh client from pssh library


class InstanceState(enum.IntEnum):
    PENDING = enum.auto()
    RUNNING = enum.auto()
    SHUTTING_DOWN = enum.auto()
    TERMINATED = enum.auto()
    STOPPING = enum.auto()
    STOPPED = enum.auto()

    @staticmethod
    def parse(name):
        return InstanceState[name.upper().replace("-", "_")]


class Instance:

    def __init__(self, id: str, region: str, dnsname: str = None, state: InstanceState = None):
        self.id = id
        self.region = region
        self.dnsname = dnsname or None
        self.ssh_ok = False
        self.status = None
        self.state = state
        self.raw_info = None
        self.raw_status = None

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        if value == InstanceState.RUNNING:
            self.ssh_ok = self.ssh_ok or test_ssh_connection(self)
        else:
            self.ssh_ok = False
        self._state = value

    def load_properties(self, instance_dict, status_dict):
        if self.id:
            assert self.id == instance_dict['InstanceId']
        else:
            self.id = instance_dict['InstanceId']
        self.raw_info = instance_dict
        self.raw_status = status_dict
        self.dnsname = instance_dict['PublicDnsName']
        self.state = InstanceState.parse(instance_dict['State']['Name'])
        self.status = status_dict['InstanceStatus']['Status'] if status_dict else None

    def __repr__(self):
        return (
            f"Instance(id='{self.id}', region='{self.region}', dnsname='{self.dnsname}', "
            f"state='{self.state.name}', ssh_ok='{self.ssh_ok}')"
        )


class Instances:

    def __init__(self, instances_dict: Optional[Dict[str, Instance]] = None):
        self._instances_dict: Dict[str, Instance] = instances_dict or {}

    def by_region(self, return_dict=False):
        d = collections.defaultdict(Instances)
        for item in self._instances_dict.values():
            d[item.region][item.id] = item
        if return_dict:
            return d
        return d.items()

    @property
    def ids(self):
        return [key for key in self._instances_dict]

    @property
    def all(self):
        return self

    @property
    def running(self):
        return Instances({i.id: i for i in self._instances_dict.values() if i.state == InstanceState.RUNNING})

    @property
    def pending(self):
        return Instances({i.id: i for i in self._instances_dict.values() if i.state == InstanceState.PENDING})

    @property
    def stopped(self):
        return Instances({i.id: i for i in self._instances_dict.values() if i.state == InstanceState.STOPPED})

    @property
    def stopping(self):
        return Instances({i.id: i for i in self._instances_dict.values() if i.state == InstanceState.STOPPING})

    @property
    def terminated(self):
        return Instances({i.id: i for i in self._instances_dict.values() if i.state == InstanceState.TERMINATED})

    def __len__(self):
        return len(self._instances_dict)

    def __getitem__(self, index_or_key: Union[int, str]):
        if isinstance(index_or_key, int):
            if index_or_key < 0:
                index_or_key += len(self._instances_dict)
            for i, value in enumerate(self._instances_dict.values()):
                if i == index_or_key:
                    return value
            raise IndexError
        else:
            return self._instances_dict[index_or_key]

    def get(self, key, default=None):
        return self._instances_dict.get(key, default)

    def __setitem__(self, key: str, value: Instance):
        if key in self._instances_dict:
            raise KeyError('Cannot set the same instance twice, use refresh_infos() to update the existing instance.')
        self._instances_dict[key] = value

    def __repr__(self):
        return repr(list(self._instances_dict.values()))


instances = Instances()
_instances = instances


class DryRunHandler:

    def __init__(self, dryrun=False):
        self.dryrun = dryrun

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        # returning False reraising any exception passed to this function
        if exc_value is None:
            assert not self.dryrun
            return True
        if self.dryrun:
            return 'DryRunOperation' in str(exc_value)
        return False

# ec2-3-122-234-82.eu-central-1.compute.amazonaws.com


def lookup(what) -> Instances:
    if isinstance(what, Instances):
        return what
    if isinstance(what, Instance):
        return Instances({what.id: what})
    if isinstance(what, str) or isinstance(what, int):
        i = instances[what]
        return Instances({i.id: i})
    if isinstance(what, Iterable):
        d = {}
        for x in what:
            i = x if isinstance(x, Instance) else instances[x]
            d[i.id] = i
        return Instances(d)
    raise TypeError()


def get_instance_id(dnsname):
    for i in instances:
        if i.dnsname == dnsname:
            return i.id
    raise ValueError(f"no instance with dnsname {dnsname} found")


def status():
    refresh()
    print()
    for i in instances:
        print(i)
    print()
    print(f"number of running instances: {len(instances.running)}")
    for x, v in instances.running.by_region():
        print(f"    {x} {REGIONS[x]}: {len(v)}")


def refresh(what=None):
    """ Uses the AWS API to refresh the information for all instances, considering all regions.
        If the parameter 'what' is provided, only the specified instances are queried.
    """
    if what is None:
        what = instances
        grouped_instances = zip(REGIONS, itertools.repeat(None))
    else:
        what = lookup(what)
        grouped_instances = what.by_region()

    for region, instances_per_region in grouped_instances:
        ids = [] if instances_per_region is None else instances_per_region.ids
        infos = []
        for reservation in ec2_clients[region].describe_instances(InstanceIds=ids)['Reservations']:
            for i in reservation['Instances']:
                infos.append(i)
        statuses = {}
        for status in ec2_clients[region].describe_instance_status(InstanceIds=ids)['InstanceStatuses']:
            statuses[status['InstanceId']] = status
        for info in infos:
            i = what.get(info['InstanceId'])
            if not i:
                assert instances.get(info['InstanceId']) is None and what is instances
                i = Instance(info['InstanceId'], region)
                instances[i.id] = i
            i.load_properties(info, statuses.get(i.id))


def refresh_until(break_condition: Callable[[], bool], instances: Instances, verbose: bool = True):
    while not break_condition():
        time.sleep(REFRESH_INTERVAL)
        refresh(instances)
        if verbose:
            print(end=".", flush=True)


def wait_for_startup(what=None):
    what = instances if what is None else lookup(what)
    print(f"waiting for startup...", end='', flush=True)
    refresh_until(lambda: all(i.ssh_ok for i in what), instances=what)
    print(" done")


def start_instances(what=None, dryrun=False):
    what = _instances.stopped if what is None else lookup(what)
    if not all(i.state == InstanceState.STOPPED for i in what):
        raise ValueError("instance(s) in invalid state")

    print(f"starting instance(s): {', '.join(what.ids)}...", end='', flush=True)
    for region, instances in what.by_region():
        with DryRunHandler(dryrun):
            ec2_clients[region].start_instances(InstanceIds=instances.ids, DryRun=dryrun)
        if not dryrun:
            for i in instances:
                i.state = InstanceState.PENDING
    if not dryrun:
        refresh_until(lambda: all(i.ssh_ok for i in what), instances=what)
    print(" done")


def stop_instances(what=None, dryrun=False):
    what = _instances.running if what is None else lookup(what)
    if not all(i.state == InstanceState.RUNNING for i in what):
        raise ValueError("instance(s) in invalid state")
    print(f"stopping instance(s): {', '.join(what.ids)}...", end='', flush=True)
    for region, instances in what.by_region():
        with DryRunHandler(dryrun):
            ec2_clients[region].stop_instances(InstanceIds=instances.ids, DryRun=dryrun)
        if not dryrun:
            for i in instances:
                i.state = InstanceState.STOPPING
    if not dryrun:
        refresh_until(lambda: all(i.state in [InstanceState.STOPPED,
                                              InstanceState.TERMINATED] for i in what), instances=what)
    print(" done")


def terminate_instances(what=None, dryrun=False):
    if what is None:
        what = [i for i in _instances if i.state != InstanceState.TERMINATED]
    what = lookup(what)
    print(f"terminating instance(s): {', '.join(what.ids)}...", end='', flush=True)
    for region, instances in what.by_region():
        with DryRunHandler(dryrun):
            ec2_clients[region].terminate_instances(InstanceIds=instances.ids, DryRun=dryrun)
        if not dryrun:
            for i in instances:
                i.state = InstanceState.SHUTTING_DOWN
    if not dryrun:
        refresh_until(lambda: all(i.state == InstanceState.TERMINATED for i in what), instances=what)
    print(" done")


def reboot_instances(what=None, dryrun=False):
    what = _instances.running if what is None else lookup(what)
    if not all(i.state == InstanceState.RUNNING for i in what):
        raise ValueError("instance(s) in invalid state")
    print(f"rebooting instance(s): {', '.join(what.ids)}...", end='', flush=True)
    for region, instances in what.by_region():
        with DryRunHandler(dryrun):
            ec2_clients[region].reboot_instances(InstanceIds=instances.ids, DryRun=dryrun)
        if not dryrun:
            for i in instances:
                i.state = InstanceState.PENDING
    if not dryrun:
        refresh_until(lambda: all(i.ssh_ok for i in what), instances=what)
    print(" done")


def _create_instances(region, num_instances=1, instance_type='t2.micro', dryrun=False):
    assert instance_type in ['t2.nano', 't2.micro', 't2.small', 't2.medium']
    assert num_instances <= 20, "check instance limits (10 for t2.micro, 20 for t2.small/t2.medium"

    load_ami_image_ids()

    print(f"    {REGIONS[region] + ':': <41} launching {num_instances: >3} instances... ", end="", flush=True)
    result = None
    with DryRunHandler(dryrun):
        result = ec2[region].create_instances(
            ImageId=AMI_IMAGE_ID_PER_REGION[region],
            InstanceType='t2.micro',
            KeyName='hydrand',
            MinCount=num_instances,
            MaxCount=num_instances,
            UserData=SETUP_INSTANCE_SCRIPT,
            SecurityGroups=['hydrand'],
            InstanceInitiatedShutdownBehavior='terminate',
            DryRun=dryrun,
        )
    print("done")
    return result


def launch_instances(instance_count_per_region=None, dryrun=False):
    if instance_count_per_region is None:
        instance_count_per_region = INSTANCE_COUNT_PER_REGION

    load_ami_image_ids()

    instance_count_per_region = {rid: ctr for rid, ctr in instance_count_per_region.items() if ctr > 0}
    running_by_region = instances.running.by_region(return_dict=True)

    to_launch = 0
    print()
    print("launch initiated, aiming to launch the following instances:")
    for region in instance_count_per_region:
        count = instance_count_per_region[region]
        count = max(0, count - len(running_by_region.get(region, [])))
        to_launch += count
        instance_count_per_region[region] = count
        print(f"    {REGIONS[region] + ':': <41} {count: >3}")

    print()
    print(f"number of currecly running instances:         {len(instances.running): >3}")
    print(f"total number of instance to launch:           {to_launch: >3}")
    print(f"total number of instance after launch:        {len(instances.running) + to_launch: >3}")
    print()
    try:
        r = input("type 'confirm' and press enter to continue: ")
        if r != 'confirm':
            print('aborted')
            return
    except KeyboardInterrupt:
        print('\naborted')
        return
    print()

    print("performing launch...")
    print()
    for region, count in instance_count_per_region.items():
        if count > 0:
            _create_instances(region, count, dryrun=dryrun)

    time.sleep(1)
    refresh()


def test_ssh_connection(what):
    what = lookup(what)
    if not all(i.dnsname for i in what):
        raise ValueError("instance(s) in invalid state, dnsname(s) not available")
    for i in what:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(REFRESH_INTERVAL)
            s.connect((i.dnsname, 22))
            s.shutdown(socket.SHUT_RDWR)
        except socket.timeout:
            return False
        except ConnectionError as e:
            print(e)
            return False
        finally:
            s.close()
    return True


def assign_security_group_to_all_instances(group_name):
    # directly set at launch of instance for now
    raise NotImplementedError


def create_or_update_security_groups():
    for region, region_name in REGIONS.items():
        for g in ec2[region].security_groups.all():
            if g.group_name == 'hydrand':
                print(f"{region_name}: deleting security group...", end='', flush=True)
                g.delete()
                print(" done")

        print(f"{region_name}: creating new security group...", end='', flush=True)
        g = ec2[region].create_security_group(
            GroupName='hydrand', Description='hydrand security group (script generated)')
        print(" done")

        print(f"{region_name}: updating permissions...", end='', flush=True)
        g.authorize_ingress(
            FromPort=22,
            ToPort=22,
            IpProtocol='tcp',
            CidrIp='0.0.0.0/0',
        )
        g.authorize_ingress(
            FromPort=5000,
            ToPort=5000,
            IpProtocol='tcp',
            CidrIp='0.0.0.0/0',
        )
        print(" done")


@dataclasses.dataclass
class SSHResult:
    id: int
    dnsname: str
    exit_code: int
    stdout: List[str]
    stderr: List[str]
    stdin: List[str]
    error: Any

    def __str__(self):
        if self.exit_code == 0:
            return self.stdout
        return f"ERROR({self.exit_code}): {self.stderr}"

    def __repr__(self):
        return f"SSHResult({repr(self.id)}, {repr(str(self))})"


def ssh_connect():
    global ssh
    ssh_instances = instances.running

    hosts = [i.dnsname for i in ssh_instances]
    ids = [i.id for i in ssh_instances]
    fmtlen = max(len(i) for i in ids) + 1

    if not hosts:
        print("no hosts to connect to, aborting")
        return

    print()
    print(f"connecting to {len(ssh_instances)} instance(s)... ", end='', flush=True)

    if ssh is None:
        ssh = pssh.clients.ParallelSSHClient(hosts, user='ec2-user', pkey="~/.ssh/hydrand.pem",
                                             keepalive_seconds=30, allow_agent=False)
    else:
        ssh.hosts = hosts

    results = ssh_run("date")
    print("done")
    for result in results:
        print(f"connected to {result.id+':': <{fmtlen}} {result.stdout}")


def ssh_run(command, raise_exception_on_failure=True, sudo=False, user=None, stop_on_errors=True,
            use_pty=False, host_args=None, shell=None,
            encoding='utf-8', timeout=None, greenlet_timeout=None):

    if isinstance(command, list):
        last_result = None
        for c in command:
            last_result = ssh_run(c, raise_exception_on_failure, sudo, user, raise_exception_on_failure, sudo, user,
                                  stop_on_errors, use_pty, host_args, shell, encoding, greenlet_timeout)
        return last_result

    output = ssh.run_command(command, sudo, user, stop_on_errors, use_pty,
                             host_args, shell, encoding, timeout, greenlet_timeout)
    ssh.join(output)

    results = []
    for k, v in output.items():
        results.append(
            SSHResult(id=get_instance_id(k), dnsname=k, exit_code=v.exit_code, error=v.exception,
                      stdout='\n'.join(list(v.stdout)),
                      stderr='\n'.join(list(v.stderr)),
                      stdin=v.stdin))

    if raise_exception_on_failure and any(r.exit_code != 0 for r in results):
        for r in results:
            print(repr(r))
        raise RuntimeError(f"execution of command '{command}' failed at least for one instance", command)
    return results


def ssh_run_raw(command, sudo=False, user=None, stop_on_errors=True,
                use_pty=False, host_args=None, shell=None,
                encoding='utf-8', timeout=None, greenlet_timeout=None):

    output = ssh.run_command(command, sudo, user, stop_on_errors, use_pty,
                             host_args, shell, encoding, timeout, greenlet_timeout)
    ssh.join(output)
    return output


def Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs):
    p = subprocess.Popen(args, stdout=stdout, stderr=stderr, **kwargs)
    output, _ = p.communicate()
    assert p.returncode == 0, f"failed to execute {args}"
    return output.decode().strip()


def load_ami_image_ids():
    if AMI_IMAGE_ID_PER_REGION:
        return
    print()
    for region in REGIONS:
        print(f"{REGIONS[region] + ':': <41} search for amazon machine image... ", end="", flush=True)
        images = ec2[region].images.filter(
            Owners=['amazon'],
            Filters=[{
                'Name': 'name',
                'Values': ['amzn2-ami-hvm-2.0.????????-x86_64-gp2'],
            }])
        image = sorted(images, key=lambda i: i.creation_date)[-1]
        AMI_IMAGE_ID_PER_REGION[region] = image.id
        print(f"done ({image.id})")


def update_hydrand(always_unpack=False):
    if not ssh:
        ssh_connect()
        print()

    update_hydrand_network_config()

    print("packing current hydrand version... ", end="", flush=True)
    assert subprocess.call([PACK_SCRIPT_PATH], stdout=subprocess.DEVNULL) == 0, "packing script failed to run"
    print("done")

    all_hosts = [i.dnsname for i in instances.running]
    updated_hosts = set()

    ssh_run("cd /home/ec2-user")
    for file in ["hydrand-base.zip", "hydrand.zip"]:
        local_path = os.path.join(AWS_DIR, file)
        remote_path = f"/home/ec2-user/{file}"

        digest = Popen(['sha1sum', local_path]).split()[0]

        hosts_to_update = []
        for result in ssh_run(f'[ -f {file} ] && sha1sum {file} || echo ""'):
            if not result.stdout or result.stdout.split()[0] != digest:
                updated_hosts.add(result.dnsname)
                hosts_to_update.append(result.dnsname)

        if hosts_to_update:
            print(f"({digest}) updating file {file: <16} on {len(hosts_to_update)} instance(s)... ", end="", flush=True)
            ssh.hosts = hosts_to_update
            gevent.joinall(ssh.scp_send(local_path, remote_path), raise_error=True)
            ssh.hosts = all_hosts
            print("done")
        else:
            print(f"({digest}) file {file: <16} already on current version on all instances")

    updated_hosts = all_hosts if always_unpack else list(updated_hosts)
    if updated_hosts:
        print(f"unpacking new verions on {len(updated_hosts)} instance(s)... ", end="", flush=True)
        ssh.hosts = updated_hosts
        ssh_run("rm -rf hydrand.py && unzip hydrand-base.zip && unzip hydrand.zip")
        ssh.hosts = all_hosts
        print("done")
        print("all instances updated to the newest version")
    else:
        print("all instances already on the newest version")


def update_hydrand_network_config():
    try:
        with open(NETWORK_CONFIG_PATH, 'r') as f:
            cfg = f.read()
    except FileNotFoundError:
        cfg = ''

    dnsnames = [i.dnsname for i in instances.running]
    dnsnames.sort()
    newcfg = ''.join(f"{dnsname}:5000\n" for dnsname in dnsnames)
    if cfg != newcfg:
        print()
        print(f"updating {NETWORK_CONFIG_PATH} to currently running instances")
        print()
        with open(NETWORK_CONFIG_PATH, 'w') as f:
            f.write(newcfg)


hydrand_processes = None


def cleanup_benchmark():
    global hydrand_processes
    if hydrand_processes:
        print("stopping processes gracefully")
        for x in hydrand_processes.values():
            x.channel.close()
        print("wait for 5 seconds...")
        time.sleep(5)

    print("checking for running python processes (and killing them)")
    results = ssh_run("pkill -9 python3", raise_exception_on_failure=False)
    processed_killed = False
    for r in results:
        if r.exit_code == 0:
            processed_killed = True
    if processed_killed:
        print("forced killed at least one running process")
        print("wait for 5 seconds...")
        time.sleep(5)
    else:
        print("gracefull shutdown succeeded (or hydrand processes already stopped)")
    hydrand_processes = None


run_args = None


def run_benchmark(num_nodes, num_rounds,
                  duration=2.0, propose_duration=None, acknowledge_duration=None, vote_duration=None,
                  startup_delay=60, connection_lead_time=20, simulate_adversary=False):

    global hydrand_processes
    ssh_connect()
    cleanup_benchmark()

    assert num_nodes == len(instances.running)

    propose_duration = propose_duration or duration
    acknowledge_duration = acknowledge_duration or duration
    vote_duration = vote_duration or duration

    tstart = datetime.utcnow().replace(microsecond=0) + timedelta(seconds=startup_delay)
    tend = tstart + timedelta(seconds=num_rounds * (propose_duration + acknowledge_duration + vote_duration))
    tend = tend.replace(microsecond=0)

    if simulate_adversary:
        num_rounds_per_node = [random.randint(0, num_rounds - 1) for _ in range(math.ceil(num_nodes / 3) - 1)]
        while len(num_rounds_per_node) != num_nodes:
            num_rounds_per_node.append(num_rounds)
        random.shuffle(num_rounds_per_node)
    else:
        num_rounds_per_node = [num_rounds for _ in range(num_nodes)]

    num_rounds_per_node_dict = {dnsname: r for dnsname, r in zip(ssh.hosts, num_rounds_per_node)}

    global run_args
    run_args = {
        'num_nodes': num_nodes,
        'num_rounds': num_rounds,
        'propose_duration': propose_duration,
        'acknowledge_duration': acknowledge_duration,
        'vote_duration': vote_duration,
        'tstart': str(tstart),
        'tend': str(tend),
        # 'num_rounds_per_node': num_rounds_per_node,
        'num_rounds_per_node_dict': num_rounds_per_node_dict
    }
    print()
    print(f"starting protocol at:        {tstart}")
    print(f"protocol should complete at: {tend}")
    print(f"total duration:              {(tend - tstart).total_seconds() / 60:.0f} min")

    print()
    pprint(run_args)
    print()

    # input("press enter to confirm...")

    ssh_run("pkill -f dstat; rm -f ~/stats.log", raise_exception_on_failure=False)

    cmd = ' '.join([
        f"dstat --integer --noupdate -T -n --tcp --cpu --mem --output ~/stats.log 1 &> /dev/null &",
        f"cd /home/ec2-user/hydrand.py &&",
        f"python3 -m hydrand",
        f"--sync-mode",
        f"--start-at '{tstart}'",
        f"--connection-lead-time {connection_lead_time}",
        f"--propose-duration {propose_duration}",
        f"--acknowledge-duration {acknowledge_duration}",
        f"--vote-duration {vote_duration}",
        f"--num-rounds %d",
        "> /home/ec2-user/std.log 2>&1"
    ])
    print(cmd)

    print()

    hydrand_processes = ssh.run_command(cmd, use_pty=True, host_args=num_rounds_per_node)

    print()
    print("waiting for protocol run to complete...")
    while datetime.utcnow() < tend:
        time.sleep(1)
    print("protocol run should be finished now, waiting for 10 more seconds")
    time.sleep(10)

    print("killing dstat processes...", end="", flush=True)
    ssh_run("pkill -f dstat", raise_exception_on_failure=False)
    print("done")

    collect_results(**run_args)
    # collect_logs(**run_args)


def collect_results(num_nodes, num_rounds, propose_duration, acknowledge_duration, vote_duration,
                    tstart, tend, num_rounds_per_node_dict):
    print("collecting results...")
    results = ssh_run("cat ~/hydrand.py/output/result")

    for i, v in enumerate(results):
        if v.stdout == "OK" and num_rounds_per_node_dict[v.dnsname] != num_rounds:
            v.stdout = "EVIL"

    results_str = ','.join(f"{v.dnsname},{v.stdout}" for v in results)
    result = 'OK'
    ok_ctr = 0
    evil_ctr = 0
    failed_ctr = 0
    for v in results:
        if v.stdout == 'FAILED':
            result = 'FAILED'
            failed_ctr += 1
        elif v.stdout == "EVIL":
            evil_ctr += 1
            ok_ctr += 1
        else:
            ok_ctr += 1

    with open(RESULTS_PATH, "a") as f:
        f.write(f"{num_nodes};{num_rounds};{propose_duration};{acknowledge_duration};{vote_duration};"
                + f"{tstart};{tend};\"{results_str}\";{result}\n")

    print()
    for r in results:
        if r.stdout == 'FAILED':
            print(f"{r.dnsname}: failed")
    print()
    print(f"##########################################################")
    print(f"### RESULT: {result}")
    print(f"### OK returned by {ok_ctr} nodes (out of which {evil_ctr} aborted)")
    print(f"### FAILED returned by {failed_ctr} nodes")
    print(f"##########################################################")
    print()


def collect_logs(tstart, **kwargs):
    d = os.path.join(DATA_PATH, str(tstart))
    os.makedirs(d)
    for remote_path in ['/home/ec2-user/std.log', '/home/ec2-user/stats.log',
                        '/home/ec2-user/hydrand.py/output/node.log']:
        download_file(tstart, remote_path)


def download_file(tstart, remote_path, instances=None):
    instances = instances or _instances.running
    for i, dnsname in enumerate([i.dnsname for i in instances]):
        print(f"downloading {remote_path} from {dnsname+'...': <65} {i + 1}/{len(instances)} ", end="", flush=True)
        cmd = ' '.join([
            f'rsync -z -e "ssh -i ~/.ssh/hydrand.pem -oStrictHostKeyChecking=accept-new"',
            f'ec2-user@{dnsname}:{remote_path}',
            f'"{DATA_PATH}/{tstart}/{dnsname}_{remote_path.split("/")[-1]}"',
        ])
        subprocess.run(cmd, shell=True, check=True, stderr=subprocess.DEVNULL)
        print("done")
    print()


# def collect_log_files(tstart, **kwargs):
#     d = os.path.join(DATA_PATH, str(tstart))
#     os.makedirs(d)

#     thosts = ssh.hosts
#     ssh.hosts = random.sample(ssh.hosts, min(len(ssh.hosts), 16))
#     print(
#         f"modified ssh.hosts to only copy log files from {len(ssh.hosts)} nodes. (check that ssh_hosts is restored!)")

#     print("collecting stats.log files...")
#     e = ssh.scp_recv("/home/ec2-user/stats.log", os.path.join(DATA_PATH, "stats.log"))
#     gevent.joinall(e, raise_error=True)
#     for filename in os.listdir(DATA_PATH):
#         if filename.startswith('stats.log_'):
#             newfilename = filename.replace('stats.log_', '') + '_stats.log'
#             os.rename(os.path.join(DATA_PATH, filename), os.path.join(DATA_PATH, newfilename))

#     print("collecting node.log files...")
#     e = ssh.scp_recv("/home/ec2-user/hydrand.py/output/node.log", os.path.join(DATA_PATH, "node.log"))
#     gevent.joinall(e, raise_error=True)
#     for filename in os.listdir(DATA_PATH):
#         if filename.startswith('node.log_'):
#             newfilename = filename.replace('node.log_', '') + '_node.log'
#             os.rename(os.path.join(DATA_PATH, filename), os.path.join(DATA_PATH, newfilename))

#     ssh.hosts = thosts
#     print("restored ssh.hosts")


# def collect_and_save_results():
#     results, stats_logs, node_logs = collect_results()
#     save_result(results=results, stats_logs=stats_logs, node_logs=node_logs, **run_args)
#     print("logs files writen")
#     print()
#     print(f"#################################")
#     print(f"### RESULT: {result}")
#     print(f"### OK returned by {ok_ctr} nodes")
#     print(f"### FAILED returned by {failed_ctr} nodes")
#     print(f"#################################")
#     print()


# collect_and_save_results()
    # results, stats_logs, node_logs = collect_results()
    # save_result(num_nodes, num_rounds, propose_duration, acknowledge_duration,
    #             vote_duration, tstart, tend, results, stats_logs, node_logs)


# def collect_results():
#     print("collecting result files...")
#     results = ssh_run("cat ~/hydrand.py/output/result")
#     print("collecting stats.log files...")
#     stats_logs = ssh_run("cat ~/stats.log")
#     print("collecting node.log files...")
#     node_logs = ssh_run("cat ~/hydrand.py/output/node.log")
#     return results, stats_logs, node_logs


# def collect_and_save_results():
#     results, stats_logs, node_logs = collect_results()
#     save_result(results=results, stats_logs=stats_logs, node_logs=node_logs, **run_args)


# def save_result(num_nodes, num_rounds, propose_duration, acknowledge_duration, vote_duration,
#                 tstart, tend, results, stats_logs, node_logs):
#     results_str = ','.join(f"{v.dnsname},{v.stdout}" for v in results)
#     result = 'OK'
#     ok_ctr = 0
#     failed_ctr = 0
#     for v in results:
#         if v.stdout == 'FAILED':
#             result = 'FAILED'
#             failed_ctr += 1
#         else:
#             ok_ctr += 1

#     with open(RESULTS_PATH, "a") as f:
#         f.write(f"{num_nodes};{num_rounds};{propose_duration};{acknowledge_duration};{vote_duration};"
#                 + f"{tstart};{tend};\"{results_str}\";{result}\n")

#     d = os.path.join(DATA_PATH, str(tstart))
#     os.makedirs(d)
#     for s, n in zip(stats_logs, node_logs):
#         with open(os.path.join(d, f"{s.dnsname}_stats.log"), 'w') as f:
#             f.write(s.stdout)
#         with open(os.path.join(d, f"{n.dnsname}_node.log"), 'w') as f:
#             f.write(n.stdout)

#     print("logs files writen")
#     print()
#     print(f"#################################")
#     print(f"### RESULT: {result}")
#     print(f"### OK returned by {ok_ctr} nodes")
#     print(f"### FAILED returned by {failed_ctr} nodes")
#     print(f"#################################")
#     print()


status()
