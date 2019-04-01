from datetime import datetime, timedelta
import subprocess
import time
import atexit
import os

processes = None
pids = None
keep_logs = False

CONNECT_DELAY = 10.0
START_DELAY = 20.0

PROPOSE_DURATION = 10.0
ACKNOWLEDGE_DURATION = 10.0
VOTE_DURATION = 10.0


assert os.path.abspath(os.curdir).endswith(
    "hydrand.py"), "use hydrand.py as working dir when running local_launcher.py"

if not os.path.exists("output"):
    os.makedirs("output")


def start_node(node_id, start_time, n=7):
    with open(f"output/{node_id:03}_log.txt", "w") as logfile:
        return subprocess.Popen(
            f"""python hydrand             {node_id}
                    -n                     {n}
                    --start-at             {start_time}
                    --connection-lead-time {CONNECT_DELAY}
                    --propose-duration     {PROPOSE_DURATION}
                    --acknowledge-duration {ACKNOWLEDGE_DURATION}
                    --vote-duration        {VOTE_DURATION}
                    --fast-mode
            """.split(),
            stderr=logfile,
            stdout=logfile,
            # preexec_fn=os.setsid
        )


def start_nodes(start_time=None, n=7):
    global processes
    if processes:
        cleanup()
    if start_time is None:
        start_time = (datetime.utcnow() + timedelta(seconds=START_DELAY)).strftime("%H:%M:%S")
        print(f"starting nodes at {start_time} UTC")
    processes = [start_node(i, start_time, n) for i in range(n)]
    pids = [p.pid for p in processes]
    print(pids)


def stop_nodes():
    # The os.setsid() is passed in the argument preexec_fn so
    # it's run after the fork() and before  exec() to run the shell.
    # p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

    for p in processes:
        # os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        p.terminate()


def kill_nodes():
    for p in processes:
        p.kill()
        # os.killpg(os.getpgid(p.pid), signal.SIGKILL)


def cleanup():
    print("cleaning up...")
    if processes:
        stop_nodes()
        time.sleep(2)
        kill_nodes()

    if not keep_logs:
        for f in os.listdir('output'):
            os.remove(os.path.join('output', f))


atexit.register(cleanup)


# TODO: add log level switch as cli options!!!
