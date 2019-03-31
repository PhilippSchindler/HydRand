import os
import subprocess

import hydrand.cliconfig
hydrand.cliconfig.USE_CLI_CONFIG = True


from hydrand.config import OUTPUT_DIR, PID_FILE_PATH, RESULT_FILE_PATH

# be careful when modifing import order!!!
import hydrand.node


# clean output directory
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)
else:
    subprocess.call(["rm", "-rf", f"{OUTPUT_DIR}/*"])

# store process id (for kill command)
with open(PID_FILE_PATH, 'w') as f:
    f.write(str(os.getpid()))

# store result FAILED (which is overwrite on success later)
with open(RESULT_FILE_PATH, 'w') as f:
    f.write("FAILED")

result = hydrand.node.Node().run()

if result:
    with open(RESULT_FILE_PATH, 'w') as f:
        f.write("OK")

# process terminated, remove pid file again
try:
    os.remove(PID_FILE_PATH)
except FileNotFoundError:
    pass
