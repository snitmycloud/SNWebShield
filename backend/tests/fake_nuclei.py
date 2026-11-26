"""A stand-in for the Nuclei binary used by the runner tests. Behaviour is chosen by the first argument:

  jsonl <file>    print each line of <file>
  env             print one JSON object with this process's environment and working directory
  hang            print a line, then wait forever
  big             print endless output
  tree            start a grandchild process that waits forever and print both process ids
  exit <code>     print nothing and exit with that code
"""
import json
import os
import subprocess
import sys
import time

mode = sys.argv[1] if len(sys.argv) > 1 else ""
if mode == "jsonl":
    for line in open(sys.argv[2], encoding="utf-8").read().splitlines():
        print(line, flush=True)
elif mode == "env":
    print(json.dumps({"env": dict(os.environ), "cwd": os.getcwd(), "args": sys.argv[2:]}), flush=True)
elif mode == "hang":
    print('{"template-id": "started"}', flush=True)
    time.sleep(600)
elif mode == "big":
    while True:
        print('{"template-id": "x", "pad": "' + "a" * 1000 + '"}', flush=True)
elif mode == "tree":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
    print(json.dumps({"parent": os.getpid(), "child": child.pid}), flush=True)
    time.sleep(600)
elif mode == "exit":
    sys.exit(int(sys.argv[2]))
