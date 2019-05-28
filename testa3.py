import subprocess
import socket
import os
import time

from scapy.all import IP, raw

if os.name == "posix":
    PYTHON_CALL = "python3.6"
else:
    PYTHON_CALL = "python"

STDOUT_FILE = "files/stdout_{}.txt"
STDIN_FILE = "files/stdin_{}.txt"
PKTOUT_FILE = "files/pktout_{}.txt"
PKTIN_FILE = "files/pktin_{}.txt"

CLI_IP_ADDR = "10.0.0.9/24"
CLI_LL_ADDR = 9999
TST_IP_ADDR = "10.0.0.1"
TST_LL_ADDR = 1234


def format_pkt_in(text):
    fields = {}
    payload = ""
    for pair in text[text.index("(")+1:text.index(")")].split(", "):
        name, _, value = pair.partition("=")
        if name == "payload":
            payload = value
            continue
        if value.isdigit():
            value = int(value)
        else:
            value = value.strip('"')
        fields[name] = value

    return IP(**fields)/payload


def format_pkt_out(raw_pkt):
    header = raw_pkt[:20]
    payload = raw_pkt[20:].decode("UTF-8")
    pkt = IP(header)
    return f"IPv4(src={pkt.src}, dst={pkt.dst}, flags={int(pkt.flags)}, proto={pkt.proto}, payload=\"{str(payload)}\")"


def compare(name, expected, actual):
    if expected != actual:
        print(f"{name} MATCH FAILED")
        print("EXPECTED:")
        print(expected)
        print("\nGOT:")
        print(actual)
        print()
        return False
    return True


def run(test_num):
    with open(STDOUT_FILE.format(test_num), "r") as out, \
            open(STDIN_FILE.format(test_num), "r") as inp, \
            open(PKTOUT_FILE.format(test_num), "r") as pktout, \
            open(PKTIN_FILE.format(test_num), "r") as pktin:
        out_text = out.read().strip("\n")
        in_text = inp.read()
        pktout_text = pktout.read().strip("\n")
        pktin_text = pktin.read().strip("\n")

    actual_pkts = []

    if os.path.exists("makefile") or os.path.exists("Makefile"):
        try:
            subprocess.check_output(["make"])
        except subprocess.CalledProcessError:
            print("Error thrown while calling makefile")
            return

    if os.path.exists("assign3.py"):
        path = [PYTHON_CALL, "assign3.py", CLI_IP_ADDR, str(CLI_LL_ADDR)]
    elif os.path.exists("Assign3.class"):
        path = ["java", "Assign3", CLI_IP_ADDR, str(CLI_LL_ADDR)]
    elif os.path.exists("assign3"):
        path = ["./assign3", CLI_IP_ADDR, str(CLI_LL_ADDR)]
    else:
        return

    proc = subprocess.Popen(path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

    if in_text.strip("\n") != "":
        proc.stdin.write(in_text.encode("UTF-8"))
        proc.stdin.flush()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("localhost", TST_LL_ADDR))
        sock.settimeout(3)
        time.sleep(1)
        for line in pktin_text.split("\n"):
            if "(" in line and ")" in line:
                sock.sendto(raw(format_pkt_in(line)), ("localhost", CLI_LL_ADDR))

        try:
            while True:
                actual_pkts.append(format_pkt_out(sock.recvfrom(2048)[0]))
        except socket.timeout:
            pass

    time.sleep(3)
    proc.kill()
    actual_stdout = proc.stdout.read().decode("UTF-8").strip("\n")
    actual_stderr = proc.stderr.read().decode("UTF-8").strip("\n")

    result = True
    result = result and compare("STDOUT", out_text, actual_stdout)
    result = result and compare("STDERR", "", actual_stderr)
    result = result and compare("PKTS", pktout_text, "\n".join(actual_pkts))
    if result:
        print("Test passed")


TESTS = ["Gateway CLI", "ARP CLI", "Simple sending", "Missing gateway/ARP",
         "Gateway sending", "Simple receiving", "Fragmentation CLI"]

if __name__ == "__main__":
    for i, test in enumerate(TESTS):
        print(f"{test} test ({i})")
        run(i)
