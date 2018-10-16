import argparse
import requests
import json
import os

def read_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--synapseUsername")
    parser.add_argument("--synapsePassword")
    parser.add_argument("--bridgeUsername")
    parser.add_argument("--bridgePassword")
    args = parser.parse_args()
    return(args)

def main():
    args = read_args()
    r = requests.get("https://repo-prod.prod.sagebase.org/repo/v1/admin/synapse/status")
    d = json.loads(r.content)
    if d['status'] == "READ_WRITE":
        os.system("docker run --rm -e synapseUsername={} -e synapsePassword={} "
                  "-e bridgeUsername={} -e bridgePassword={} "
                  "philsnyder/mpower2-user-add:env_var_credentials".format(
                      args.synapseUsername, args.synapsePassword,
                      args.bridgeUsername, args.bridgePassword))

if __name__ == "__main__":
    main()
