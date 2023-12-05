import argparse
import getpass
import yaml
from pypsrp.client import Client
from pypsrp.shell import Process, SignalCode, WinRS
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

def parse_arguments():
    parser = argparse.ArgumentParser(description="Script to execute PowerShell commands remotely.")
    parser.add_argument("-c", "--config", help="Path to YAML configuration file")
    parser.add_argument("-u", "--username", help="Username for remote host")
    parser.add_argument("-i", "--host", help="Remote host IP address or hostname")
    parser.add_argument("-p", "--password", help="Password for remote host (will prompt if not provided)")
    parser.add_argument("-S", "--ssl", action="store_true", help="Use SSL for connection")
    parser.add_argument("-s", "--script", help="Path to PowerShell script file")
    return parser.parse_args()

def read_config(config_path):
    with open(config_path, 'r') as config_file:
        config = yaml.safe_load(config_file)
    return config

def main():
    args = parse_arguments()

    if not any(vars(args).values()):
        print("No arguments provided. Use -h or --help for help.")
        return

    missing_argument = find_missing_argument(args)
    if missing_argument:
        print(f"Missing required argument: {missing_argument}")
        return

    if args.config:
        config = read_config(args.config)
        validate_config(config)

        username = args.username or config['username']
        password = args.password or config['password']
        host = args.host or config['host']
        ssl = args.ssl if args.ssl is not None else config.get('ssl', False)

        wsman = WSMan(host, ssl=ssl, auth="negotiate", username=username, password=password)

        for script_path in config.get('scripts', []):
            execute_script(wsman, script_path)

    else:
        username = args.username
        password = args.password or getpass.getpass("Enter password: ")
        host = args.host
        ssl = args.ssl

        wsman = WSMan(host, ssl=ssl, auth="negotiate", username=username, password=password)

        script_path = args.script
        execute_script(wsman, script_path)

def find_missing_argument(args):
    if not args.host:
        return "-h | --host"
    if not args.username:
        return "-u | --username"
    if not args.password:
        return "-p | --password"
    if not args.script:
        return "-s | --script"
    return None

def validate_config(config):
    required_fields = ['username', 'password', 'host', 'scripts']
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Config is missing required field: {field}")

def execute_script(wsman, script_path):
    with open(script_path) as fin:
        script = fin.read()

    # Uncomment the following block if you want to use WinRS instead of RunspacePool
    # with wsman, WinRS(wsman) as shell:
    #     process = Process(shell, "gal gal")
    #     process.invoke()
    #     print(process.stdout.rstrip().decode())
    #     print(process.stderr.rstrip().decode())
    #     process.signal(SignalCode.CTRL_C)

    with wsman, RunspacePool(wsman) as pool:
        ps = PowerShell(pool)
        ps.add_script(script)
        ps.invoke(['string', 1])
        for outputObj in ps.output:
        	print(outputObj)

if __name__ == "__main__":
    main()