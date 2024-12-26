import subprocess

def run_command(command):
    try:
        # Run the command
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        # Print the output from the command
        print(f"Command executed successfully: {result.stdout}")
    except subprocess.CalledProcessError as e:
        # Handle any errors that occur during command execution
        print(f"Error executing command: {e.stderr}")

if __name__ == "__main__":
    # Use a for loop to add routes for IPs from 172.17.0.10 to 172.17.0.35
    for i in range(10, 36):
        ip_address = f"172.17.0.{i}"
        command = f"sudo ip route add {ip_address}/32 via 172.17.0.3"
        run_command(command)
