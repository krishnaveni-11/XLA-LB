import subprocess

def run_command(command):
    try:
        # Run the command
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()  # Wait for the command to complete
        
        # Check if the command was successful
        if process.returncode == 0:
            print("Command executed successfully: {}".format(stdout.decode().strip()))
        else:
            print("Error executing command: {}".format(stderr.decode().strip()))

    except Exception as e:
        # Handle any exceptions that occur during command execution
        print("An error occurred: {}".format(e))

if __name__ == "__main__":
    # Add the default route
    run_command("sudo ip addr add 172.17.0.3/24 dev s1")
    run_command("sudo ip link set s1 address 02:42:ac:11:00:03")
    run_command("sudo ip link set s1 up")
    #run_command("sudo ip route add default via 172.17.0.3")
    
    # Add routes for IPs 172.17.0.10 to 172.17.0.34
    for i in range(10, 36):
        run_command("sudo ip route add 172.17.0.{}/32 via 172.17.0.3".format(i))

