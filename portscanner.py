import socket
import time
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port):
    """
    Attempts to connect to a specific port on the host to determine if it’s open.

    Args:
        host (str): The IP address or hostname of the target.
        port (int): The port number to scan.

    Returns:
        int or None: The port number if open, None if closed or unreachable.
    """
    try:
        # Create a new TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout to avoid hanging (1 second)
        s.settimeout(1)
        # Attempt to connect to the host on the specified port
        s.connect((host, port))
        # Close the socket if connection succeeds
        s.close()
        return port
    except:
        # Return None if connection fails (port closed or error occurred)
        return None

def main():
    """
    Main function to execute the port scanner.
    Prompts for a target host, resolves it to an IP, and scans ports 1-1024 concurrently.
    """
    # Get the target host from user input
    target = input("Enter target host: ")
    try:
        # Resolve hostname to IP address
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        # Handle case where hostname cannot be resolved
        print("Cannot resolve host.")
        return

    # Define the port range to scan (well-known ports)
    start_port = 1
    end_port = 1024

    # Inform the user that scanning is starting
    print(f"Scanning {ip} from port {start_port} to {end_port}...")

    # Record the start time for performance measurement
    start_time = time.time()

    # List to store open ports
    open_ports = []

    # Use ThreadPoolExecutor to scan ports concurrently with 100 threads
    with ThreadPoolExecutor(max_workers=100) as executor:
        # Submit scanning tasks for all ports in the range
        futures = [executor.submit(scan_port, ip, port) for port in range(start_port, end_port + 1)]
        # Collect results from each scan
        for future in futures:
            result = future.result()
            if result is not None:
                open_ports.append(result)

    # Calculate the time taken
    end_time = time.time()

    # Display the results
    print("Open ports:")
    for port in sorted(open_ports):
        print(f"Port {port} is open.")

    # Show the total time taken, formatted to 2 decimal places
    print(f"Scan completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    try:
        # Run the main function
        main()
    except KeyboardInterrupt:
        # Handle user interruption (e.g., Ctrl+C)
        print("\nScan interrupted by user.")