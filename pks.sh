#!/bin/bash

# Output file path
output_file="ipvs_stats.log"

# Function to extract Pkts/s stats
get_packets_per_second() {
    # Extract the Pkts/s values (Incoming and Outgoing)
    pkts_per_sec=$(awk 'NR==6 {print $2, $3}' /proc/net/ip_vs_stats)
    echo $pkts_per_sec
}

# Initialize the output file
echo "Timestamp,Incoming Pkts/s,Outgoing Pkts/s" > "$output_file"
echo "Monitoring IPVS Packets Per Second (PPS)... Logging to $output_file. Press Ctrl+C to stop."

while true; do
    sleep 1
    # Fetch Pkts/s stats
    pkts_sec=$(get_packets_per_second)
    incoming_pps=$(echo $pkts_sec | awk '{print $1}')
    outgoing_pps=$(echo $pkts_sec | awk '{print $2}')
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Log to file
    echo "$timestamp,$incoming_pps,$outgoing_pps" >> "$output_file"

    # Debug output to console
    echo "Incoming Pkts/s: $incoming_pps, Outgoing Pkts/s: $outgoing_pps"
done
