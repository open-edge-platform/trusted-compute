#!/bin/bash

# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Initialize variables
interval=2
sum=0
count=0
loads=()

# Check if /proc/loadavg exists
if [ ! -f /proc/loadavg ]; then
    echo "Error: /proc/loadavg not found. This script requires a Linux system."
    exit 1
fi

# Trap Ctrl+C to handle exit gracefully
trap 'echo -e "\nReceived Ctrl+C. Exiting..."; print_stats; exit 0' SIGINT

# Function to print max and average CPU load
print_stats() {
    if [ $count -eq 0 ]; then
        echo "No samples collected."
        return
    fi
    # Calculate average
    avg=$(echo "scale=2; $sum / $count" | bc)
    # Calculate maximum by iterating through the loads array
    max_load=0
    for load in "${loads[@]}"; do
        if [ "$(echo "$load > $max_load" | bc -l)" -eq 1 ]; then
            max_load=$load
        fi
    done
    echo "--------------------------------"
    echo "Maximum CPU load: $max_load"
    echo "Average CPU load over $count samples: $avg"
}

echo "Monitoring CPU load every $interval seconds (press Ctrl+C to stop)..."

# Main loop to continuously collect CPU load
while true; do
    # Read the 1-minute load average from /proc/loadavg
    load=$(awk '{print $1}' /proc/loadavg)
    # Print the current CPU load
    echo "CPU load: $load"
    # Add to sum and store in array
    sum=$(echo "$sum + $load" | bc)
    loads+=("$load")
    ((count++))
    # Wait for the interval
    sleep $interval
done
