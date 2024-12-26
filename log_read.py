import csv

def convert_hex_to_decimal(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        reader = csv.DictReader(infile)  # Using DictReader to handle the CSV format
        for row in reader:
            # Extract the Incoming Pkts/s field and check if it's a valid hex value
            hex_value = row['Incoming Pkts/s'].strip()
            try:
                # Convert hex value to decimal
                decimal_value = int(hex_value, 16)
                # Write the decimal value to the output file
                outfile.write(f"{decimal_value}\n")
            except ValueError:
                # Handle cases where conversion fails (e.g., if it's 0 or empty)
                print(f"Skipping invalid hex value: {hex_value}")

# Input and output file paths
input_file = "ipvs_stats.log"  # Replace with your actual input file name
output_file = "converted_inpkts.txt"  # Output file to store decimal values

# Run the conversion
convert_hex_to_decimal(input_file, output_file)

print(f"Converted Incoming Pkts/s values saved to {output_file}")
