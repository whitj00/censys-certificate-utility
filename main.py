import censys.certificates
import csv
import argparse

c = censys.certificates.CensysCertificates()
search_fields = ["parsed.fingerprint_sha256", "parsed.validity.start", "parsed.validity.end"]
search_query = "parsed.names: censys.io and tags: trusted"

def create_file(output_file: str="output.csv") -> None:
    '''Creates a file `output_file` and outputs information for trusted certificates associated with censys.io to that file
    
    Keyword arguments:
    output_file -- name of output csv file (default: output.csv)
    '''
    with open(output_file, 'w', newline='') as output_csv:
        output_writer = csv.writer(output_csv)
        output_writer.writerow(["fingerprint", "start_date", "end_date"])
        for page in c.search(query=search_query, fields=search_fields):
            output_writer.writerow([page["parsed.fingerprint_sha256"], page["parsed.validity.start"], page["parsed.validity.end"]])
    print("CSV: Write Successful")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Output a CSV with certificate information for all trusted X.509 certificates associated with the censys.io domain")
    parser.add_argument('--filename', type=str, default="output.csv", help='output csv filename (default: output.csv)')
    args = parser.parse_args()
    create_file(args.filename)
