import csv
from collections import Counter
import re


def count_requests_by_ip(logs, csv_writer):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_addresses = [re.search(ip_pattern, log).group(0)
                    for log in logs if re.search(ip_pattern, log)]

    request_counts = Counter(ip_addresses)

    sorted_requests = sorted(request_counts.items(),
                             key=lambda x: x[1], reverse=True)

    # Print results to terminal
    print(f"{'IP Address':<20} {'Request Count':<15}")
    print("-" * 35)
    for ip, count in sorted_requests:
        print(f"{ip:<20} {count:<15}")

    csv_writer.writerow(["IP Address", "Request Count"])
    csv_writer.writerow(['-'*35])
    csv_writer.writerows(sorted_requests)
    csv_writer.writerow(['*'*35])
    csv_writer.writerow([])


def most_frequent_endpoint(logs, csv_writer):
    endpoint_pattern = r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*?) HTTP/1.[01]"'
    endpoints = [re.search(endpoint_pattern, log).group(1)
                 for log in logs if re.search(endpoint_pattern, log)]

    endpoint_counts = Counter(endpoints)

    most_frequent = endpoint_counts.most_common(
        1)[0] if endpoint_counts else None

    if most_frequent:
        endpoint, count = most_frequent
        print(
            f"The most frequently accessed endpoint is:\n{endpoint} (Accessed {count} {'times'if count > 1 else 'time'}).")
        csv_writer.writerow(['-'*35])
        csv_writer.writerow(
            [f"The most frequently accessed endpoint is:\n{endpoint} (Accessed {count} {'times'if count > 1 else 'time'}"])
        csv_writer.writerow(['*'*35])
        csv_writer.writerow([])
    else:
        print("No endpoints were found in the log file.")
        csv_writer.writerow(['-'*35])
        csv_writer.writerow(["No endpoints were found in the log file."])
        csv_writer.writerow(['*'*35])
        csv_writer.writerow([])


def detect_suspicious_activity(logs, csv_writer):
    failed_login_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b.*?(401|Invalid credentials)'

    failed_attempts = [
        re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log).group(0)
        for log in logs if re.search(failed_login_pattern, log)
    ]

    failed_attempt_counts = Counter(failed_attempts)

    flagged_ips = {

        ip: count for ip, count in failed_attempt_counts.items()}

    if flagged_ips:
        print('Suspicious Activity Detected:')
        print(f"{'IP Address':<20} {'Failed Attempts':<15}")
        print("-" * 35)
        for ip, count in flagged_ips.items():
            print(f"{ip:<20} {count:<15}")
        csv_writer.writerow(['Suspicious Activity Detected:'])
        csv_writer.writerow(["IP Address", "Failed Attempts"])
        csv_writer.writerow(['-'*35])
        csv_writer.writerows(flagged_ips.items())
        csv_writer.writerow(['*'*35])

        print(f"\nResults saved to {output_csv_path}")
    else:
        print(
            f"No suspicious activity detected ")


log_file_path = './sample.log'
output_csv_path = 'Log_Analysis.csv'

try:
    with open(log_file_path, 'r') as file:
        with open(output_csv_path, 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            logs = file.readlines()
            count_requests_by_ip(logs, csv_writer)
            print("*" * 35)
            print('\n')
            most_frequent_endpoint(logs, csv_writer)
            print("*" * 35)
            print('\n')
            detect_suspicious_activity(logs, csv_writer)

except FileNotFoundError:
    print(f"Error: The file {log_file_path} was not found.")
except Exception as e:
    print(f"An error occurred: {e}")
