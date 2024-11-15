import re
import json
from datetime import datetime
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
import requests
import seaborn as sns


class NASAWebLogAnalyzer:
    def __init__(self):
        self.data_source_url = "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/nginx_logs/nginx_logs"
        self.log_regex = r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)'
        self.logs = []

    def download_logs(self):
        """Download logs from the specified URL."""
        print("Downloading logs...")
        response = requests.get(self.data_source_url)
        if response.status_code == 200:
            return response.text.split('\n')
        else:
            raise Exception("Failed to download logs")

    def parse_logs(self):
        """Parse the downloaded logs and extract relevant information."""
        print("Parsing logs...")
        log_lines = self.download_logs()

        for line in log_lines:
            if not line.strip():
                continue

            match = re.match(self.log_regex, line)
            if match:
                client_ip, timestamp, http_method, request_path, http_protocol, status_code, bytes_sent = match.groups()

                # Convert timestamp
                try:
                    parsed_date = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
                    formatted_date = parsed_date.strftime('%Y-%m-%d')
                except ValueError:
                    formatted_date = timestamp

                # Handle cases where bytes_sent is '-'
                bytes_sent = int(bytes_sent) if bytes_sent != '-' else 0

                log_entry = {
                    'client_ip': client_ip,
                    'timestamp': formatted_date,
                    'http_method': http_method,
                    'request_path': request_path,
                    'http_protocol': http_protocol,
                    'status_code': int(status_code),
                    'bytes_sent': bytes_sent
                }
                self.logs.append(log_entry)

        print(f"Processed {len(self.logs)} log entries")

    def save_logs_to_json(self, output_file):
        """Save parsed log data to a JSON file."""
        with open(output_file, 'w') as file:
            json.dump(self.logs, file, indent=2)
        print(f"Data saved to {output_file}")

    def plot_http_method_distribution(self):
        """Generate an enhanced pie chart of HTTP methods distribution."""
        http_methods = [entry['http_method'] for entry in self.logs]
        method_counts = Counter(http_methods)

        plt.figure(figsize=(10, 6))
        colors = sns.color_palette('husl', n_colors=len(method_counts))
        plt.pie(method_counts.values(), labels=method_counts.keys(),
                autopct='%1.1f%%', colors=colors, shadow=True)
        plt.title('HTTP Methods Distribution in NASA Logs', pad=20)
        plt.savefig('nasa_http_methods_distribution.png', bbox_inches='tight', dpi=300)
        plt.close()

    def plot_status_code_distribution(self):
        """Generate an enhanced bar chart of status codes distribution."""
        status_codes = [entry['status_code'] for entry in self.logs]
        status_counts = Counter(status_codes)

        plt.figure(figsize=(12, 6))
        sns.barplot(x=list(status_counts.keys()), y=list(status_counts.values()))
        plt.title('HTTP Status Codes Distribution in NASA Logs')
        plt.xlabel('Status Code')
        plt.ylabel('Request Count')
        plt.xticks(rotation=0)

        for i, count in enumerate(status_counts.values()):
            plt.text(i, count, str(count), ha='center', va='bottom')

        plt.savefig('nasa_status_codes_distribution.png', bbox_inches='tight', dpi=300)
        plt.close()

    def plot_daily_request_trend(self):
        """Generate an enhanced line chart of daily requests."""
        daily_request_counts = defaultdict(int)
        for entry in self.logs:
            daily_request_counts[entry['timestamp']] += 1

        sorted_dates = sorted(daily_request_counts.keys())
        sorted_counts = [daily_request_counts[date] for date in sorted_dates]

        plt.figure(figsize=(15, 6))
        sns.lineplot(x=sorted_dates, y=sorted_counts, marker='o')
        plt.title('Daily Requests in NASA Logs')
        plt.xlabel('Date')
        plt.ylabel('Number of Requests')
        plt.xticks(rotation=45)
        plt.grid(True, alpha=0.3)

        plt.savefig('nasa_daily_requests_trend.png', bbox_inches='tight', dpi=300)
        plt.close()

    def plot_top_requested_paths(self, top_n=10):
        """Generate a horizontal bar chart of the most requested paths."""
        request_paths = [entry['request_path'] for entry in self.logs]
        top_paths = Counter(request_paths).most_common(top_n)

                plt.figure(figsize=(12, 8))
        paths, counts = zip(*top_paths)

        sns.barplot(x=counts, y=paths)

        plt.title(f'Top {top_n} Most Requested Paths')
        plt.xlabel('Number of Requests')
        plt.ylabel('Path')

        plt.savefig('nasa_top_requested_paths.png', bbox_inches='tight', dpi=300)
        plt.show()
        plt.close()

    def generate_report(self):
        """Generate a detailed report with statistics."""
        total_requests = len(self.logs)
        method_counts = Counter(entry['http_method'] for entry in self.logs)
        status_counts = Counter(entry['status_code'] for entry in self.logs)
        unique_clients = len(set(entry['client_ip'] for entry in self.logs))
        total_bytes = sum(entry['bytes_sent'] for entry in self.logs)

        # Calculate the most common paths
        top_paths = Counter(entry['request_path'] for entry in self.logs).most_common(10)

        report_data = {
            'total_requests': total_requests,
            'unique_clients': unique_clients,
            'total_bytes_transferred': total_bytes,
            'average_bytes_per_request': total_bytes / total_requests if total_requests > 0 else 0,
            'http_method_counts': dict(method_counts),
            'status_code_counts': dict(status_counts),
            'top_10_paths': dict(top_paths)
        }

        with open('nasa_analysis_report.json', 'w') as file:
            json.dump(report_data, file, indent=2)

        print("Report generated in nasa_analysis_report.json")


def main():
    try:
        # Create an instance of the log analyzer
        log_analyzer = NASAWebLogAnalyzer()

        # Parse logs
        log_analyzer.parse_logs()
        log_analyzer.save_logs_to_json('nasa_logs_processed.json')

        # Generate visualizations
        print("Generating visualizations...")
        log_analyzer.plot_http_method_distribution()
        log_analyzer.plot_status_code_distribution()
        log_analyzer.plot_daily_request_trend()
        log_analyzer.plot_top_requested_paths()

        # Generate report
        log_analyzer.generate_report()

        print("Analysis completed successfully!")

    except Exception as e:
        print(f"Error during analysis: {str(e)}")


if __name__ == "__main__":
    main()
        
