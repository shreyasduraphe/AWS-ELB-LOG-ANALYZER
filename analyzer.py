import boto3
import os
import re
import datetime
import gzip  # <-- ADD THIS LINE
from collections import Counter, defaultdict
from urllib.parse import unquote

# Initialize the S3 client
s3_client = boto3.client('s3')

# Environment variables for configuration
DESTINATION_BUCKET = os.environ.get('DESTINATION_BUCKET')

# Regular expression to parse an ALB log entry.
ALB_LOG_REGEX = re.compile(
    r'([^\s]+)\s'  # type
    r'([^\s]+)\s'  # time
    r'([^\s]+)\s'  # elb
    r'([^\s]+)\s'  # client:port
    r'([^\s]+)\s'  # target:port
    r'([^\s]+)\s'  # request_processing_time
    r'([^\s]+)\s'  # target_processing_time
    r'([^\s]+)\s'  # response_processing_time
    r'([^\s]+)\s'  # elb_status_code
    r'([^\s]+)\s'  # target_status_code
    r'([^\s]+)\s'  # received_bytes
    r'([^\s]+)\s'  # sent_bytes
    r'\"([^\"]*)\"\s'  # "request"
    r'\"([^\"]*)\"\s'  # "user_agent"
    r'([^\s]+)\s'  # ssl_cipher
    r'([^\s]+)\s'  # ssl_protocol
    r'([^\s]+)\s'  # target_group_arn
    r'\"([^\"]*)\"\s'  # "trace_id"
    r'\"([^\"]*)\"\s'  # "domain_name"
    r'\"([^\"]*)\"\s'  # "chosen_cert_arn"
    r'([^\s]+)\s'  # matched_rule_priority
    r'([^\s]+)\s'  # request_creation_time
    r'\"([^\"]*)\"\s'  # "actions_executed"
    r'\"([^\"]*)\"\s'  # "redirect_url"
    r'\"([^\"]*)\"\s'  # "error_reason"
    r'\"([^\"]*)\"'   # "target:port_list" ... (rest is optional)
, re.VERBOSE)

def parse_log_line(line):
    """Parses a single ALB log line into a dictionary."""
    match = ALB_LOG_REGEX.match(line)
    if not match:
        return None

    return {
        'type': match.group(1),
        'time': match.group(2),
        'elb': match.group(3),
        'client_ip': match.group(4).split(':')[0],
        'target_port': match.group(5),
        'request_processing_time': float(match.group(6)) if match.group(6) != '-1.000000' else 0.0,
        'target_processing_time': float(match.group(7)) if match.group(7) != '-1.000000' else 0.0,
        'response_processing_time': float(match.group(8)) if match.group(8) != '-1.000000' else 0.0,
        'elb_status_code': match.group(9),
        'target_status_code': match.group(10),
        'received_bytes': int(match.group(11)),
        'sent_bytes': int(match.group(12)),
        'request': match.group(13),
        'user_agent': match.group(14),
        'ssl_protocol': match.group(16),
        'target_group_arn': match.group(17),
        'actions_executed': match.group(23).split(','),
    }

def analyze_logs(log_content):
    """Processes the full log content and returns an analysis dictionary."""
    # Data structures for aggregation
    total_requests = 0
    total_sent_bytes = 0
    
    sum_target_processing_time = 0.0
    sum_req_processing_time = 0.0
    sum_resp_processing_time = 0.0

    endpoint_times = defaultdict(lambda: {'count': 0, 'total_time': 0.0})
    
    elb_status_codes = Counter()
    target_status_codes = Counter()
    
    client_ips = Counter()
    target_groups = Counter()
    
    ssl_protocols = Counter()
    actions_executed = Counter()

    for line in log_content.splitlines():
        log_entry = parse_log_line(line)
        if not log_entry:
            continue

        total_requests += 1
        total_sent_bytes += log_entry['sent_bytes']
        
        sum_target_processing_time += log_entry['target_processing_time']
        sum_req_processing_time += log_entry['request_processing_time']
        sum_resp_processing_time += log_entry['response_processing_time']

        # Extract path from request string
        try:
            path = unquote(log_entry['request'].split(' ')[1].split('?')[0])
            endpoint_times[path]['count'] += 1
            endpoint_times[path]['total_time'] += log_entry['target_processing_time']
        except IndexError:
            pass
            
        elb_status_codes[log_entry['elb_status_code']] += 1
        if log_entry['target_status_code'] != '-':
            target_status_codes[log_entry['target_status_code']] += 1
            
        client_ips[log_entry['client_ip']] += 1
        target_groups[log_entry['target_group_arn']] += 1
        
        if log_entry['ssl_protocol'] != '-':
            ssl_protocols[log_entry['ssl_protocol']] += 1
        
        for action in log_entry['actions_executed']:
            if action:
                actions_executed[action] += 1

    # Prepare final analysis results
    analysis = {
        'total_requests': total_requests,
        'total_sent_gb': round(total_sent_bytes / (1024**3), 4),
        'avg_target_processing_time': round(sum_target_processing_time / total_requests, 4) if total_requests > 0 else 0,
        'avg_req_processing_time': round(sum_req_processing_time / total_requests, 4) if total_requests > 0 else 0,
        'avg_resp_processing_time': round(sum_resp_processing_time / total_requests, 4) if total_requests > 0 else 0,
        'endpoint_times': endpoint_times,
        'elb_status_codes': elb_status_codes,
        'target_status_codes': target_status_codes,
        'top_10_clients': client_ips.most_common(10),
        'requests_by_tg': target_groups,
        'ssl_protocols': ssl_protocols,
        'actions_executed': actions_executed
    }
    return analysis

def generate_report(analysis, source_location):
    """Formats the analysis dictionary into a human-readable string report."""
    report = []
    report.append(f"# AWS ALB Log Analysis Report for: {source_location}\n")
    report.append("="*50 + "\n")
    
    # Performance Section
    report.append("## 🚀 Performance & Latency Monitoring\n")
    report.append(f"- **Average Target Response Time:** {analysis['avg_target_processing_time']} seconds")
    report.append("- **Latency Bottleneck Analysis:**")
    report.append(f"  - Request Processing (Client -> ALB): {analysis['avg_req_processing_time']}s")
    report.append(f"  - Target Processing (ALB -> Target): {analysis['avg_target_processing_time']}s")
    report.append(f"  - Response Processing (Target -> Client): {analysis['avg_resp_processing_time']}s\n")
    
    endpoint_avg_times = {
        path: data['total_time'] / data['count']
        for path, data in analysis['endpoint_times'].items()
    }
    top_5_slowest = sorted(endpoint_avg_times.items(), key=lambda item: item[1], reverse=True)[:5]
    report.append("- **Top 5 Slowest Endpoints:**")
    for path, avg_time in top_5_slowest:
        report.append(f"  - {path}: {round(avg_time, 4)}s")
    report.append("\n" + "-"*50 + "\n")

    # Error Section
    report.append("## 🚦 Error & Availability Analysis\n")
    report.append("- **ELB Status Code Summary:**")
    for code, count in analysis['elb_status_codes'].most_common():
        report.append(f"  - {code}: {count} requests")
    report.append("\n- **Target Status Code Summary:**")
    for code, count in analysis['target_status_codes'].most_common():
        report.append(f"  - {code}: {count} requests")
    report.append("\n" + "-"*50 + "\n")

    # Traffic Section
    report.append("## 🌐 Traffic & Audience Insights\n")
    report.append(f"- **Total Requests Processed:** {analysis['total_requests']}")
    report.append(f"- **Total Bandwidth (Sent):** {analysis['total_sent_gb']} GB")
    report.append("\n- **Top 10 Visitors by IP:**")
    for ip, count in analysis['top_10_clients']:
        report.append(f"  - {ip}: {count} requests")
    report.append("\n- **Requests by Target Group:**")
    for tg, count in analysis['requests_by_tg'].items():
        tg_name = tg.split('/')[-2]
        report.append(f"  - {tg_name}: {count} requests")
    report.append("\n" + "-"*50 + "\n")
    
    # Security Section
    report.append("## 🔒 Security & Compliance\n")
    report.append("- **TLS Protocol Summary:**")
    for proto, count in analysis['ssl_protocols'].items():
        report.append(f"  - {proto}: {count} connections")
    report.append("\n- **Actions Executed Summary:**")
    for action, count in analysis['actions_executed'].items():
        report.append(f"  - {action}: {count} times")
        
    return "\n".join(report)

def lambda_handler(event, context):
    """
    Main Lambda function entry point for MANUAL invocation.
    Processes all log files in a specified S3 bucket and prefix.
    
    Expected input event format (JSON):
    {
      "source_bucket": "your-alb-logs-bucket",
      "source_prefix": "path/to/your/logs/"
    }
    """
    # 1. Validate configuration and input event
    if not DESTINATION_BUCKET:
        print("Error: DESTINATION_BUCKET environment variable not set.")
        return {'statusCode': 500, 'body': 'Configuration error.'}

    source_bucket = event.get('source_bucket')
    source_prefix = event.get('source_prefix')
    
    if not source_bucket or source_prefix is None:
        print("Error: Missing 'source_bucket' or 'source_prefix' in the invocation event.")
        return {'statusCode': 400, 'body': 'Bad request. Please provide source_bucket and source_prefix.'}

    print(f"Starting analysis for s3://{source_bucket}/{source_prefix}")
    
    try:
        # 2. Find all log files in the specified prefix
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=source_bucket, Prefix=source_prefix)
        
        all_log_content = []
        file_count = 0
        for page in pages:
            if 'Contents' not in page:
                continue
            for obj in page['Contents']:
                log_file_key = obj['Key']
                # Skip directories/empty objects and ensure it's a gzipped log
                if not log_file_key.endswith('.log.gz'):
                   continue
                
                print(f"Downloading file: {log_file_key}")
                response = s3_client.get_object(Bucket=source_bucket, Key=log_file_key)
                
                # Decompress the gzipped log file content
                with gzip.GzipFile(fileobj=response['Body']) as gzipfile:
                    content = gzipfile.read().decode('utf-8')
                    all_log_content.append(content)
                file_count += 1
        
        if not all_log_content:
            print(f"No log files found at s3://{source_bucket}/{source_prefix}")
            return {'statusCode': 200, 'body': 'No log files to process.'}
            
        print(f"Downloaded and decompressed {file_count} log file(s).")
        
        # 3. Analyze the combined log content
        combined_logs = "".join(all_log_content)
        analysis = analyze_logs(combined_logs)
        
        # 4. Generate the report
        source_location = f"s3://{source_bucket}/{source_prefix}"
        report_content = generate_report(analysis, source_location)
        
        # 5. Upload the report to the destination S3 bucket
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        folder_name = source_prefix.strip('/').replace('/', '-') if source_prefix else "root"
        report_key = f"reports/{folder_name}-{timestamp}-report.txt"
        
        s3_client.put_object(
            Bucket=DESTINATION_BUCKET,
            Key=report_key,
            Body=report_content,
            ContentType='text/plain'
        )
        
        print(f"Successfully generated and uploaded report to s3://{DESTINATION_BUCKET}/{report_key}")
        
        return {
            'statusCode': 200,
            'body': f'Report generated successfully: {report_key}'
        }

    except Exception as e:
        print(f"Error processing logs: {e}")
        return {
            'statusCode': 500,
            'body': f'Error processing logs: {str(e)}'
        }