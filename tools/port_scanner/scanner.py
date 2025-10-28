import time
import socket

def connect_scan(target, ports, timeout, concurrency, dry_run, banner):
    results = []
    
    if dry_run:
        for port in ports:
            results.append({target, port, status="simulated", latency_ms=None, banner=None, timestamp=now()})
            return results
    # Function that executes the test in a port
    def worker(port):
        
        start_time = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCKSTREAM) as s:
                s.settimeout(timeout)
                start = now()
                s.connect((target, port))
                end = now()
                latency = (end - start) * 1000
                status = "open"
                banner_text = None
                if banner:
                    banner_text = banner_grab(s, target, port, timeout)
                s.close()
        except timeout_exception:
            status = "filtered" or "closed"
            latency = None
            banner_text = None
        except connection_refused_exception:
            status = "closed"
            latency = None
            banner_text = None
        except Exception as e:
            status = "error"
            latency = None
            banner_text = str(e)
        return 
