import sublist3r
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

# Global executor for background tasks
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sublist3r")

def run_sublist3r(domain, timeout=300):
    """
    Run Sublist3r to enumerate subdomains in the background efficiently.
    Returns a future object immediately - does NOT block!
    Use future.result() or future.done() to check/get results.
    """
    def _run_sublist3r():
        """Internal function to run Sublist3r."""
        try:
            subdomains = sublist3r.main(
                domain, 
                40, 
                savefile=None, 
                ports=None, 
                silent=True, 
                verbose=False, 
                enable_bruteforce=False, 
                engines=None
            )
            return {"status": "success", "subdomains": list(set(subdomains))}  # Remove duplicates
        except Exception as e:
            return {"status": "error", "error": str(e), "subdomains": []}
    
    # Submit task to thread pool (runs in background - returns immediately!)
    future = _executor.submit(_run_sublist3r)
    return future


def get_sublist3r_result(future, timeout=None):
    """
    Get the result from a sublist3r future.
    If timeout is None, waits indefinitely. Otherwise waits up to timeout seconds.
    """
    try:
        if timeout is None:
            result = future.result()
        else:
            result = future.result(timeout=timeout)
        return result
    except FutureTimeoutError:
        return {"status": "timeout", "subdomains": []}
    except Exception as e:
        return {"status": "error", "error": str(e), "subdomains": []}


def run_sublist3r_blocking(domain, timeout=300):
    """
    Run Sublist3r and wait for result (blocking version).
    Use this if you need to wait for the result immediately.
    """
    future = run_sublist3r(domain)
    return get_sublist3r_result(future, timeout=timeout)

