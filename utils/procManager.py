import multiprocessing, threading
from collections.abc import Iterable

class ProcManager:
    class AlreadyRunningError(Exception):
        """Exception raised when trying to start a process that is already running."""
        pass

    def __init__(self):
        self._lock      = multiprocessing.Lock()
        self.cmd_q     = multiprocessing.Queue()    # Communication queue for commands
        self.processes = {}   # name -> Process
        self.targets   = {}   # name -> (target, args)
        
        # Thread listening for commands
        self.listener = threading.Thread(target=self._listen, daemon=True)
        self.listener.start()
    
    def _listen(self):
        #Recevies commands from the command queue and handles them
        while True:
            cmd, name = self.cmd_q.get()
            if cmd == "restart":
                print(f"[*] Restart required for '{name}'")
                try:
                    if self.processes[name].is_alive():
                        print(f"[*] Stopping process '{name}'")
                        self.stop_process(name)
                    else:
                        print(f"[*] '{name}' is not running...")
                        return
                    target, args = self.targets[name]
                    self.run_process(target, args)
                except Exception as e:
                    print(f"[*] Error restarting {name}: {e}")
            elif cmd == "stop":
                print(f"[*] Stop required for '{name}'")
                try:
                    if self.process[name].is_alive():
                        print(f"[*] Stopping '{name}'")
                        self.stop_process(name)
                    else:
                        print(f"[*] '{name}' is not running...")
                except Exception as e:
                    print(f"[*] Error stopping {name}: {e}")
            elif cmd == "shutdown_all":
                self.cleanup()
                break

    def run_process(self, target, args=()):
        name = target.__name__
        try:
            if not isinstance(args, Iterable) or isinstance(args, (str, bytes)):
                # If args is not iterable, wrap it in a tuple for consistency
                args = (args,)
            self.targets[name] = (target, args)
            with self._lock:
                if name in self.processes and self.processes[name].is_alive():
                    raise ProcManager.AlreadyRunningError(f"Process '{name}' already running")
                p = multiprocessing.Process(target=target, args=(self.cmd_q, *args), name=name)
                p.start()
                self.processes[name] = p
            return True
        except Exception as e:
            print(f"[!] Error starting {name}:{e}")
            return False
    
    def stop_process(self, name, timeout = 5):
        with self._lock:
            p = self.processes.get(name)
        if not p:
            print(f"[!] No such process '{name}'")
            return False
        p.terminate()
        p.join(timeout)
        if p.is_alive():
            logging.warning(f"Process '{name}' did not exit after {timeout}s")
        with self._lock:
            del self.processes[name]
    def wait_process(self, target):
        name = target.__name__
        with self._lock:
            p = self.processes.get(name)
        if not p:
            print(f"[!] No such process '{name}'")
            return False
        p.join()
        with self._lock:
            del self.processes[name]
        return True

    def cleanup(self):
        """Terminate and join any remaining process."""
        with self._lock:
            names = list(self.processes.keys())
        for name in names:
            try:
                self.stop_process(name)
            except Exception as e:
                print(f"[!] Cleanup error on '{name}': {e}")
            