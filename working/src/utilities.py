import traceback
import multiprocessing

class DynamicMultiQueueManager:
    """
    This class in used to manage multiprocess queues to share data flow 
    captured by scapy between processes.
    This class also provides a 'history' field used to store persistently -until flushed- 
    some messages. 
    !!! Consider to expand the class in order to have history for filtered messages
    only !!!
    Loading history with every message flowing may generate a considerate
    memory load for medium-long time sniffing.
    """
    def __init__(self, queue_names=None):
        # Initialize with an optional list of queue names
        if queue_names is None:
            queue_names = []
        self.queues = {name: multiprocessing.Queue() for name in queue_names}
        #self.history = []
        #self._lock = multiprocessing.Lock()

    def put(self, queue_name, item):
        if queue_name not in self.queues:
            return False
        self.queues[queue_name].put(item)
        
        return True
    
    def get(self, queue_name):
        if queue_name not in self.queues:
            return False
        """ elif self.queues[queue_name].empty():
            return False """
        return self.queues[queue_name].get()

    def empty(self, queue_name):
        if queue_name not in self.queues:
            return None
        else:
            return self.queues[queue_name].empty()
    
    """ def add_to_history(self,item):
        with self._lock:
            self.history.append(item)

    def get_history(self):
         Retrieve the history list
        with self._lock:
            return list(self.history)
    def clear_history(self):
        with self._lock:
            self.history.clear()        """    
    def add_queue(self, queue_name):
        """Dynamically add a new queue to the manager."""
        if queue_name in self.queues:
            print(f"[!] Queue '{queue_name}' already exists.")
            return False
        else:
            self.queues[queue_name] = multiprocessing.Queue()
            print(f"[+] Queue '{queue_name}' has been added.")
            return True
    def queue_exist(self,queue_name):
        """Check if queue exists"""
        return queue_name in self.queues
        
    def list_queues(self):
        """Optional: List all queue names"""
        return list(self.queues.keys())

