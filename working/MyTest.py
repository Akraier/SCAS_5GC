import time
class myTestCase:
    test_available = {
        -1: {
            "name": "ANY",
            "group": "ANY",
            "NFs": "ANY"
        },
        0: {
            "name": "TC_AMF_NAS_INTEGRITY_FAILURE",
            "group": "NGAP/NAS",
            "NFs": "AMF"
        }
    }

    def __init__(self,test):
        for t in test:
            #create a list of test to run
            if t == -1:
                self.tests = self.test_available
                return
            if t in self.test_available.keys():
                self.tests[t] = self.test_available[t]
                self.tests[t]["status"] = "PENDING"     #PENDING, RUNNING, PASSED, FAILED
            else:
                return None
        
    def tc_amf_nas_integrity_failure(self, ngap_segment):
        print(f"[TEST][{time.strftime("%Y%m%d:%H%M%S")}]tc_amf_nas_integrity_failure")