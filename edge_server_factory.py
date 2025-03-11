from edge_server_for_zkedi import EdgeServerForZKEDI
from edge_server_for_cooperedi import EdgeServerForCOOPEREDI
from edge_server_for_ediv import EdgeServerForEDIV

class EdgeServerFactory:
    @staticmethod
    def get_edge_server(method):
        if method == "ZKEDI":
            return EdgeServerForZKEDI()
        elif method == "COOPEREDI":
            return EdgeServerForCOOPEREDI()
        elif method == "EDIV":
            return EdgeServerForEDIV()
        else:
            raise ValueError(f"EDI verification method {method} not found")
