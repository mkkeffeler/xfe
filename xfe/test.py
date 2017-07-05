from xfe import query_xforce_exchange as xforce 

def client():
    client = xforce.Client(user="bilbo", password="baggins")
    return client

client()

