from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure

# Replace with your actual credentials
MONGO_URI = "mongodb+srv://agriculture:agriculture@agriculture.a8s36tf.mongodb.net/?retryWrites=true&w=majority&appName=Agriculture"

try:
    # Attempt to connect
    client = MongoClient(MONGO_URI)
    
    # Check if the connection is successful
    client.admin.command('ping')  # Runs a simple "ping" command
    print("✅ MongoDB connection successful!")
    
    # Optional: List databases (if permissions allow)
    print("📂 Available databases:")
    for db in client.list_database_names():
        print(f"- {db}")
    
except ConnectionFailure:
    print("❌ Failed to connect to MongoDB (Network/Auth Error)")
except OperationFailure as e:
    print(f"❌ Authentication failed or permission denied: {e}")
except Exception as e:
    print(f"❌ Unexpected error: {e}")
finally:
    # Close the connection
    if 'client' in locals():
        client.close()