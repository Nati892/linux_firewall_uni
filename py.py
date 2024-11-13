import socket
import os
import struct
import sys

NETLINK_TEST_FAMILY = 25
SOCKET_TIMEOUT = 3.5  # 3.5 seconds timeout

# Message types as bytes
MSG_SEND_FILE = b'\x01'
MSG_GET_FILE = b'\x02'
MSG_FILE_DATA = b'\x03'

# Add to your message types
MSG_SEND_SUCCESS = b'\x04'
MSG_SEND_FAIL = b'\x05'

def create_message(payload, msg_type):
    # Create proper netlink message header
    # Format: 
    # - nlmsg_len (u32) - length of message including header
    # - nlmsg_type (u16) - message type
    # - nlmsg_flags (u16) - message flags
    # - nlmsg_seq (u32) - sequence number
    # - nlmsg_pid (u32) - sender port ID
    
    msg_len = len(payload) + 1 + 16  # payload + msg_type byte + netlink header
    header = struct.pack("=LHHLL",
        msg_len,    # nlmsg_len
        0,          # nlmsg_type 
        0,          # nlmsg_flags
        0,          # nlmsg_seq
        os.getpid() # nlmsg_pid
    )
    return header + msg_type + payload

def send_file(filepath):
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_TEST_FAMILY)
    sock.bind((os.getpid(), 0))
    sock.settimeout(SOCKET_TIMEOUT)
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        message = create_message(data, MSG_SEND_FILE)
        sock.send(message)
        print(f"Sent {len(data)} bytes")
        
        # Wait for response
        try:
            response = sock.recv(1024)
            if len(response) >= 20:  # Header + status
                status = response[16:20]  # Get the 4-byte status
                if status == b'\x04\x00\x00\x00':  # MSG_SEND_SUCCESS
                    print("File sent and processed successfully")
                    return True
                else:
                    print("File processing failed")
                    return False
        except socket.timeout:
            print(f"No response received after {SOCKET_TIMEOUT} seconds")
            return False
            
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found")
        return False
    except PermissionError:
        print(f"Error: Permission denied accessing '{filepath}'")
        return False
    except Exception as e:
        print(f"Error: {str(e)}")
        return False
    finally:
        sock.close()

def get_file():
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_TEST_FAMILY)
    sock.bind((os.getpid(), 0))
    sock.settimeout(SOCKET_TIMEOUT)  # Set timeout for all socket operations
    
    try:
        # Send request for file
        message = create_message(b'', MSG_GET_FILE)
        sock.send(message)
        print("Sent file request")
        
        # Receive response
        try:
            response = sock.recv(1024 * 1024)  # Allow for up to 1MB response
            
            if len(response) > 17:  # netlink header (16) + message type (1)
                data = response[17:]  # Skip header and message type
                print(f"Received {len(data)} bytes")
                
                # Optionally save the received data to a file
                with open('received_file', 'wb') as f:
                    f.write(data)
                print("Saved data to 'received_file'")
                return data
            else:
                print("Received response too short")
                return None
                
        except socket.timeout:
            print(f"Timeout waiting for response after {SOCKET_TIMEOUT} seconds")
            return None
            
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        sock.close()

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Send file: python script.py send <filename>")
        print("  Get file:  python script.py get")
        sys.exit(1)
        
    command = sys.argv[1].lower()
    
    if command == "send" and len(sys.argv) == 3:
        filename = sys.argv[2]
        print(f"Sending file: {filename}")
        send_file(filename)
    elif command == "get":
        print("Requesting file from kernel")
        get_file()
    else:
        print("Invalid command")
        print("Usage:")
        print("  Send file: python script.py send <filename>")
        print("  Get file:  python script.py get")
        sys.exit(1)

if __name__ == "__main__":
    main()