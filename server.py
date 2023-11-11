import socket
import json
import random
import datetime
import hashlib
import sys

IP = sys.argv[1]
PORT = int(sys.argv[2])
ACCOUNTS_FILE = sys.argv[3]
SESSION_TIMEOUT = int(sys.argv[4]) if len(sys.argv) > 4 else 300
ROOT_DIRECTORY = sys.argv[5]

with open(ACCOUNTS_FILE, 'r') as accounts_file:
    accounts_data = json.load(accounts_file)

SESSIONS = {}

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def create_session_id():
    return format(random.getrandbits(64), 'x')

def verify_credentials(username, password):
    user_data = accounts_data.get(username, None)
    if not user_data:
        return False
    stored_hashed_password, salt = user_data
    hashed_input_password = hash_password(password, salt)
    return hashed_input_password == stored_hashed_password

def log_message(message):
    current_time = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    print(f"SERVER LOG: {current_time} {message}")

def handle_post_request(request_headers):
    try:
        username = request_headers.get("username")
        password = request_headers.get("password")

        if not username or not password:
            log_message("LOGIN FAILED: Missing username or password")
            return "HTTP/1.0 501 Not Implemented\r\nContent-Type: text/plain\r\n\r\nLogin failed due to missing credentials."

        if not verify_credentials(username, password):
            log_message(f"LOGIN FAILED: {username} : {password}")
            return "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nLogin failed!"

        session_id = create_session_id()
        SESSIONS[session_id] = {'username': username, 'expires': datetime.datetime.now() + datetime.timedelta(seconds=SESSION_TIMEOUT)}
        log_message(f"LOGIN SUCCESSFUL: {username} : {password}")
        return f"HTTP/1.0 200 OK\r\nSet-Cookie: sessionID={session_id}; Path=/\r\nContent-Type: text/plain\r\n\r\nLogged in!"

    except Exception as e:
        log_message(f"LOGIN FAILED: Exception in POST request handling - {e}")
        return "HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nInternal server error."

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen(5)
    log_message(f"Starting HTTP server on {IP}:{PORT}")

    while True:
        client_connection, client_address = server_socket.accept()
        request = client_connection.recv(1024).decode()
        request_lines = request.split('\r\n')
        request_headers = {line.split(": ")[0]: line.split(": ")[1] for line in request_lines[1:] if ": " in line}
        
        request_method = request_lines[0].split(' ')[0]
        request_target = request_lines[0].split(' ')[1]

        if request_method == "POST" and request_target == "/":
            response = handle_post_request(request_headers)
        else:
            response = "HTTP/1.0 501 Not Implemented\r\nContent-Type: text/plain\r\n\r\nThis method is not supported."

        client_connection.sendall(response.encode())
        client_connection.close()

if __name__ == "__main__":
    start_server()
