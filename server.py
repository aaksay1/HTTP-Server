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
        log_message(f"LOGIN FAILED: Username not found - {username}")
        return False
    stored_hashed_password, salt = user_data
    hashed_input_password = hash_password(password, salt)
    log_message(f"Hashed Input: {hashed_input_password}")
    log_message(f"Stored Hash: {stored_hashed_password}")

    if hashed_input_password == stored_hashed_password:
        log_message(f"LOGIN SUCCESSFUL: {username}")
        return True
    else:
        log_message(f"LOGIN FAILED: Incorrect password for {username}")
        return False

def log_message(message):
    current_time = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    print(f"SERVER LOG: {current_time} {message}")

def handle_post_request(request_data):
    try:
        lines = request_data.split("\r\n\r\n", 1)
        headers = lines[0]
        body = lines[1]

        log_message(f"POST Data: {body}")

        credentials = dict(x.split("=") for x in body.split("&"))
        username = credentials.get("username")
        password = credentials.get("password")

        if not username or not password:
            log_message("LOGIN FAILED: Missing username or password")
            return "HTTP/1.0 400 Bad Request\r\n\r\nLogin failed due to missing credentials."
        if verify_credentials(username, password):
            session_id = create_session_id()
            SESSIONS[session_id] = {'username': username, 'expires': datetime.datetime.now() + datetime.timedelta(seconds=SESSION_TIMEOUT)}
            log_message(f"Created Session: {session_id} with expiry {SESSIONS[session_id]['expires']}")
            log_message(f"LOGIN SUCCESSFUL: {username}")
            return f"HTTP/1.0 200 OK\r\nSet-Cookie: sessionID={session_id}; Path=/\r\n\r\nLogged in!"
        else:
            log_message(f"LOGIN FAILED: {username}")
            return "HTTP/1.0 401 Unauthorized\r\n\r\nLogin failed due to incorrect credentials."
    except Exception as e:
        log_message(f"LOGIN FAILED: Exception in POST request handling - {e}")
        return "HTTP/1.0 400 Bad Request\r\n\r\nLogin failed due to error processing request."

def get_session_from_cookie(cookie_string):
    try:
        session_id = [part.split('=')[1] for part in cookie_string.split(';') if part.strip().startswith('sessionID')][0]
        return session_id.strip()
    except IndexError:
        return None

def handle_get_request(request_data, request_target):
    try:
        lines = request_data.split("\r\n")
        headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
        cookie_string = headers.get("Cookie", "")
        session_id = get_session_from_cookie(cookie_string)
        
        log_message(f"Retrieved Session ID: {session_id}")
        session = SESSIONS.get(session_id)
        if session:
            log_message(f"Session Expiry: {session['expires']}")
            log_message(f"Current Time: {datetime.datetime.now()}")

            if session['expires'] < datetime.datetime.now():
                log_message(f"SESSION EXPIRED: {session_id}")
                return "HTTP/1.0 401 Unauthorized\r\n\r\nSession expired or invalid."

            SESSIONS[session_id]['expires'] = datetime.datetime.now() + datetime.timedelta(seconds=SESSION_TIMEOUT)
            username = SESSIONS[session_id]['username']
            user_directory = ROOT_DIRECTORY + '/' + username
            filepath = user_directory + '/' + request_target.lstrip("/")

            if not filepath.startswith(user_directory):
                log_message(f"GET FAILED: Attempted Directory Traversal by {username}")
                return "HTTP/1.0 403 Forbidden\r\n\r\nAccess denied."

            try:
                with open(filepath, 'r') as file:
                    file_contents = file.read()
                log_message(f"GET SUCCEEDED: {username} : {request_target}")
                return f"HTTP/1.0 200 OK\r\n\r\n{file_contents}"
            except FileNotFoundError:
                log_message(f"GET FAILED: File not found - {username} : {request_target}")
                return "HTTP/1.0 404 Not Found\r\n\r\nFile not found."
            except Exception as e:
                log_message(f"GET FAILED: Error accessing file - {e}")
                return "HTTP/1.0 500 Internal Server Error\r\n\r\nInternal server error."
        else:
            log_message("SESSION INVALID: No matching session found")
            return "HTTP/1.0 401 Unauthorized\r\n\r\nSession expired or invalid."
    except Exception as e:
        log_message(f"GET FAILED: Error processing request - {e}")
        return "HTTP/1.0 400 Bad Request\r\n\r\nError processing request."

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen(5)
    log_message(f"Starting HTTP server on {IP}:{PORT}")

    while True:
        client_connection, client_address = server_socket.accept()
        request = client_connection.recv(1024).decode()
        request_method, request_target, _ = request.split(' ')[:3]

        if request_method == "POST" and request_target == "/":
            response = handle_post_request(request)
        elif request_method == "GET":
            response = handle_get_request(request, request_target)
        else:
            log_message("UNSUPPORTED METHOD")
            response = "HTTP/1.0 501 Not Implemented\r\n\r\n"

        client_connection.sendall(response.encode())
        client_connection.close()

if __name__ == "__main__":
    start_server()
