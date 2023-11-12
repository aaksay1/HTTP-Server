import socket
import json
import random
import datetime
import hashlib
import sys

IP = sys.argv[1]
PORT = int(sys.argv[2])
ACCOUNTS_FILE = sys.argv[3]
SESSION_TIMEOUT = int(sys.argv[4])
ROOT_DIRECTORY = sys.argv[5]

with open(ACCOUNTS_FILE, 'r') as accounts_file:
    accounts_data = json.load(accounts_file)

SESSIONS = {}

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def create_sessionID():
    return '0x' + format(random.getrandbits(64), 'x')


def verify_credentials(username, password):
    user_data = accounts_data.get(username, None)
    if not user_data:
        return False
    stored_hashed_password, salt = user_data
    hashed_input_password = hash_password(password, salt)

    if hashed_input_password == stored_hashed_password:
        return True
    else:
        return False

def log_message(message):
    current_time = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    print(f"SERVER LOG: {current_time} {message}")

def handle_post_request(request_data):
    headers, _ = request_data.split("\r\n\r\n", 1)
    headers_dict = dict(line.split(": ", 1) for line in headers.split("\r\n") if ": " in line)
    
    username = headers_dict.get("username")
    password = headers_dict.get("password")

    if not username or not password:
        log_message("LOGIN FAILED")
        return "HTTP/1.0 501 Not Implemented\r\n\r\n"
    
    if verify_credentials(username, password):
        sessionID = create_sessionID()
        SESSIONS[sessionID] = {'username': username, 'expires': datetime.datetime.now() + datetime.timedelta(seconds=SESSION_TIMEOUT)}
        log_message(f"LOGIN SUCCESSFUL: {username} : {password}")
        return f"HTTP/1.0 200 OK\r\nSet-Cookie: sessionID={sessionID}\r\n\r\nLogged in!"
    else:
        log_message(f"LOGIN FAILED: {username} : {password}")
        return "HTTP/1.0 200 OK\r\n\r\nLogin failed!"

def get_session_from_cookie(cookie_string):
    sessionID = None
    if 'sessionID' in cookie_string:
        cookies = cookie_string.split(';')
        for cookie in cookies:
            cookie_parts = cookie.split('=')
            if len(cookie_parts) == 2 and cookie_parts[0].strip() == 'sessionID':
                sessionID = cookie_parts[1].strip()
                break
    return sessionID
def handle_get_request(request_data, request_target):
    headers = dict(line.split(": ", 1) for line in request_data.split("\r\n") if ": " in line)
    cookie_string = headers.get("Cookie", "")
    sessionID = get_session_from_cookie(cookie_string)

    if not sessionID:
        log_message(f"COOKIE INVALID: {request_target}")
        return "HTTP/1.0 401 Unauthorized\r\n\r\n"

    session = SESSIONS.get(sessionID)

    if not session:
        log_message(f"COOKIE INVALID: {request_target}")
        return "HTTP/1.0 401 Unauthorized\r\n\r\n"

    username = session['username']
    if session['expires'] < datetime.datetime.now():
        log_message(f"SESSION EXPIRED: {username} : {request_target}")
        return "HTTP/1.0 401 Unauthorized\r\n\r\n"
    SESSIONS[sessionID]['expires'] = datetime.datetime.now() + datetime.timedelta(seconds=SESSION_TIMEOUT)
    filepath = f"{ROOT_DIRECTORY}/{username}/{request_target}"
    if ".." in filepath or not filepath.startswith(f"{ROOT_DIRECTORY}/{username}/"):
        log_message(f"GET FAILED: {username} : {request_target}")
        return "HTTP/1.0 404 NOT FOUND\r\n\r\n"
    try:
        with open(filepath, 'r') as file:
            file_contents = file.read()
        log_message(f"GET SUCCEEDED: {username} : {request_target}")
        return f"HTTP/1.0 200 OK\r\n\r\n{file_contents}"
    except FileNotFoundError:
        log_message(f"GET FAILED: {username} : {request_target}")
        return "HTTP/1.0 404 NOT FOUND\r\n\r\n"

def start_server(IP, PORT, ACCOUNTS_FILE, SESSION_TIMEOUT, ROOT_DIRECTORY):
    with open(ACCOUNTS_FILE, 'r') as accounts_file:
        accounts_data = json.load(accounts_file)

    SESSIONS = {}

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen(5)

    while True:
        client_connection, client_address = server_socket.accept()
        request = client_connection.recv(1024).decode()
        request_lines = request.split("\r\n")
        request_line = request_lines[0]
        method, path, version = request_line.split(" ")

        if method == "POST" and path == "/":
            response = handle_post_request(request)
        elif method == "GET":
            response = handle_get_request(request, path)
        else:
            response = "HTTP/1.0 501 Not Implemented\r\n\r\n"

        client_connection.sendall(response.encode())
        client_connection.close()

if __name__ == "__main__":
    IP = sys.argv[1]
    PORT = int(sys.argv[2])
    ACCOUNTS_FILE = sys.argv[3]
    SESSION_TIMEOUT = int(sys.argv[4])
    ROOT_DIRECTORY = sys.argv[5]

    start_server(IP, PORT, ACCOUNTS_FILE, SESSION_TIMEOUT, ROOT_DIRECTORY)