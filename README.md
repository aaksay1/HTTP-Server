# HTTP-Server

to run:
python3 server.py 127.0.0.1 8080 accounts.json 300 accounts/

client:

curl -i -X POST http://127.0.0.1:8080/ -d "username=Ben&password=PXMAZPRE0H0U0OD"
curl -X GET http://127.0.0.1:8080/file.txt -H "Cookie: sessionID=(recievedcookie)"
