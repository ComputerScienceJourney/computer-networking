# import socket module
from socket import *
import sys

# (AF_INET é usado para protolocos IPv4)
# (SOCK_STREAM é usado para TCP)
serverSocket = socket(AF_INET, SOCK_STREAM)

port = 6789
server_ip = '127.0.0.1'

print(f"Listening on {server_ip}:{port}")

# Prepare um socket de servidor
serverSocket.bind(('', port))
serverSocket.listen(1)
print('O Servidor Web está ligado na porta:', port)
link = True
while True:
    # Estabeleça a conexão
    print('\nServidor está pronto...\n')

    connectionSocket, addr = serverSocket.accept()

    try:
        request = connectionSocket.recv(1024).decode()
        if not request:
            # if request is not received break
            break

        print(request)
        method = request.split()[0]
        filename = request.split()[1]

        if method == 'POST':
            # Verificar se é um pedido POST
            # Pega os dados do corpo do POST
            user_data = request.split('\r\n\r\n')[1]
            user, password = user_data.split('&')
            user = user.split('=')[1]
            password = password.split('=')[1]

            if user == 'admin' and password == '1234':
                response = 'HTTP/1.1 302 Found\r\nLocation: /home.html\r\n\r\n'
                connectionSocket.send(response.encode())
            else:
                # Se as credenciais estiverem incorretas, envie uma mensagem de erro. Precisa melhorar essa parte
                response = "\nHTTP/1.1 404 Not Found\n\n"
                connectionSocket.send(response.encode())
        else:
            # Se não for um pedido POST, trate como antes
            f = open(filename[1:], encoding="utf-8")
            outputdata = f.read()
            connectionSocket.send('\nHTTP/1.1 200 OK \n\n'.encode())
            for i in range(0, len(outputdata)):
                connectionSocket.send(outputdata[i].encode())
            connectionSocket.send("\r\n".encode())
        connectionSocket.close()

    except IOError:
        # Enviar mensagem de resposta para arquivo não encontrado
        response = "\nHTTP/1.1 404 Not Found\n\n"
        connectionSocket.send(response.encode())
        # Fechar socket do cliente
        serverSocket.close()

serverSocket.close()
sys.exit()  # Encerre o programa após enviar os dados correspondentes
