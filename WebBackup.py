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
        filename = request.split()[1]

        f = open(filename[1:])

        outputdata = f.read()
        # print(outputdata)
        # Envie uma linha de cabeçalho HTTP para o socket
        connectionSocket.send('\nHTTP/1.1 200 OK \n\n'.encode())

        # Envie o conteúdo do arquivo solicitado ao cliente
        for i in range(0, len(outputdata)):
            connectionSocket.send(outputdata[i].encode())
        connectionSocket.send("\r\n".encode())
        connectionSocket.close()

    except IOError:
        # Enviar mensagem de resposta para arquivo não encontrado
        connectionSocket.send("\nHTTP/1.1 404 Not Found\n\n".encode())
        # Fechar socket do cliente
        serverSocket.close()

serverSocket.close()
sys.exit()  # Encerre o programa após enviar os dados correspondentes
