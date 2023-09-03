from socket import *
import sys


def getUserAndPass(request):
    user_data = request.split('\r\n\r\n')[1]
    user, password = user_data.split('&')
    user = user.split('=')[1]
    password = password.split('=')[1]

    return user, password


# (AF_INET é usado para protolocos IPv4)
# (SOCK_STREAM é usado para TCP)
serverSocket = socket(AF_INET, SOCK_STREAM)

# Configuração inicial
port = 6789
server_ip = '127.0.0.1'

# Configuração de usuário
dataLogin = {'usuario': 'admin',
             'senha': '1234'}

print(f"Executando em http://{server_ip}:{port}")

# Prepare um socket de servidor
serverSocket.bind((server_ip, port))
serverSocket.listen(1)
link = True
while True:
    # Estabeleça a conexão
    print('\nServidor está pronto...\n')

    connectionSocket, addr = serverSocket.accept()

    try:
        request = connectionSocket.recv(1024).decode()
        if not request:
            break

        # Obter o endereço DNS do cliente
        client_dns = addr[0]

        print(request)
        method = request.split()[0]
        filename = request.split()[1]

        if method == 'POST':
            # Pega os dados do corpo do POST
            user, password = getUserAndPass(request)
            print('oiii', dataLogin['usuario'],
                  user, user == dataLogin['usuario'])

            if user == dataLogin['usuario'] and password == dataLogin['senha']:
                response = 'HTTP/1.1 302 Found\r\nLocation: /home.html\r\n\r\n'
                connectionSocket.send(response.encode())
                # response = f'HTTP/1.1 302 Found\r\nLocation: /home.html\r\n\r\nClient DNS: {client_dns}\r\n'
                # connectionSocket.send(response.encode())
            else:
                # Se as credenciais estiverem incorretas, envie uma mensagem de erro. (Precisa melhorar essa parte)
                response = "\nHTTP/1.1 404 Not Found\n\n"
                connectionSocket.send(response.encode())
        else:
            # Se não for um pedido POST, trate como GET
            try:
                with open(filename[1:], 'rb') as f:
                    outputdata = f.read()
                connectionSocket.send('\nHTTP/1.1 200 OK \n\n'.encode())
                connectionSocket.sendall(outputdata)
            except FileNotFoundError:
                # Enviar mensagem de resposta para arquivo não encontrado
                response = "\nHTTP/1.1 404 Not Found\n\n"
                connectionSocket.send(response.encode())
        connectionSocket.close()

    except IOError:
        # Enviar mensagem de resposta para arquivo não encontrado
        response = "\nHTTP/1.1 404 Not Found\n\n"
        connectionSocket.send(response.encode())
        # Fechar socket do cliente
        serverSocket.close()

serverSocket.close()
sys.exit()  # Encerre o programa após enviar os dados correspondentes
