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
server_ip = 'localhost'

# Configuração de usuário
dataLogin = {'usuario': 'admin',
             'senha': '1234'}

print(f"\nExecutando em http://{server_ip}:{port}/login.html")

# Prepare um socket de servidor
serverSocket.bind((server_ip, port))
serverSocket.listen(1)
link = True
while True:
    # Estabeleça a conexão
    print('Servidor está pronto...')

    connectionSocket, addr = serverSocket.accept()

    try:
        request = connectionSocket.recv(1024).decode()
        if not request:
            continue

        # Obter o endereço DNS do cliente
        client_dns = gethostbyname(server_ip)
        print('\n' + request + '\n')

        method = request.split()[0]
        filename = request.split()[1]

        if method == 'POST':
            # Pega os dados do corpo do POST
            user, password = getUserAndPass(request)

            if user == dataLogin['usuario'] and password == dataLogin['senha']:
                response = '\nHTTP/1.1 200 OK \n\n'
                connectionSocket.send(response.encode())

                with open('home.html', 'rb') as f:
                    outputdata = f.read()
                outputdata = outputdata.replace(
                    b'DNS_AQUI', client_dns.encode())

                connectionSocket.send(outputdata)
            else:
                # Se as credenciais estiverem incorretas, envie uma mensagem de erro.
                response = "\nHTTP/1.1 404 Not Found\n\n"
                connectionSocket.send(response.encode())

                with open('error404.html', 'rb') as f:
                    outputdata = f.read()
                connectionSocket.sendall(outputdata)

        else:
            # Se não for um pedido POST, trate como GET
            if filename[1:] != 'home.html':
                try:
                    with open(filename[1:], 'rb') as f:
                        outputdata = f.read()
                    connectionSocket.send('\nHTTP/1.1 200 OK \n\n'.encode())
                    connectionSocket.sendall(outputdata)
                except FileNotFoundError:
                    # Enviar mensagem de resposta para arquivo não encontrado
                    response = "\nHTTP/1.1 404 Not Found\n\n"
                    connectionSocket.send(response.encode())

            else:
                response = "\nHTTP/1.1 404 Not Found\n\n"
                connectionSocket.send(response.encode())

                with open('error404.html', 'rb') as f:
                    outputdata = f.read()
                connectionSocket.sendall(outputdata)
        connectionSocket.close()

    except IOError:
        # Enviar mensagem de resposta para arquivo não encontrado
        response = "\nHTTP/1.1 404 Not Found\n\n"
        connectionSocket.send(response.encode())
        # Fechar socket do cliente
        serverSocket.close()

serverSocket.close()
sys.exit()  # Encerre o programa após enviar os dados correspondentes
