from socket import *
import sys


def get_local_ip():
    try:
        # Obtenha o nome do host da máquina
        host_name = gethostname()

        # Resolva o nome do host para o endereço IP
        local_ip = gethostbyname(host_name)

        return local_ip
    except Exception as e:
        print(f"Erro ao obter o endereço IP local: {str(e)}")
        return None


def getUserAndPass(request):
    user_data = request.split('\r\n\r\n')[1]
    user, password = user_data.split('&')
    user = user.split('=')[1]
    password = password.split('=')[1]

    return user, password


def send_response(connection_socket, status, content):
    response = f'\nHTTP/1.1 {status}\n\n'
    connection_socket.send(response.encode())
    connection_socket.sendall(content)


# (AF_INET é usado para protolocos IPv4) & (SOCK_STREAM é usado para TCP)
serverSocket = socket(AF_INET, SOCK_STREAM)

# Configuração inicial
local_ip = get_local_ip()
server_ip = local_ip if local_ip else 'localhost'
port = 6789

# Configuração de usuário
data_login = {'usuario': 'admin', 'senha': '1234'}

# Prepare um socket de servidor
serverSocket.bind((server_ip, port))
serverSocket.listen(1)

# acesso rápido ao servidor
print(f"\nExecutando em http://{server_ip}:{port}/login.html")


while True:
    # Estabeleça a conexão
    print('Servidor está pronto...')

    connectionSocket, addr = serverSocket.accept()

    try:
        request = connectionSocket.recv(1024).decode()
        if not request:
            continue

        print('\n' + request + '\n')

        method = request.split()[0]
        filename = request.split()[1]

        if method == 'POST':
            user, password = getUserAndPass(request)

            if user == data_login['usuario'] and password == data_login['senha']:
                # Obter o endereço DNS do cliente
                client_dns = gethostbyname(server_ip)

                with open('home.html', 'rb') as f:
                    output_data = f.read()

                output_data = output_data.replace(
                    b'DNS_AQUI', client_dns.encode())

                send_response(connectionSocket, '200 OK', output_data)
            else:
                with open('error404.html', 'rb') as f:
                    output_data = f.read()

                send_response(connectionSocket, '404 Not Found', output_data)

        else:
            if filename[1:] != 'home.html':
                try:
                    with open(filename[1:], 'rb') as f:
                        output_data = f.read()
                    send_response(connectionSocket, '200 OK', output_data)
                except FileNotFoundError:
                    with open('error404.html', 'rb') as f:
                        output_data = f.read()
                    send_response(connectionSocket,
                                  '404 Not Found', output_data)
            else:
                with open('error404.html', 'rb') as f:
                    output_data = f.read()
                send_response(connectionSocket, '404 Not Found', output_data)

        connectionSocket.close()

    except IOError:
        send_response(connectionSocket, '404 Not Found', b'')

serverSocket.close()
sys.exit()
