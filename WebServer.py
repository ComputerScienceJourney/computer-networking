from socket import *
import sys
import pandas as pd
from urllib.parse import parse_qsl
import hashlib

# carregando o banco de dados local
DATABASE = pd.read_csv('dados/database.csv')


def auth_user(user, password):
    user = user.lower()
    user_row = DATABASE.loc[DATABASE['usuario'] == user]
    password = hashlib.md5(password.encode()).hexdigest()
    if not user_row.empty and str(user_row.iloc[0]['senha']) == password:
        return user_row
    return False


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


def send_response(connection_socket, status, content):
    response = f'\nHTTP/1.1 {status}\n\n'
    connection_socket.send(response.encode())
    connection_socket.sendall(content)


def makeDictionary(request):
    data = {}
    # separa as linhas da requisição
    request_lines = request.split('\r\n')

    # pega primeira linha da mensagem hhtp e separa em três
    parts = request_lines[0].split()
    data['Method'], data['Filename'], data['Version'] = parts

    # Percorra as linhas da requisição
    for line in request_lines[1:]:
        if line:
            # Separe o cabeçalho da linha em chave e valor
            parts = line.split(': ')
            if len(parts) == 2:
                key, value = parts
                data[key] = value
        else:
            # Linha em branco indica o fim dos cabeçalhos
            break

    # Processa os dados enviados via POST e separados po &
    body = request.split('\r\n\r\n', 1)[1]
    post_data = dict(parse_qsl(body))

    data.update(post_data)

    return data


# (AF_INET é usado para protolocos IPv4) & (SOCK_STREAM é usado para TCP)
serverSocket = socket(AF_INET, SOCK_STREAM)

# Configuração inicial
# server_ip = get_local_ip() or 'localhost'
server_ip = '192.168.1.106'
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

        request = makeDictionary(request)

        if request['Method'] == 'POST':
            if request['Referer'].split('/')[-1] == 'login.html':
                user_session = auth_user(request['usuario'], request['senha'])
                if len(user_session):
                    # Obter o endereço DNS do cliente
                    client_dns = gethostbyname(server_ip)

                    with open('home.html', 'rb') as f:
                        output_data = f.read()

                    output_data = output_data.replace(
                        b'DNS_AQUI', client_dns.encode())
                    output_data = output_data.replace(
                        b'NOME_USER', user_session['nome'].values[0].encode())

                    send_response(connectionSocket, '200 OK', output_data)
                else:
                    with open('error404.html', 'rb') as f:
                        output_data = f.read()

                    send_response(connectionSocket,
                                  '404 Not Found', output_data)
            else:
                data_user = {
                    'nome': request.get('nome', ''),
                    'sobrenome': request.get('sobrenome', ''),
                    'usuario': request.get('usuario', ''),
                    'senha': hashlib.md5(request.get('senha', '').encode()).hexdigest(),
                    'email': request.get('email', ''),
                }
                data_user = pd.DataFrame([data_user])

                # Registra o novo usuário na base de dados
                DATABASE = pd.concat([DATABASE, data_user], ignore_index=True)
                DATABASE.to_csv('dados/database.csv', index=False)

                # Rediciona para pagina de login
                try:
                    with open(request['Filename'][1:], 'rb') as f:
                        output_data = f.read()
                    send_response(connectionSocket, '200 OK', output_data)
                except FileNotFoundError:
                    with open('error404.html', 'rb') as f:
                        output_data = f.read()
                    send_response(connectionSocket,
                                  '404 Not Found', output_data)

        else:
            if request['Filename'][1:] != 'home.html':
                try:
                    with open(request['Filename'][1:], 'rb') as f:
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
