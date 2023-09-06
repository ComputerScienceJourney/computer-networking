from socket import *
import pandas as pd
from urllib.parse import parse_qsl
import hashlib

# carregando o banco de dados local
DATABASE = pd.read_csv('dados/database.csv')

# informações do usuário ao ser autenticado
USER_LOGIN = None


def auth_user(user: str, password: str) -> bool:
    """
    Autentica um usuário com base em um nome de usuário e senha fornecidos.

    Args:
        user (str): O nome de usuário que o usuário está tentando autenticar.
        password (str): A senha correspondente ao nome de usuário.

    Returns:
        bool: True se a autenticação for bem-sucedida; False caso contrário.
    """
    global USER_LOGIN, DATABASE
    user = user.lower()
    user_row = DATABASE.loc[DATABASE['usuario'] == user]
    password = hashlib.md5(password.encode()).hexdigest()
    if not user_row.empty and str(user_row.iloc[0]['senha']) == password:
        USER_LOGIN = user_row
        return True
    return False


def user_save(data_user: dict) -> bool:
    """
    Salva informações do usuário em um banco de dados, verificando se o usuário já existe.

    Args:
        data_user (dict): Um dicionário contendo informações do usuário a serem salvas.
            Deve conter as chaves 'usuario' (nome de usuário) e outras informações relevantes.

    Returns:
        bool: True se o usuário foi salvo com sucesso; False se o usuário já existe no banco de dados.
    """
    global DATABASE
    data_user['usuario'] = data_user['usuario'].lower()
    user_row = DATABASE.loc[DATABASE['usuario'] == data_user['usuario']]

    if user_row.empty:
        data_user = pd.DataFrame([data_user])
        DATABASE = pd.concat([DATABASE, data_user], ignore_index=True)
        DATABASE.to_csv('dados/database.csv', index=False)
        return True

    else:
        return False


def get_local_ip() -> str:
    """
    Obtém o endereço IP local da máquina onde este código está sendo executado.

    Returns:
        str: O endereço IP local da máquina como uma string.
             Retorna uma string vazia se houver algum erro ao obter o endereço IP.
    """
    try:
        host_name = gethostname()
        local_ip = gethostbyname(host_name)
        return local_ip

    except Exception as e:
        print(f"Erro ao obter o endereço IP local: {str(e)}")
        return ""


def send_response(connection_socket: socket, status: str, content: bytes) -> None:
    """
    Envia uma resposta HTTP para um socket de conexão com um status e conteúdo fornecidos.

    Args:
        connection_socket (socket): O objeto de soquete de conexão no qual a resposta será enviada.
        status (str): A linha de status da resposta HTTP, por exemplo, '200 OK' ou '404 Not Found'.
        content (bytes): O conteúdo da resposta HTTP, que deve ser uma sequência de bytes.

    Returns:
        None
    """
    response = f'\nHTTP/1.1 {status}\n\n'
    connection_socket.send(response.encode())
    connection_socket.sendall(content)


def load_file(filename: str) -> bytes:
    """
    Carrega um arquivo binário a partir do sistema de arquivos e retorna seu conteúdo como bytes.

    Args:
        filename (str): O nome do arquivo a ser carregado.

    Returns:
        bytes: O conteúdo do arquivo carregado como uma sequência de bytes.
    """
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        # Se o arquivo não for encontrado, carrega um arquivo de erro padrão (404 Not Found).
        return load_file('error404.html')


def makeDictionary(request: str) -> dict:
    """
    Analisa uma string de requisição HTTP e cria um dicionário com informações relevantes.

    Args:
        request (str): A string da requisição HTTP a ser analisada.

    Returns:
        dict: Um dicionário contendo informações da requisição, incluindo o método HTTP,
              o nome do arquivo solicitado, a versão do protocolo, cabeçalhos e dados de POST (se houver).
    """
    data = {}
    # separa as linhas da requisição
    request_lines = request.split('\r\n')

    # Pega a primeira linha da mensagem HTTP e a divide em três partes (método, nome do arquivo, versão)
    parts = request_lines[0].split()
    data['Method'], data['Filename'], data['Version'] = parts

    # Percorre as linhas da requisição para analisar cabeçalhos
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
    # Atualiza o dicionário com os dados de POST
    data.update(post_data)

    return data


serverSocket = socket(AF_INET, SOCK_STREAM)

# Configuração inicial
server_ip = get_local_ip() or 'localhost'
port = 6789

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

                if user_session:
                    client_dns = gethostbyname(server_ip)
                    output_data = load_file('home.html')
                    output_data = output_data.replace(
                        b'DNS_AQUI', client_dns.encode())
                    output_data = output_data.replace(
                        b'NOME_USER', USER_LOGIN['nome'].values[0].encode())
                    send_response(connectionSocket, '200 OK', output_data)

                else:
                    output_data = load_file('error404.html')
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

                # Registra o novo usuário na base de dados
                if not user_save(data_user):
                    output_data = load_file('error404.html')
                    send_response(connectionSocket,
                                  '404 Not Found', output_data)
                    continue

                # Rediciona para pagina de login
                try:
                    output_data = load_file(request['Filename'][1:])
                    send_response(connectionSocket, '200 OK', output_data)
                except FileNotFoundError:
                    output_data = load_file('error404.html')
                    send_response(connectionSocket,
                                  '404 Not Found', output_data)

        else:
            print('recebi GET')
            if request['Filename'][1:] != 'home.html':
                try:
                    output_data = load_file(request['Filename'][1:])
                    send_response(connectionSocket, '200 OK', output_data)
                except FileNotFoundError:
                    output_data = load_file('error404.html')
                    send_response(connectionSocket,
                                  '404 Not Found', output_data)
            else:
                output_data = load_file('error404.html')
                send_response(connectionSocket, '404 Not Found', output_data)

    except IOError:
        send_response(connectionSocket, '404 Not Found', b'')

    finally:
        connectionSocket.close()
