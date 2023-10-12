from socket import *
from ssl import *
import pandas as pd
from urllib.parse import parse_qsl
import hashlib
import threading


class webserver:
    def __init__(self, ip, port) -> None:
        self.ip = 'localhost'
        self.port = port
        self.USER_INFO = None
        self.DATABASE = pd.read_csv('dados/database.csv')

    def run(self):
        serverSocket = socket(AF_INET, SOCK_STREAM)
        serverSocket.bind((self.ip, self.port))
        serverSocket.listen(5)

        # context = create_default_context(Purpose.CLIENT_AUTH)
        context = SSLContext(PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="certificados/certificado1234.pem")
        context.options |= OP_NO_TLSv1 | OP_NO_TLSv1_1
        context.set_ciphers('AES256+ECDH:AES256+EDH')

        # acesso rápido ao servidor
        print(f"\nExecutando em http://{self.ip}:{self.port}/login.html")

        while True:
            print('Servidor está pronto...')
            connectionSocket, addr = serverSocket.accept()
            thread = threading.Thread(
                target=self.handler, args=(connectionSocket, addr, context))
            thread.start()

    def handler(self, connectionSocket, addr, context):
        ssl_connection = None

        try:
            ssl_connection = context.wrap_socket(
                connectionSocket, server_side=True)
            request = ssl_connection.recv().decode()
            if not request:
                return

            request = self.makeDictionary(request)

            if request['Method'] == 'POST':

                if request['Referer'].split('/')[-1] == 'login.html':
                    user_session = self.auth_user(
                        request['usuario'], request['senha'])

                    if user_session:
                        client_dns = gethostbyname(self.ip)
                        output_data = self.load_file('home.html')
                        output_data = output_data.replace(
                            b'DNS_AQUI', client_dns.encode())
                        output_data = output_data.replace(
                            b'USER_NAME', self.USER_INFO['nome'].values[0].title().encode())
                        self.send_response(
                            ssl_connection, '200 OK', output_data)

                    else:
                        output_data = self.load_file('error404.html')
                        self.send_response(ssl_connection,
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
                    if not self.user_save(data_user):
                        output_data = self.load_file('error404.html')
                        self.send_response(ssl_connection,
                                           '404 Not Found', output_data)
                        return

                    # Rediciona para pagina de login
                    try:
                        output_data = self.load_file(request['Filename'][1:])
                        self.send_response(
                            ssl_connection, '200 OK', output_data)
                    except FileNotFoundError:
                        output_data = self.load_file('error404.html')
                        self.send_response(ssl_connection,
                                           '404 Not Found', output_data)

            else:
                if request['Filename'][1:] != 'home.html':
                    try:
                        output_data = self.load_file(request['Filename'][1:])
                        self.send_response(
                            ssl_connection, '200 OK', output_data)
                    except FileNotFoundError:
                        output_data = self.load_file('error404.html')
                        self.send_response(ssl_connection,
                                           '404 Not Found', output_data)
                else:
                    output_data = self.load_file('error404.html')
                    self.send_response(
                        ssl_connection, '404 Not Found', output_data)

        except IOError:
            self.send_response(ssl_connection, '404 Not Found', b'')

        finally:
            if ssl_connection:
                ssl_connection.close()

    def auth_user(self, user: str, password: str) -> bool:
        """
        Autentica um usuário com base em um nome de usuário e senha fornecidos.

        Args:
            user (str): O nome de usuário que o usuário está tentando autenticar.
            password (str): A senha correspondente ao nome de usuário.

        Returns:
            bool: True se a autenticação for bem-sucedida; False caso contrário.
        """
        user = user.lower()
        user_row = self.DATABASE.loc[self.DATABASE['usuario'] == user]
        password = hashlib.md5(password.encode()).hexdigest()
        if not user_row.empty and str(user_row.iloc[0]['senha']) == password:
            self.USER_INFO = user_row
            return True
        return False

    def user_save(self, data_user: dict) -> bool:
        """
        Salva informações do usuário em um banco de dados, verificando se o usuário já existe.

        Args:
            data_user (dict): Um dicionário contendo informações do usuário a serem salvas.
                Deve conter as chaves 'usuario' (nome de usuário) e outras informações relevantes.

        Returns:
            bool: True se o usuário foi salvo com sucesso; False se o usuário já existe no banco de dados.
        """
        data_user['usuario'] = data_user['usuario'].lower()
        user_row = self.DATABASE.loc[self.DATABASE['usuario']
                                     == data_user['usuario']]

        if user_row.empty:
            data_user = pd.DataFrame([data_user])
            self.DATABASE = pd.concat(
                [self.DATABASE, data_user], ignore_index=True)
            self.DATABASE.to_csv('dados/database.csv', index=False)
            return True

        else:
            return False

    def send_response(self, ssl_connection: SSLSocket, status: str, content: bytes) -> None:
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
        ssl_connection.write(response.encode())
        ssl_connection.write(content)

    def load_file(self, filename: str) -> bytes:
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
            return self.load_file('error404.html')

    def makeDictionary(self, request: str) -> dict:
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


if __name__ == "__main__":
    server_ip = get_local_ip() or 'localhost'
    port = 6789
    server = webserver(server_ip, port)
    server.run()
