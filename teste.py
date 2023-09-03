import socket
import threading
import sys

# Configuração de usuário
USER_DATA = {'usuario': 'admin', 'senha': '1234'}


def get_local_ip():
    try:
        host_name = socket.gethostname()
        local_ip = socket.gethostbyname(host_name)
        return local_ip
    except Exception as e:
        print(f"Erro ao obter o endereço IP local: {str(e)}")
        return None


def parse_request(request):
    headers, body = request.split('\r\n\r\n', 1)
    method, path, _ = headers.split('\r\n', 1)[0].split()
    return method, path, body


def send_response(connection_socket, status, content):
    response = f'\nHTTP/1.1 {status}\n\n'
    connection_socket.send(response.encode())
    connection_socket.sendall(content)


def handle_client(connection_socket, server_ip):
    try:
        request = connection_socket.recv(2048).decode()
        if not request:
            return

        method, filename, body = parse_request(request)

        if method == 'POST':
            user, password = parse_post_data(body)

            if user == USER_DATA['usuario'] and password == USER_DATA['senha']:
                client_dns = socket.gethostbyname(server_ip)
                with open('home.html', 'rb') as f:
                    output_data = f.read()
                output_data = output_data.replace(
                    b'DNS_AQUI', client_dns.encode())
                send_response(connection_socket, '200 OK', output_data)
            else:
                send_404_response(connection_socket)
        else:
            serve_static_file(connection_socket, filename)

    except IOError:
        send_404_response(connection_socket)

    finally:
        connection_socket.close()


def parse_post_data(data):
    data_dict = {}
    for field in data.split('&'):
        key, value = field.split('=')
        data_dict[key] = value
    return data_dict.get('usuario', ''), data_dict.get('senha', '')


def send_404_response(connection_socket):
    with open('error404.html', 'rb') as f:
        output_data = f.read()
    send_response(connection_socket, '404 Not Found', output_data)


def serve_static_file(connection_socket, filename):
    if filename[1:] == 'home.html':
        send_404_response(connection_socket)
        return

    try:
        with open(filename[1:], 'rb') as f:
            output_data = f.read()
        send_response(connection_socket, '200 OK', output_data)
    except FileNotFoundError:
        send_404_response(connection_socket)


def run_server():
    local_ip = get_local_ip() or 'localhost'
    port = 6789

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((local_ip, port))
        server_socket.listen(1)

        print(f"\nExecutando em http://{local_ip}:{port}/login.html")

        while True:
            print('Servidor está pronto...')
            connection_socket, addr = server_socket.accept()
            thread = threading.Thread(
                target=handle_client, args=(connection_socket, local_ip))
            thread.start()

    except Exception as e:
        print(f"Erro: {e}")

    finally:
        server_socket.close()


if __name__ == '__main__':
    run_server()
