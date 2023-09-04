import socket
import threading
import sys


def get_local_ip():
    try:
        host_name = socket.gethostname()
        local_ip = socket.gethostbyname(host_name)
        return local_ip
    except Exception as e:
        print(f"Erro ao obter o endereço IP local: {str(e)}")
        return None


def handle_client(data, addr, serverSocket):
    try:
        filename = data.decode().split()[1]

        with open(filename[1:], 'rb') as f:
            outputdata = f.read()

        serverSocket.sendto(b'HTTP/1.1 200 OK\n\n', addr)
        serverSocket.sendto(outputdata, addr)

    except IOError:
        serverSocket.sendto(b'HTTP/1.1 404 Not Found\n\n', addr)


def run_server():
    serverPort = 6789
    ipServer = get_local_ip() or 'localhost'
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serverSocket.bind((ipServer, serverPort))
        print(f"\nExecutando em http://{ipServer}:{serverPort}/login.html")

        while True:
            print('Servidor está pronto...')
            data, addr = serverSocket.recvfrom(2048)
            thread = threading.Thread(
                target=handle_client, args=(data, addr, serverSocket))
            thread.start()

    except Exception as e:
        print(f"Erro: {e}")

    finally:
        serverSocket.close()


run_server()
