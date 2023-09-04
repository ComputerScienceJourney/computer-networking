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


# Atualmente so recebe UM resposta.
def http_client(server_ip, server_port, path):
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        request = f"GET {path} HTTP/1.1\r\nHost: {server_ip}:{server_port}\r\n\r\n"

        clientSocket.sendto(request.encode(), (server_ip, server_port))

        response, server_address = clientSocket.recvfrom(2048)
        print(response.decode())

        clientSocket.close()

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python http_client.py <server_ip> <server_port> <path>")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    path = '/' + sys.argv[3].split('/')[-1]
    print(server_ip, server_port, path)
    http_client(server_ip, server_port, path)
