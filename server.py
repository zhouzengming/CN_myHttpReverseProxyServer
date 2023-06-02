import socket
import os
from configparser import ConfigParser
import threading
from datetime import datetime

class ReverseProxyServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None

    def start(self):
        try:
            # 创建套接字并绑定地址和端口
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))

            # 开始监听连接
            self.server_socket.listen(1)
            print(f"Reverse proxy server is running on {self.host}:{self.port}")

            while True:
                # 接受客户端连接
                client_socket, client_address = self.server_socket.accept()

                # 创建新线程来处理客户端请求
                client_thread = threading.Thread(target=self.handle_client_request, args=(client_socket,))
                client_thread.start()
        except KeyboardInterrupt:
            print("Server stopped.")
        finally:
            # 关闭服务器套接字
            if self.server_socket:
                self.server_socket.close()

    def handle_client_request(self, client_socket):
        # 接收客户端请求数据
        request_data = client_socket.recv(4096)

        # 解析请求数据，获取请求的域名
        host = self.get_host_from_request(request_data.decode())

        if host:
            # 根据域名读取对应的配置文件
            config_file = f"./config/sites/{host}.ini"
            if not os.path.isfile(config_file):
                self.send_error_response(client_socket, 404, "File Not Found")
                client_socket.close()
                return

            # 解析配置文件
            config = ConfigParser()
            config.read(config_file)

            # 获取目标主机和端口
            target_host = config.get('server', 'target_host')
            target_port = config.getint('server', 'target_port')

            try:
                # 创建与目标主机的连接
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.connect((target_host, target_port))

                # 发送请求数据到目标主机
                target_socket.sendall(request_data)

                # 接收目标主机的响应数据
                response_data = self.receive_response(target_socket)

                # 将响应数据发送给客户端
                client_socket.sendall(response_data)

                # 记录日志
                # 记录访问日志
                self.log_request(host, client_socket.getpeername(), request_data.decode(), response_data.decode())
            except Exception as e:
                self.send_error_response(client_socket, 500, str(e))
            finally:
                # 关闭与目标主机的连接
                target_socket.close()
                # 关闭与客户端的连接
                client_socket.close()
        else:
            self.send_error_response(client_socket, 400, "Bad Request")
            client_socket.close()

    def get_host_from_request(self, request_data):
        host = None
        lines = request_data.split('\r\n')
        for line in lines:
            if line.startswith('Host:'):
                host = line.split(': ')[1]
                break
        return host

    def receive_response(self, target_socket):
        response_data = b""
        while True:
            data = target_socket.recv(4096)
            if not data:
                break
            response_data += data
        return response_data

    def send_error_response(self, client_socket, status_code, message):
        response = f"HTTP/1.1 {status_code} {message}\r\n\r\n"
        client_socket.sendall(response.encode())

    def log_request(self, host, client_ip, request_data, response_data):
        log_file = f"./logs/{host}.log"
        if not os.path.isfile(log_file):
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            open(log_file, "w").close()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        response_code = response_data.split(' ', 2)[1]

        log_entry = f"{timestamp} - IP: {client_ip[0]} - Host: {host} - Request: {request_data.split(' ')[1]} - Response Code: {response_code}\n"

        with open(log_file, "a") as f:
            f.write(log_entry)


if __name__ == '__main__':
    # 读取服务器配置
    config = ConfigParser()
    config.read('./config/server.ini')
    server_address = (config.get('Server', 'ip'), int(config.get('Server', 'port')))

    # 创建反向代理服务器实例
    proxy_server = ReverseProxyServer(*server_address)

    # 启动服务器
    proxy_server.start()
