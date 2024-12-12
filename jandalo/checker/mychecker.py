#!/usr/bin/env python3

from ctf_gameserver import checkerlib
import logging
import http.client
import socket
import paramiko
import hashlib
import mysql.connector

PORT_WEB = 9798
PORT_MYSQL = 8833

def ssh_connect():
    def decorator(func):
        def wrapper(*args, **kwargs):
            # SSH connection setup
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            rsa_key = paramiko.RSAKey.from_private_key_file(f'/keys/team{args[0].team}-sshkey')
            client.connect(args[0].ip, username = 'root', pkey=rsa_key)

            # Call the decorated function with the client parameter
            args[0].client = client
            result = func(*args, **kwargs)

            # SSH connection cleanup
            client.close()
            return result
        return wrapper
    return decorator

class MyChecker(checkerlib.BaseChecker):

    def __init__(self, ip, team):
        checkerlib.BaseChecker.__init__(self, ip, team)
        self._baseurl = f'http://[{self.ip}]:{PORT_WEB}'
        logging.info(f"URL: {self._baseurl}")
        self.db_host = self.ip
        self.db_port = PORT_MYSQL
        self.db_user = "dev1"
        self.db_password = "w3ar3h4ck3r2"
        self.db_name = "ctf_db"

    #@ssh_connect()
    #def place_flag(self, tick): #EGITEKE MUA
    #    flag = checkerlib.get_flag(tick)
    #    creds = self._add_new_flag(self.client, flag)
    #    if not creds:
    #        return checkerlib.CheckResult.FAULTY
    #    logging.info('created')
    #    checkerlib.store_state(str(tick), creds)
    #    checkerlib.set_flagid(str(tick))
    #    return checkerlib.CheckResult.OK
    
    @ssh_connect()  # Decorador proporcionado por tu infraestructura
    def place_flag(self, tick):
        flag = checkerlib.get_flag(tick)
        try:
            # Conexión a la base de datos
            connection = mysql.connector.connect(
                host=self.db_host,
                port=self.db_port,
                user=self.db_user,
                password=self.db_password,
                database=self.db_name
            )
            if connection.is_connected():
                logging.info("Conexión a MySQL exitosa.")
                # Llamar a la función para insertar el flag
                if not self._add_new_flag(connection, flag):
                    return checkerlib.CheckResult.FAULTY
            else:
                logging.error("No se pudo conectar a MySQL.")
                return checkerlib.CheckResult.FAULTY
        except Error as e:
            logging.error(f"Error al conectar con la base de datos: {e}")
            return checkerlib.CheckResult.FAULTY
        finally:
            if 'connection' in locals() and connection.is_connected():
                connection.close()

        logging.info("Flag creado correctamente.")
        checkerlib.store_state(str(tick), {"flag": flag})
        checkerlib.set_flagid(str(tick))
        return checkerlib.CheckResult.OK

    def check_service(self):
        # check if ports are open
        if not self._check_port_web(self.ip, PORT_WEB) or not self._check_port_mysql(self.ip, PORT_MYSQL):
            return checkerlib.CheckResult.DOWN
        #else
        # check if server is Apache 2.4.50
        ##MUAif not self._check_apache_version():
        ##MUA    return checkerlib.CheckResult.FAULTY
        # check if dev1 user exists in pasapasa_ssh docker
        if not self._check_user_in_db('dev1'):
            return checkerlib.CheckResult.FAULTY
        file_path_web = '/usr/local/apache2/htdocs/admin/users.txt'
        # check if index.hmtl from pasapasa_web has been changed by comparing its hash with the hash of the original file
        if not self._check_web_integrity(file_path_web):
            return checkerlib.CheckResult.FAULTY            
        ##MUAfile_path_ssh = '/etc/ssh/sshd_config'
        # check if /etc/sshd_config from pasapasa_ssh has been changed by comparing its hash with the hash of the original file
        ##MUAif not self._check_ssh_integrity(file_path_ssh):
        ##MUA    return checkerlib.CheckResult.FAULTY            
        return checkerlib.CheckResult.OK
    
    def check_flag(self, tick):
        if not self.check_service():
            return checkerlib.CheckResult.DOWN
        flag = checkerlib.get_flag(tick)
        #creds = checkerlib.load_state("flag_" + str(tick))
        # if not creds:
        #     logging.error(f"Cannot find creds for tick {tick}")
        #     return checkerlib.CheckResult.FLAG_NOT_FOUND
        flag_present = self._check_flag_present(flag)
        if not flag_present:
            return checkerlib.CheckResult.FLAG_NOT_FOUND
        return checkerlib.CheckResult.OK
      
    @ssh_connect()
    def _check_web_integrity(self, path):
        ssh_session = self.client
        command = f"docker exec jandalo_web_1 sh -c 'cat {path}'"
        stdin, stdout, stderr = ssh_session.exec_command(command)
        if stderr.channel.recv_exit_status() != 0:
            return False
        
        output = stdout.read().decode().strip()
        return hashlib.md5(output.encode()).hexdigest() == '536cb16e62551ba6954fd55833b114b5' #users.txt
    
    @ssh_connect()
    def _check_ssh_integrity(self, path):
        ssh_session = self.client
        command = f"docker exec pasapasa_ssh_1 sh -c 'cat {path}'"
        stdin, stdout, stderr = ssh_session.exec_command(command)
        if stderr.channel.recv_exit_status() != 0:
            return False
        output = stdout.read().decode().strip()
        print (hashlib.md5(output.encode()).hexdigest())

        return hashlib.md5(output.encode()).hexdigest() == 'ba55c65e08e320f1225c76f810f1328b'
  
    # Private Funcs - Return False if error
    def _add_new_flag(self, connection, flag):
        try:
            cursor = connection.cursor()
            # Insertar el flag en la tabla
            query = "INSERT INTO flag (flag_value) VALUES (%s)"
            cursor.execute(query, (flag,))
            connection.commit()
            return {'flag': flag}
        except Error as e:
            logging.error(f"Error al insertar el flag: {e}")
            return False     

    @ssh_connect()
    #Function to check if an user exists
    def _check_user_in_db(self, username):
        ssh_session = self.client
        command = (
            "docker exec jandalo_mysql_1 "
            "mysql -u root -prootpassword -e "
            f"'SELECT COUNT(*) FROM mysql.user WHERE user = \"{username}\";'"
        )
        stdin, stdout, stderr = ssh_session.exec_command(command)
        if stderr.channel.recv_exit_status() != 0:
            return False
        return True   

    @ssh_connect()
    def _check_flag_present(self, flag):
        ssh_session = self.client
        command = (
            "docker exec jandalo_mysql_1 "
            "mysql -u root -prootpassword -e "
            f"'SELECT COUNT(*) FROM ctf_db.flag WHERE flag_value = \"{flag}\";'"
        )
        stdin, stdout, stderr = ssh_session.exec_command(command)
        if stderr.channel.recv_exit_status() != 0:
            return False

        output = stdout.read().decode().strip()
        # Divide la salida en líneas y selecciona la segunda línea (el resultado del conteo)
        lines = output.splitlines()
        if len(lines) < 2:
            print("Unexpected output format")
            return False

        try:
            count = int(lines[1])  # La segunda línea contiene el valor del conteo
            print(f"Flags found: {count}")
            return count > 0
        except ValueError:
            print("Error parsing the count value")
            return False

    def _check_port_web(self, ip, port):
        try:
            conn = http.client.HTTPConnection(ip, port, timeout=5)
            conn.request("GET", "/")
            response = conn.getresponse()
            return response.status == 200
        except (http.client.HTTPException, socket.error) as e:
            print(f"Exception: {e}")
            return False
        finally:
            if conn:
                conn.close()

    def _check_port_mysql(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            return result == 0
        except socket.error as e:
            print(f"Exception: {e}")
            return False
        finally:
            sock.close()


if __name__ == '__main__':
    checkerlib.run_check(MyChecker)




