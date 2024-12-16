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
        self.db_user = "root"
        self.db_password = "rootpassword"
        self.db_name = "ctf_db"
    
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
        except:
            logging.error("Error al conectar con la base de datos")
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
        
        #MUA orain fitxategia aldatu daiteke if not self._check_web_integrity(file_path_web):
        #MUA    return checkerlib.CheckResult.FAULTY  
        # Check erabiltzaile:pasahitza users.txt fitxategia existitzen den ala ez (edukia kontuan hartu gabe)
        file_path_web_users = '/usr/local/apache2/htdocs/admin/users.txt'       
        if not self._check_userstxt_exist(file_path_web_users):
            return checkerlib.CheckResult.FAULTY
        
        #Orain erabiltzailea aldatu daiteke. Checkeatu ea dev1 erabiltzailea existitzen den datubasean.
        ##MUA if not self._check_user_in_db('dev1'):
        #MUA    return checkerlib.CheckResult.FAULTY
        # check if 'user':'pass' in users.txt exists in jandalo_mysql docker's database
        if not self._check_user_with_credentials(file_path_web_users):
            return checkerlib.CheckResult.FAULTY
                
        return checkerlib.CheckResult.OK
    
    def check_flag(self, tick):
        if not self.check_service():
            return checkerlib.CheckResult.DOWN
        flag = checkerlib.get_flag(tick)
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
    def _check_userstxt_exist(self, path):
        ssh_session = self.client
        command = f"docker exec jandalo_web_1 sh -c 'test -f {path} && echo exists || echo not_exists'"
        stdin, stdout, stderr = ssh_session.exec_command(command)
        if stderr.channel.recv_exit_status() != 0:
            print(f"Error executing command: {stderr.read().decode().strip()}")
            return False

        output = stdout.read().decode().strip()
        print(f"File existence check output: {output}")
        return output == "exists"

    # Private Funcs - Return False if error
    def _add_new_flag(self, connection, flag):
        try:
            cursor = connection.cursor()
            # Insertar el flag en la tabla
            query = "INSERT INTO flag (flag_value) VALUES (%s)"
            cursor.execute(query, (flag,))
            connection.commit()
            return {'flag': flag}
        except:
            logging.error("Error al insertar el flag:")
            return False     

    @ssh_connect()
    #Function to check if an user exists
    def _check_user_in_db(self, username):
        ssh_session = self.client
        command = (
            "docker exec jandalo_mysql_1 "
            "mysql -u root -prootpassword -c " # edo -e?
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
            count = int(lines[1])  # Lehen lerroan COUNT(*) eta bigarrenean emaitza dago
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

    @ssh_connect()
    def _check_user_with_credentials(self, userfile_path):
        ssh_session = self.client

        # userfile_path-en fitxategia irakurri (erabiltzaile:pasahitz formatua espero da)
        command = f"docker exec jandalo_web_1 sh -c 'cat {userfile_path}'"
        stdin, stdout, stderr = ssh_session.exec_command(command)

        if stderr.channel.recv_exit_status() != 0:
            print(f"Error reading credentials file: {stderr.read().decode().strip()}")
            return False

        # Irteeratik erabiltzaile:pasahitza jaso
        output = stdout.read().decode().strip()
        print(f"Raw credentials file content:\n{output}")
        try:
            username, password = output.split(":")
        except ValueError:
            print("Invalid format in credentials file. Expected 'username:password'")
            return False

        # Konprobatu ea erabiltzaile:pasahitza existitzen den mysqlen
        mysql_command = (
            f"docker exec jandalo_mysql_1 "
            f"mysql -u {username} -p{password} -e 'SELECT 1;'"
        )
        try:
            stdin, stdout, stderr = ssh_session.exec_command(mysql_command)

            if stderr.channel.recv_exit_status() != 0:
                print(f"Invalid MySQL credentials for user '{username}': {stderr.read().decode().strip()}")
                return False
        except:
            return False

        print(f"MySQL credentials for user '{username}' are valid.")
        return True

if __name__ == '__main__':
    checkerlib.run_check(MyChecker)




