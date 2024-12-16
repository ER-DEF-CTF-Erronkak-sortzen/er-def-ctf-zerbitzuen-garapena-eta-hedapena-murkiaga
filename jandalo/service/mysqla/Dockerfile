# Usar la imagen oficial de MySQL
FROM mysql:8.0

# Establecer las variables de entorno para MySQL
ENV MYSQL_ROOT_PASSWORD=rootpassword
ENV MYSQL_DATABASE=ctf_db
ENV MYSQL_USER=dev1
ENV MYSQL_PASSWORD=w3ar3h4ck3r2

# Copiar el script de inicialización al contenedor
COPY init.sql /docker-entrypoint-initdb.d/

EXPOSE 3306