FROM httpd:2.4.50

COPY ./index.html /usr/local/apache2/htdocs/index.html

#Copy user:pass file to admin folder
COPY ./users.txt /usr/local/apache2/htdocs/admin/users.txt
COPY ./secret.txt /usr/local/apache2/htdocs/admin/secret.txt