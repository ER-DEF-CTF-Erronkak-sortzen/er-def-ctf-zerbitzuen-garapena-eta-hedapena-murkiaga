# JanDaLo Service definition:
We have two dockers: 
1. A mysql:8.0 image, which contains the flags on da Database. 
2. A httpd:2.4.50 image, with apache service. 
The attacker has access to a web page (web_docker) and has to look for information that can help him accessing the other docker via mysql service.
The flags are stored in mysql database and attacker has to let them in his T-Submission machine. 

# Service implementation:
web docker is configured to take a copy index.html and users.txt files from the host machine, letting them in '*/usr/local/apache2/htdocs/index.html*' and in '*/usr/local/apache2/htdocs/admin/users.txt*'. 
mysql docker is configured attending to the following tips:
  - It has mysql-server installed and started. 
  - It has a user called 'dev1' whose password is 'w3ar3h4ck3r2'. 
  - 'root' user with 'rootpassword' password (only usable for checkers)

users.txt file must have one line with *user:password* and the access to the database must be open. Moreover, if a team denies access to the database with the users.txt *user:password*, it will be losing SLa points. 
 
-Flags: 
    Flags will be stored in 'jandalo_mysql_1' docker's *ctf_db* database in table *flag* that has a column *flag_value*.

# About exploting:
- The attacker has to access to http://*target-ip*/admin folder; the credentialas are stored there as plain text in the file **users.txt**. With those credentials, the attacker can log into jandalo_mysql docker and take the flags from the ctf_db database.
- The defender should change the following things:
  - Disable the access to /admin folder or the user.txt file modifying /**usr/local/apache2/conf/httpd.conf** file
  - Restart the apache service: <code>httpd -k restart</code>
  - Change the username/password of the database.
  - Update the userts.txt file with the new user/password
  
  
- <b>Attack performed by Team1 against Team2: </b><br>
  - Visit web page in 10.0.2.101/admin<br>
      We find users.txt file with 'dev1/w3ar3h4ck3r2' credentials.
  With those credentials, connect to the database of attacked machine:
  <br><code>mysql -P 8833 -h 10.0.2.101 -u dev1 -pw3ar3h4ck3r2</code>

  - Now see what databases exists and select the data of the only database-table:  
  <code>show databases;<br>
  select * from ctf_db.flag;
  </code><br>
  Copy last flags and exit.

  - Place them in Submission machine<br>
  <code>'ssh -i ./keyak/team2-sshkey root@10.0.1.1'</code><br>
  <code>nano /root/xxx.flag</code><br>
  Paste copied flags. 

- <b>Defense performed by Team2:</b>

    - Connect to the machine and execute web docker's bash:<br>
    <code>ssh root@10.0.2.101<br>
    docker exec -it jandalo_web_1 /bin/bash<br>
    </code>

    - Change permissions of http://ip/admin folder. Add this code to **/usr/local/apache2/conf/httpd.conf**<br>
      ```
      <Directory "/usr/local/apache2/htdocs/admin"><br>
        Require ip 10.255.254.0/24<br>
        Require all denied<br>
      </Directory>
      ```
    *We allow network 10.255.254.0/24 to let the checker if there is a user:password in that folders txt*
    Now if the attacker tries to get to /admin page: will get forbidden error, but still can see the general page.
    
    - Restart apache2 service and exit web docker's bash<br>
    <code>httpd -k restart<br>exit</code>

    - Execute mysql docker's bash and change username and/or password of the user in the database. Then exit:<br>
    <code>
    docker exec -it jandalo_mysql_1 /bin/bash<br>
    mysql -u root -prootpassword<br>
    ALTER USER 'dev1'@'%' IDENTIFIED BY 'pasahitz_berria';<br>
    FLUSH PRIVILEGES;<br>
    exit<br>
    exit<br>
    </code>
    At this point, there is a FAULTY service (depending on Tick duration), because the user:pass in the web users.txt file is not a valir user in the database, so we have to change it in the web docker, updating the new password.

    - Connect one more time to web docker's bash and update /admin/users.txt file with the new password:<br>
    <code>
    docker exec -it jandalo_web_1 /bin/bash<br>
    echo "dev1:pasahitz_berria" > /usr/local/apache2/htdocs/admin/users.txt<br>
    exit
    </code>
    At this point the service status is correct (up).

# Checker checks:
- Ports to reach dockers are open (WEB:9798; MYSQL:8833)
- users.txt file exists in \<web>/admin folder. 
- the *user:password* of users.txt has access to mysql database
- the flags are present on the database ctf_db.flag 

Checks done: 
- TEAM 1. Stop the container: 'root@team0-services:~# docker stop jandalo_web_1' It works OK, service's status becomes DOWN. 
- TEAM 1. Stop the container: 'root@team0-services:~# docker stop jandalo_mysql_1' It works OK, service's status becomes DOWN.
- TEAM 2. Change users.txt password but not on database. Service's status becomes faulty. 
- TEAM 2. Changes the password of the database, but not on users.txt. Service's status becomes faulty. 
# License notes
Parts from:
https://github.com/kristianvld/SQL-Injection-Playground

# requirements (services-playbook):
- mysql-connector-python
- curl



