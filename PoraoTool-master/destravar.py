import re  # Changed from 'regex' to built-in 're'
import subprocess
import os

username = os.getlogin()  # Obter o nome de usuário
users_list = []
get_users = subprocess.run("wmic useraccount get name", capture_output=True, shell=True)  # Obtendo usuários da máquina
users = get_users.stdout.decode()
users = re.split(r"\W|Name|\r|\n", users)  # Added 'r' prefix for raw string to handle backslashes properly
for usr in list(users):  # Changed 'user' to 'usr' to avoid shadowing
    usr = usr.strip()
    if usr == '':
        pass
    else:
        users_list.append(usr)


def destravar(folder):  # Permite que usuários acessem a pasta segura
    global users_list
    for usr in users_list:  # Changed 'user' to 'usr' here too
        subprocess.run(f'icacls "{folder}" /grant "{usr}":R', shell=True)  # Dando permissão a todos os usuários para a pasta


destravar(f"C:\\Users\\{username}\\Downloads\\protected_backup")