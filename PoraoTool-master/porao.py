import os
import pathlib
import time
import subprocess
import re
import psutil
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from comportamento import avaliar
from detector import DetectorMalware
import RegistroAdd as registry
import tkinter as tk
from tkinter import messagebox
from destravar import destravar

# Variáveis globais
data_list = []
users_list = []
username = os.getlogin()
change_type = [0, 0, 0, 0, 0]  # [criados, modificados, movidos, deletados, editados]
ult_processos = []
time_since_last_change = 100
last_shadow_backup = 0

# Caminho do backup fora da pasta Downloads
backup_root = f"C:\\Users\\{username}\\ProtectedBackup"
os.makedirs(backup_root, exist_ok=True)


def log_event(message: str):
    """Registra eventos em um arquivo de log."""
    with open("antivirus_log.txt", "a") as log:
        log.write(f"{time.ctime()}: {message}\n")


def alert_ransomware():
    """Exibe um alerta ao usuário."""
    root = tk.Tk()
    root.withdraw()
    messagebox.showwarning("Alerta", "Possível Ransomware detectado!")
    root.destroy()


def encerrar_proctree():
    """Encerra processos suspeitos."""
    global ult_processos
    log_event("Possível Ransomware detectado!")
    alert_ransomware()
    pids = " ".join(f"/PID {pid}" for pid in reversed(ult_processos) if pid != os.getpid())
    if pids:
        subprocess.run(f"taskkill {pids} /F /T", shell=True)
        ult_processos.clear()


def extrair_extensao(file: str) -> bool:
    """Verifica extensões suspeitas."""
    return pathlib.Path(file).suffix.lower() in {".exe", ".dll"}


def start_protection():
    """Configura proteção inicial."""
    global users_list, username
    procname = psutil.Process(os.getpid()).name()
    try:
        subprocess.run(f'wmic process where name="{procname}" CALL setpriority "above normal"', shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Erro na configuração inicial: {e}. Execute como administrador.")

    get_users = subprocess.run("wmic useraccount get name", capture_output=True, shell=True)
    users = get_users.stdout.decode()
    users_list.extend(user.strip() for user in re.split(r"\W|Name|\r|\n", users) if user.strip())


def honeypot():
    """Cria arquivos honeypot."""
    for x in range(1, 100):
        with open(f".porao{x}.txt", "w") as file:
            file.write("arquivo feito para detectar o ransomware")


def securing_files(folder: str):
    """Nega acesso à pasta."""
    global users_list
    for user in users_list:
        subprocess.run(f'icacls "{folder}" /deny "{user}":R', shell=True)


def shadow_copy():
    """Cria shadow copy a cada 1h30."""
    global last_shadow_backup, username
    now = time.time()
    backup_path = backup_root
    if last_shadow_backup == 0 or (now - last_shadow_backup >= 5400):  # 1h30
        try:
            # Executa xcopy em silêncio e captura saída
            subprocess.run(f'xcopy "C:\\Users\\{username}\\Downloads\\*.*" "{backup_path}" /Y /E /Q', shell=True, check=True, capture_output=True, text=True)
            subprocess.run("wmic shadowcopy delete", shell=True, check=True, capture_output=True)
            subprocess.run("wmic shadowcopy call create Volume='C:\\'", shell=True, check=True, capture_output=True)
            last_shadow_backup = now
            securing_files(backup_path)
            log_event("Shadow copy criada com sucesso.")
        except subprocess.CalledProcessError as e:
            log_event(f"Erro ao criar shadow copy: {e}")


def restaurar_backup():
    """Restaura arquivos do backup."""
    global username
    backup_path = backup_root
    try:
        destravar(backup_path)
        subprocess.run(f'xcopy "{backup_path}" "C:\\Users\\{username}\\Downloads" /Y /E /Q', shell=True, check=True, capture_output=True, text=True)
        log_event("Arquivos restaurados do backup.")
    except subprocess.CalledProcessError as e:
        log_event(f"Erro ao restaurar backup: {e}")


def novos_processos():
    """Monitora processos recentes."""
    global ult_processos
    now = time.time()
    for process in psutil.process_iter(['pid', 'create_time']):
        if abs(process.info['create_time'] - now) < 61:
            if process.info['pid'] not in ult_processos:
                ult_processos.append(process.info['pid'])


class MonitorFolder(FileSystemEventHandler):
    def on_any_event(self, event):
        global data_list, change_type
        if avaliar(*change_type):
            encerrar_proctree()
            restaurar_backup()
        if "porao" in event.src_path:
            change_type[4] += 1
        data_list.append((time.time(), event.src_path, event_type))

    def on_created(self, event):
        global change_type
        change_type[0] += 1
        if any(x in event.src_path.lower() for x in ["decrypt", "restore", "recover"]):
            log_event("Arquivos de recuperação detectados.")
            encerrar_proctree()
            restaurar_backup()

    def on_deleted(self, event):
        global change_type
        change_type[3] += 1

    def on_modified(self, event):
        global change_type
        change_type[1] += 1
        if extrair_extensao(event.src_path):
            DetectorMalware(event.src_path)

    def on_moved(self, event):
        global change_type
        change_type[2] += 1


if __name__ == "__main__":
    script_path = os.path.realpath(__file__)
    registry.AdicionarRegistro(script=script_path, name="PoraoRansomwareDetect")
    start_protection()
    shadow_copy()  # Executa uma vez no início
    honeypot()
    src_path = f"C:\\Users\\{username}\\Downloads"
    event_handler = MonitorFolder()
    observer = Observer()
    observer.schedule(event_handler, path=src_path, recursive=True)
    observer.start()
    try:
        while True:
            if avaliar(*change_type):
                encerrar_proctree()
                restaurar_backup()
            novos_processos()
            if data_list:
                time_since_last_change = abs(int(data_list[-1][0] - time.time()))
                if time_since_last_change > 10 or sum(change_type) > 20:
                    data_list.clear()
                    change_type = [0, 0, 0, 0, 0]
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        log_event("Programa encerrado pelo usuário.")
    except Exception as e:
        log_event(f"Erro inesperado: {e}")
        observer.stop()
        observer.join()