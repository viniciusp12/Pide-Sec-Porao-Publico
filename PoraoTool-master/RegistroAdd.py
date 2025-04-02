import winreg as reg
import ctypes
import sys
import os


def is_admin() -> bool:
    """Verifica se o script está sendo executado como administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def AdicionarRegistro(script: str = os.path.realpath(__file__), key=reg.HKEY_LOCAL_MACHINE,
                      name: str = "MyApp") -> bool:
    """
    Adiciona uma entrada ao Registro do Windows para inicialização automática.

    Args:
        script (str): Caminho do script ou executável a ser adicionado.
        key: Chave do registro (padrão: HKEY_LOCAL_MACHINE).
        name (str): Nome da entrada no registro.

    Returns:
        bool: True se a entrada foi adicionada com sucesso, False caso contrário.
    """
    if not script or not os.path.exists(script):
        print(f"Erro: O caminho do script '{script}' é inválido ou não existe.")
        return False

    if not name.strip():
        print("Erro: O nome do registro não pode estar vazio.")
        return False

    if is_admin():
        path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            reg_key = reg.OpenKey(key, path, 0, reg.KEY_ALL_ACCESS)
            reg.SetValueEx(reg_key, name, 0, reg.REG_SZ, script)
            reg.CloseKey(reg_key)
            print(f"Registro '{name}' adicionado com sucesso em '{path}'.")
            return True
        except PermissionError:
            print("Erro: Permissão negada. Execute como administrador.")
            return False
        except Exception as e:
            print(f"Erro ao adicionar registro: {e}")
            return False
    else:
        # Solicita elevação de privilégios
        print("Solicitando privilégios administrativos...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}"', None, 1)
        return False  # Retorna False pois a execução original não completou


if __name__ == "__main__":
    # Exemplo de uso com o caminho do script atual e um nome específico
    script_path = os.path.realpath(__file__)
    AdicionarRegistro(script=script_path, name="PoraoRansomwareDetect")


# Integração com o projeto principal (exemplo)
def integrar_com_projeto():
    """Exemplo de como chamar AdicionarRegistro no contexto do projeto."""
    project_script = r"C:\Users\vpo10\OneDrive\Área de Trabalho\PoraoTool-master\seu_script.py"
    if AdicionarRegistro(script=project_script, name="PoraoRansomwareDetect"):
        print("Inicialização automática configurada com sucesso!")
    else:
        print("Falha ao configurar inicialização automática.")