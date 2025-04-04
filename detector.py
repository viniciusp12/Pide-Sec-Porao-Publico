import requests
import hashlib
import os
from typing import Dict, Optional

class Hash:
    def __init__(self, last_file: str) -> None:
        self.malware = False
        self.last_file = last_file

    def gerar_hash(self) -> str:
        """Gera o hash SHA-256 do último arquivo."""
        sha256 = hashlib.sha256()
        try:
            with open(self.last_file, "rb") as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo não encontrado: {self.last_file}")
        except PermissionError:
            raise PermissionError(f"Permissão negada para acessar: {self.last_file}")


class ColetaDados(Hash):
    def __init__(self, last_file: str) -> None:
        super().__init__(last_file)
        self.url = "https://mb-api.abuse.ch/api/v1/"
        self.malware_info: Dict[str, str] = {}
        self.dataBase_Search()

    def dataBase_Search(self) -> None:
        """Consulta a API do MalwareBazaar para verificar se o hash é de um malware."""
        errors = ["illegal_hash", "hash_not_found"]
        hash_value = self.gerar_hash()
        data = {"query": "get_info", "hash": hash_value}

        try:
            response = requests.post(url=self.url, data=data, timeout=10)
            response.raise_for_status()  # Levanta exceção para erros HTTP
            result = response.json()

            if result.get("query_status") in errors:
                self.malware = False
            elif "data" in result and result["data"]:
                self.malware_info = {
                    "signature": result["data"][0].get("signature", "Desconhecido"),
                    "sha256": result["data"][0].get("sha256_hash", hash_value),
                    "locate": self.last_file
                }
                self.malware = True
            else:
                self.malware = False
        except requests.RequestException as e:
            print(f"Erro ao consultar a API: {e}")
            self.malware = False


class DetectorMalware(ColetaDados):
    def __init__(self, last_file: str) -> None:
        super().__init__(last_file)
        self.main()

    def main(self) -> None:
        """Exibe o resultado da detecção de malware."""
        if self.malware:
            print(
                f'\nFoi encontrado um Malware!\n{"-"*20}\n'
                f'Signature: {self.malware_info["signature"]}\n'
                f'SHA256: {self.malware_info["sha256"]}\n'
                f'Locate: {self.malware_info["locate"]}\n{"-"*20}'
            )
            # Descomente para remover o arquivo:
            # try:
            #     os.remove(self.last_file)
            #     print(f"Arquivo removido: {self.last_file}")
            # except OSError as e:
            #     print(f"Erro ao remover o arquivo: {e}")
        else:
            print("\nNão foi detectado nenhum Malware!\n")


# Exemplo de uso
if __name__ == "__main__":
    arquivo = "caminho/para/seu/arquivo.exe"  # Substitua pelo caminho real
    detector = DetectorMalware(arquivo)