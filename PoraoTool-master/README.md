# Antivírus Porão - Challenger Pride Sec

## Introdução
### Descrição
O **"Antivírus Porão"** é um projeto acadêmico desenvolvido para identificar e mitigar danos causados por ransomware em sistemas Windows. Ele combina detecção comportamental via machine learning, verificação de hashes com a API MalwareBazaar e estratégias de prevenção e recuperação como honeypots e backups.

### Contexto
Ransomwares criptografam arquivos e exigem resgate, sendo uma ameaça crescente. Este antivírus visa detectar esses ataques em tempo real e minimizar seus impactos.

## Estrutura do Projeto
### Arquivos
- **comportamento.py**: Detecção comportamental com machine learning.
- **detector.py**: Verificação de malware via API MalwareBazaar.
- **porão.py**: Script principal que integra todas as funcionalidades.
- **destravar.py**: Restaura permissões de acesso ao backup.
- **RegistroAdd.py**: Configura inicialização automática no Registro do Windows.

### Dependências
Para executar, instale as seguintes bibliotecas:
```bash
pip install scikit-learn psutil requests watchdog
```
- **scikit-learn**: Modelo de árvore de decisão.
- **psutil**: Monitoramento de processos.
- **requests**: Requisições à API.
- **watchdog**: Monitoramento de arquivos.
- **tkinter**: Alertas visuais (incluso no Python padrão).

## Funcionalidades
### Identificação de Ransomware
#### Detecção Comportamental (**comportamento.py**):
- Usa árvore de decisão para classificar atividades como normais (0) ou suspeitas (1).
- Métricas: arquivos criados, modificados, movidos, deletados, editados.

#### Detecção por Hash (**detector.py**):
- Calcula hash SHA-256 e consulta MalwareBazaar.

### Mitigação de Danos
- **Encerramento de Processos**: Mata processos suspeitos.
- **Backups**: Cria shadow copies a cada 1h30.
- **Restauração**: Recupera arquivos do backup.

### Prevenção
- **Honeypots**: Arquivos `.poraoX.txt` como iscas.
- **Inicialização Automática**: Executa na inicialização do Windows.

### Monitoramento
- Monitora a pasta **Downloads** com watchdog.

## Análise Técnica
### Identificação
#### **comportamento.py**:
- **Pontos Fortes**: Simples e eficaz para padrões claros.
- **Pontos Fracos**: Conjunto de dados pequeno.

#### **detector.py**:
- **Pontos Fortes**: Base confiável.
- **Pontos Fracos**: Depende de internet.

#### **porão.py**:
- **Pontos Fortes**: Integração robusta.
- **Pontos Fracos**: Falsos positivos não tratados.

### Mitigação
#### **porão.py**:
- **Pontos Fortes**: Backups e honeypots eficazes.
- **Pontos Fracos**: Restauração manual, exige admin.

#### **destravar.py**:
- **Pontos Fracos**: Não integrado ao fluxo principal.

### Inicialização
#### **RegistroAdd.py**:
- **Pontos Fortes**: Execução contínua.
- **Pontos Fracos**: Sem opção de remoção.

## Instruções de Uso
### Pré-requisitos
- Windows 10/11.
- Python 3.8+ com tkinter.
- Privilégios administrativos.

### Instalação
Clone o repositório:
```bash
git clone https://github.com/seu_usuario/PoraoTool-master.git
cd PoraoTool-master
```

Crie e ative o ambiente virtual:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Instale as dependências:
```powershell
pip install scikit-learn psutil requests watchdog
```

### Execução
Execute como administrador:
```powershell
python porão.py
```

### Teste
Use um ransomware simulado:
```python
# ransomware_simulado.py
import os, time
username = os.getlogin()
path = f"C:\\Users\\{username}\\Downloads"
for filename in os.listdir(path):
    if not filename.endswith(".encrypted"):
        os.rename(f"{path}\\{filename}", f"{path}\\{filename}.encrypted")
        time.sleep(0.1)
```

Rode em outro terminal:
```powershell
python ransomware_simulado.py
```

### Resultados Esperados
- **Detecção**: Alertas via tkinter.
- **Mitigação**: Processos encerrados, arquivos restaurados.
- **Logs**: Registrados em `antivirus_log.txt`.

## Limitações e Melhorias
### Limitações
- Exige prívilegios administrativos.
- Dados de treinamento limitados.
- Dependência de internet para hashes.

### Melhorias Futuras
- Expandir dados de treinamento.
- Interface gráfica completa.
- Quarentena de arquivos suspeitos.

## Conclusão
O **"Antivírus Porão"** é uma solução eficaz para ransomware, integrando detecção avançada e mitigação prática. Ideal para estudo e expansão futura.

## Referências
- [scikit-learn](https://scikit-learn.org/)
- [MalwareBazaar API](https://bazaar.abuse.ch/)
- [Python Docs](https://docs.python.org/)

