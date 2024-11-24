import psutil

def check_malicious(process_name):
    """
    Verifica se o nome do processo pode ser suspeito.
    """
    # Lista básica de nomes de processos suspeitos conhecidos
    suspicious_keywords = ["keylogger", "miner", "rat", "malware", "trojan", "hacktool"]
    # Verifica se o nome contém palavras suspeitas
    for keyword in suspicious_keywords:
        if keyword.lower() in process_name.lower():
            return True
    return False

def scan_processes():
    """
    Analisa todos os processos em execução no computador.
    """
    print(f"{'PID':<8} {'Process Name':<25} {'Status':<15} {'Malicious':<10}")
    print("-" * 60)

    for proc in psutil.process_iter(['pid', 'name', 'status']):
        try:
            process_name = proc.info['name']
            pid = proc.info['pid']
            status = proc.info['status']

            # Verifica se o processo pode ser malicioso
            is_malicious = check_malicious(process_name)

            print(f"{pid:<8} {process_name:<25} {status:<15} {'Yes' if is_malicious else 'No':<10}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Ignora processos inacessíveis
            continue

if __name__ == "__main__":
    print("Scanning running processes for potential threats...\n")
    scan_processes()
