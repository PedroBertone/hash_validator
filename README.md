# hash_validator
Hash validator for Python

import hashlib

def gerar_hash(texto, algoritmo):
    texto_bytes = texto.encode('utf-8')
    
    if algoritmo == 'md5':
        return hashlib.md5(texto_bytes).hexdigest()
    elif algoritmo == 'sha1':
        return hashlib.sha1(texto_bytes).hexdigest()
    elif algoritmo == 'sha256':
        return hashlib.sha256(texto_bytes).hexdigest()
    else:
        return None

def main():
    print("=== Validador de Hashes ===")
    texto_original = input("Digite o texto original: ")
    hash_fornecido = input("Digite o hash para comparação: ")
    algoritmo = input("Algoritmo (md5 / sha1 / sha256): ").lower()

    hash_gerado = gerar_hash(texto_original, algoritmo)

    if not hash_gerado:
        print("Algoritmo inválido!")
        return

    print(f"\nHash gerado ({algoritmo}): {hash_gerado}")
    if hash_gerado == hash_fornecido:
        print("[✅] Hashes coincidem!")
    else:
        print("[❌] Hashes NÃO coincidem.")

if __name__ == "__main__":
    main()


#exemplo de uso
(JAVA)

Digite o texto original: admin
Digite o hash para comparação: 21232f297a57a5a743894a0e4a801fc3
Algoritmo (md5 / sha1 / sha256): md5

Hash gerado (md5): 21232f297a57a5a743894a0e4a801fc3
[✅] Hashes coincidem!
