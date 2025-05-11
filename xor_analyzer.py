import sys
from collections import Counter

def xor_decrypt(data, key):
    """Декодирует данные с помощью XOR"""
    return bytes(b ^ key for b in data)

def analyze_file(filename, search_terms=None):
    """Анализирует файл на наличие XOR-строк"""
    if search_terms is None:
        search_terms = [b'login', b'password', b'error', b'admin']
    
    with open(filename, 'rb') as f:
        data = f.read()
    
    print(f"\nАнализ файла: {filename}")
    print(f"Размер файла: {len(data)} байт")
    
    # Шаг 1: Анализ частоты байтов
    byte_counts = Counter(data)
    common_bytes = byte_counts.most_common(10)
    print("\n10 самых частых байтов:")
    for byte, count in common_bytes:
        print(f"0x{byte:02x}: {count} раз")
    
    # Шаг 2: Поиск по всем ключам XOR
    print("\nПоиск по XOR-ключам (0x01-0xff):")
    for key in range(1, 256):
        decoded = xor_decrypt(data[:1000], key)  # Анализируем первые 1000 байт
        
        # Проверяем наличие известных строк
        matches = [term for term in search_terms if term in decoded]
        if matches:
            print(f"\nНайден ключ 0x{key:02x}:")
            for match in matches:
                print(f"- Обнаружена строка: {match.decode('ascii', errors='replace')}")
            
            # Показываем пример декодированных данных
            sample_start = decoded.find(matches[0])
            sample = decoded[max(0, sample_start-20):sample_start+20]
            print("Пример декодированных данных:")
            print(sample.decode('ascii', errors='replace'))
    
    # Шаг 3: Поиск возможных повторяющихся ключей
    print("\nАнализ возможных повторяющихся ключей...")
    for i in range(1, 32):
        possible_key = data[0] ^ ord('M')  # Предполагаем, что файл начинается с 'M'
        if 0x20 <= possible_key <= 0x7f:  # Проверяем, является ли ключ печатным символом
            print(f"Возможный ключ для позиции 0: 0x{possible_key:02x}")
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python xor_analyzer.py <файл> [термины для поиска]")
        sys.exit(1)
    
    filename = sys.argv[1]
    search_terms = [term.encode('ascii') for term in sys.argv[2:]] if len(sys.argv) > 2 else None
    analyze_file(filename, search_terms)
