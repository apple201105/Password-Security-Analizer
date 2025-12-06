import hashlib
import json
import os

def generate_offline_db(password_file='top_passwords.txt', output_file='offline_db.json'):
    if not os.path.exists(password_file):
        print(f"Файл {password_file} не найден.")
        return

    offline_db = {}

    with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            password = line.strip()
            if password:
                sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
                prefix = sha1_hash[:5]
                suffix = sha1_hash[5:]

                # Количество утечек неизвестно, ставим 1
                count = 1

                if prefix not in offline_db:
                    offline_db[prefix] = []

                offline_db[prefix].append([suffix, count])

    with open(output_file, 'w') as f:
        json.dump(offline_db, f, indent=2)

    print(f"Офлайн база сохранена в {output_file}")

if __name__ == "__main__":
    generate_offline_db()