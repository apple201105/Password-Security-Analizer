
import hashlib
import json
import requests
import re
import os
from typing import Dict, Tuple

class PasswordChecker:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.use_online = self.check_internet()
        self.offline_db = None

        if not self.use_online:
            print("Интернет недоступен, использую офлайн-базу...")
            self.load_offline_db()
        else:
            print("Интернет доступен, использую онлайн-базу Have I Been Pwned...")

    def check_internet(self):
        try:
            response = requests.get("https://api.pwnedpasswords.com/range/7C4A8", timeout=5)
            return response.status_code == 200
        except:
            return False

    def load_offline_db(self):
        if os.path.exists('offline_db.json'):
            with open('offline_db.json', 'r') as f:
                self.offline_db = json.load(f)
        else:
            print("Офлайн-база не найдена. Проверка будет работать только по общим правилам.")
            self.offline_db = {}

    def load_common_passwords(self):
        common_passwords = {
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'baseball', 'abc123', 'football', 'monkey',
            'letmein', 'shadow', 'master', '666666', 'qwertyuiop',
            '123321', 'mustang', '1234567890', 'michael', 'superman'
        }
        return common_passwords

    def calculate_password_strength(self, password: str) -> Dict:
        score = 0
        feedback = []

        if len(password) >= 12:
            score += 3
            feedback.append("✓ Длина пароля отличная (12+ символов)")
        elif len(password) >= 8:
            score += 2
            feedback.append("✓ Длина пароля хорошая (8+ символов)")
        else:
            feedback.append("✗ Слишком короткий пароль (рекомендуется 8+ символов)")

        if re.search(r'\d', password):
            score += 1
            feedback.append("✓ Содержит цифры")
        else:
            feedback.append("✗ Добавьте цифры для увеличения сложности")

        if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            score += 2
            feedback.append("✓ Использует смешанный регистр")
        elif re.search(r'[a-zA-Z]', password):
            score += 1
            feedback.append("✗ Добавьте буквы в разных регистрах")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 2
            feedback.append("✓ Содержит специальные символы")
        else:
            feedback.append("✗ Добавьте специальные символы (!@#$ и т.д.)")

        if password.lower() in self.common_passwords:
            score = 0
            feedback.append("✗ Пароль находится в списке самых слабых паролей!")

        if score >= 8:
            strength = "Отличный"
            color = "\033[92m"
        elif score >= 5:
            strength = "Хороший"
            color = "\033[93m"
        elif score >= 3:
            strength = "Средний"
            color = "\033[33m"
        else:
            strength = "Слабый"
            color = "\033[91m"

        return {
            'score': score,
            'max_score': 10,
            'strength': strength,
            'color': color,
            'feedback': feedback,
            'length': len(password)
        }

    def check_offline(self, password: str) -> Tuple[bool, int]:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        if prefix in self.offline_db:
            for item in self.offline_db[prefix]:
                if item[0] == suffix:
                    return True, item[1]
        return False, 0

    def check_online(self, password: str) -> Tuple[bool, int]:
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return True, int(count)
                return False, 0
            else:
                return False, -1
        except:
            return False, -1

    def check_password_security(self, password: str) -> Tuple[bool, int]:
        if self.use_online:
            is_pwned, count = self.check_online(password)
            if count == -1:
                print("\nОнлайн-проверка не удалась, пробую офлайн...")
                if self.offline_db is None:
                    self.load_offline_db()
                is_pwned, count = self.check_offline(password)
        else:
            is_pwned, count = self.check_offline(password)

        return is_pwned, count

    def generate_recommendations(self, analysis: Dict, is_pwned: bool, pwned_count: int) -> list:
        recommendations = []

        if is_pwned and pwned_count > 0:
            recommendations.append(f"🚨 СРОЧНО: Этот пароль найден в {pwned_count} утечках! Немедленно измените его везде, где он используется.")

        if analysis['length'] < 8:
            recommendations.append(f"Увеличьте длину пароля минимум до 12 символов. Сейчас: {analysis['length']}")

        if analysis['score'] < 5:
            recommendations.append("Используйте комбинацию: заглавные + строчные буквы + цифры + специальные символы")

        recommendations.append("Не используйте один пароль на разных сайтах")
        recommendations.append("Рассмотрите использование менеджера паролей (Bitwarden, KeePass)")

        return recommendations

    def check_password(self, password: str):
        print("\n" + "="*50)
        print("АНАЛИЗ БЕЗОПАСНОСТИ ПАРОЛЯ")
        print("="*50)

        analysis = self.calculate_password_strength(password)

        print("\n[1/2] Проверка сложности пароля...")
        print(f"{analysis['color']}Оценка: {analysis['score']}/{analysis['max_score']} ({analysis['strength']})\033[0m")

        for item in analysis['feedback']:
            print(f"  {item}")

        print("\n[2/2] Проверка по базам утечек...")
        is_pwned, pwned_count = self.check_password_security(password)

        if is_pwned:
            print(f"\033[91m✗ Обнаружено в утечках: {pwned_count} раз(а)\033[0m")
        elif pwned_count == -1:
            print("\033[93m⚠ Проверка через API недоступна\033[0m")
        else:
            print("\033[92m✓ Не найден в известных утечках\033[0m")

        print("\n" + "="*50)
        print("РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ:")
        print("="*50)

        recommendations = self.generate_recommendations(analysis, is_pwned, pwned_count)
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")

        print("\n" + "="*50)
        print("ОБРАЗЕЦ БЕЗОПАСНОГО ПАРОЛЯ:")
        print("="*50)
        print("• Используйте фразу: 'Кот!Любит2Спать#На$Диване'")
        print("• Или случайный набор: 'g7#Xq!29$Lp@4Rn'")
        print("\nПримечание: не используйте эти примеры как реальные пароли!")

def get_password_input():
    print("\n" + "="*60)
    print("ВАРИАНТЫ ВВОДА ПАРОЛЯ:")
    print("1. Ввести пароль вручную")
    print("2. Использовать тестовый пароль")
    print("3. Выйти из программы")
    print("="*60)

    choice = input("\nВыберите вариант (1/2/3): ").strip()

    if choice == "1":
        password = input("Введите пароль для проверки: ").strip()
        return password
    elif choice == "2":
        test_passwords = [
            "123456",
            "password",
            "Password123",
            "My$tr0ngP@ss!",
            "qwertyuiop",
            "abc123",
            "superman"
        ]

        print("\nТестовые пароли:")
        for i, pwd in enumerate(test_passwords, 1):
            print(f"{i}. {pwd}")

        try:
            choice = int(input("\nВыберите номер тестового пароля (1-7): ")) - 1
            if 0 <= choice < len(test_passwords):
                return test_passwords[choice]
            else:
                print("Неверный номер, используется пароль по умолчанию.")
                return "123456"
        except ValueError:
            print("Неверный ввод, используется пароль по умолчанию.")
            return "123456"
    elif choice == "3":
        return "exit"
    else:
        print("Неверный выбор, попробуйте снова.")
        return get_password_input()

def main():
    print("="*60)
    print("ПРОВЕРКА БЕЗОПАСНОСТИ ПАРОЛЕЙ")
    print("(инструмент для обучения основам кибербезопасности)")
    print("="*60)
    print("\nВАЖНО:")
    print("1. Программа не сохраняет проверяемые пароли")
    print("2. Для проверки используются только хеши паролей")
    print("3. Не проверяйте чужие пароли без разрешения")
    print("="*60)

    checker = PasswordChecker()

    while True:
        try:
            password = get_password_input()

            if password == "exit":
                print("\nСпасибо за использование программы!")
                break

            if not password:
                print("Пароль не может быть пустым!")
                continue

            checker.check_password(password)

            print("\n" + "="*60)
            print("ЭТИЧЕСКОЕ ИСПОЛЬЗОВАНИЕ:")
            print("="*60)
            print("Этот инструмент предназначен только для:")
            print("• Проверки СВОИХ паролей")
            print("• Обучения основам безопасности")
            print("• Демонстрации на уроках информатики")
            print("\nНе используйте для проверки паролей других людей!")

            cont = input("\nПроверить ещё один пароль? (да/нет): ").lower()
            if cont not in ['да', 'д', 'yes', 'y']:
                print("\nСпасибо за использование программы!")
                break

        except KeyboardInterrupt:
            print("\n\nПрограмма завершена.")
            break
        except Exception as e:
            print(f"\nПроизошла ошибка: {e}")
            print("Попробуйте ещё раз.")

if __name__ == "__main__":
    main()