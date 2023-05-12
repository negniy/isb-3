import argparse
import json
import logging
import os

from generation import generate_key_pair
from decryption import decrypt_data
from encryption import encrypt_data

SETTINGS_FILE = os.path.join('file', 'settings.json')


def get_argument():
    """ Функция, считывающа аргументы

    Args:
    None

    Returt value:
    args(Namespase) - считанные аргументы
    """
    parser = argparse.ArgumentParser()

    mode_group = parser.add_mutually_exclusive_group(required=True)

    mode_group.add_argument(
        '-gen', '--generation', action='store_true', help='Сгенерировать ключи')
    mode_group.add_argument('-enc', '--encryption', action='store_true',
                            help='Зашифровать данные')
    mode_group.add_argument('-dec', '--decryption', action='store_true',
                            help='Расшифровать данные')
    args = parser.parse_args()
    return args


def check_size(size: int):
    """Проверка размерности для ключа

    Args:
    size(int) - длина ключа

    Return value:
    size(int) - проверенная длина ключа
    true or false - идентификатор проверки
    """
    if size == 64 or size == 128 or size == 192:
        return int(size), True
    return 128, False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        with open(SETTINGS_FILE) as json_file:
            settings = json.load(json_file)
    except FileNotFoundError:
        logging.error(f"{SETTINGS_FILE} Ошибка считывания файла")
    size = int(settings["size"])
    size, correct = check_size(size)
    if not correct:
        logging.info(
            'Размер ключа введен некорректно -> установлен размер по умолчанию = 128')
    else:
        logging.info(f'Размер ключа: {size}')
    args = get_argument()
    mode = (args.generation, args.encryption, args.decryption)
    match mode:
        case (True, False, False):
            logging.info('Генерация ключей...\n')
            generate_key_pair(
                settings['secret_key'], settings['public_key'], settings['symmetric_key'], size)
            logging.info('Ключи сгенерированы')
        case (False, True, False):
            logging.info('Шифрование...\n')
            encrypt_data(settings['initial_file'], settings['secret_key'],
                         settings['symmetric_key'], settings['encrypted_file'], size)
            logging.info('Данные зашифрованы')
        case (False, False, True):
            logging.info('Расшифровка...\n')
            decrypt_data(settings['encrypted_file'], settings['secret_key'],
                         settings['symmetric_key'], settings['decrypted_file'], size)
            logging.info('Данные расшифрованы')
        case _:
            logging.error("Ошибка, нет такого режима")
