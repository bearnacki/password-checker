import requests
import hashlib
import sys


class PasswordChecker:
    API_URL = 'https://api.pwnedpasswords.com/range/'

    def __init__(self, password: str):
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        self.hash_first_five_chars = sha1_password[:5]
        self.hash_tail = sha1_password[5:]

    def __api_request(self) -> requests.models.Response:
        url = self.API_URL + self.hash_first_five_chars
        response = requests.get(url)
        if response.status_code != 200:
            raise RuntimeError(f'API response status: {response.status_code}. \
                Check your connection and try again')

        return response

    def __count_leaks_from_api_response(self) -> int:
        response = self.__api_request()
        hashes = (line.split(':') for line in response.text.splitlines())
        for hash, count in hashes:
            if self.hash_tail == hash:
                return count

        return 0

    def check(self) -> str:
        count = self.__count_leaks_from_api_response()
        if count:
            return f'Password was found {count} times. It doesn\'t look good.'

        return 'Password was not found!'


def main() -> None:
    if len(sys.argv) < 2:
        print('Call script with password to check.')
        return

    password = sys.argv[1]
    if not password:
        print('Provide correct password.')
        return

    print(PasswordChecker(password).check())


if __name__ == "__main__":
    main()
