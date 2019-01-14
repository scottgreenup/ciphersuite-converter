#!/usr/bin/env python3

import argparse
import csv
import subprocess
import sys


class Converter:
    def __init__(self):
        self.__ianasuites = self.__get_iana()
        self.__opensslsuites = self.__get_openssl()

    def __get_iana(self):
        ciphersuites = {}

        # newline is \r\n as some descriptions have a newline, the real
        # delimiter is \r\n
        with open("./tls-parameters-4.csv", newline='\r\n') as csvfile:
            # skip the header
            next(csvfile)
            field_names = ['code', 'name', 'DTLS-OK', 'Recommended', 'Reference']
            reader = csv.DictReader(csvfile, fieldnames=field_names, delimiter=",")
            for i, row in enumerate(reader):
                ciphersuites[row['code']] = row['name']
        return ciphersuites

    def __get_openssl(self):
        try:
            command = ["openssl", "ciphers", "-V"]
            cp = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True)
        except subprocess.CalledProcessError as e:
            print("openssl returned {}".format(e.returncode))
            print("command: {}", " ".join(command))
            print("")
            print("output:\n{}".format(str(e.output)))

        output = cp.stdout.decode("utf8")

        ciphersuites = {}

        for line in output.split("\n"):
            if not line:
                continue
            parts = line.strip().split(' ')
            code = parts[0]
            name = parts[2]
            ciphersuites[code] = name

        return ciphersuites

    def validate_openssl(self, name):
        return name in self.__opensslsuites.values()

    def from_openssl(self, name):
        code = None
        for k, v in self.__opensslsuites.items():
            if v == name:
                code = k
                break

        if code == None:
            return None

        return self.__ianasuites.get(code, None)


def main(ciphersuites_string):

    converter = Converter()
    ciphersuites = ciphersuites_string.split(':')

    print("\nOpenSSL names:")

    unknown = []
    for name in ciphersuites:
        if converter.validate_openssl(name):
            print(name)
        else:
            unknown.append(name)

    if unknown:
        print("\nUnknown names")
        for name in unknown:
            print(name)

    print("\nIANA names:")

    unknown = []
    for name in ciphersuites:
        iana_name = converter.from_openssl(name)
        if iana_name:
            print(iana_name)
        else:
            unknown.append(iana_name)

    if unknown:
        print("\nCould not find IANA equivalent:")
        for name in unknown:
            print(name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="formatter")
    parser.add_argument("ciphersuites")
    args = parser.parse_args()
    main(args.ciphersuites)
