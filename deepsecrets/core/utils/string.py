class StringUtils:

    @staticmethod
    def camel_case_divide(string: str) -> str:
        final = ''
        for i, _ in enumerate(string):
            final += string[i].lower()
            if i == len(string) - 1:
                continue

            if string[i].islower() and string[i+1].isupper():
                final += ' '
        return final