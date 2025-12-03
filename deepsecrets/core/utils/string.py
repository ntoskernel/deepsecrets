class StringUtils:

    @staticmethod
    def camel_case_divide(string: str) -> str:
        final = ''
        word_start_index = 0

        for i, char in enumerate(string):
            final += char.lower()

            if i == len(string) - 1:
                break

            if string[i].islower() and string[i + 1].isupper():

                current_word_len = (i - word_start_index) + 1
                if current_word_len < 2:
                    continue

                remaining_len = len(string) - (i + 1)
                if remaining_len < 2:
                    continue

                final += ' '
                word_start_index = i + 1

        return final
