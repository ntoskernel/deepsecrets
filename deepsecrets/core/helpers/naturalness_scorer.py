import collections
import json
import math
import zlib

from deepsecrets.core.utils.fs import get_path_inside_package


class NaturalnessScorer:

    def __init__(self, expected_elements=370000, false_positive_rate=0.01):
        # Parameters for bloom filter
        self.num_words = expected_elements
        self.fp_rate = false_positive_rate
        self.bit_size = int(-(self.num_words * math.log(self.fp_rate)) / (math.log(2) ** 2))
        self.num_hashes = int((self.bit_size / self.num_words) * math.log(2))
        self.bit_array = [0] * self.bit_size

        # Trigrams frequency dictionary
        self.trigram_counts = collections.Counter()
        self.total_trigrams = 0
        self.max_word_len = 0

        self.min_log_prob = -15.0

    def _get_hashes(self, item):
        hashes = []
        for i in range(self.num_hashes):
            salted = f"{item}{i}".encode("utf-8")
            hashes.append(zlib.crc32(salted) % self.bit_size)
        return hashes

    def _in_dictionary(self, word):
        if len(word) < 2:
            return False
        for position in self._get_hashes(word):
            if self.bit_array[position] == 0:
                return False
        return True

    @classmethod
    def load_from_json(cls, filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            model_data = json.load(f)

        instance = cls(
            expected_elements=model_data["num_words"],
            false_positive_rate=model_data["fp_rate"],
        )

        instance.bit_size = model_data["bit_size"]
        instance.num_hashes = model_data["num_hashes"]
        instance.max_word_len = model_data["max_word_len"]
        instance.total_trigrams = model_data["total_trigrams"]
        instance.trigram_counts = collections.Counter(model_data["trigram_counts"])

        byte_data = bytes.fromhex(model_data["bit_array_hex"])
        bit_array = []
        for byte in byte_data:
            for i in range(7, -1, -1):
                bit = (byte >> i) & 1
                bit_array.append(bit)

        instance.bit_array = bit_array
        return instance

    def _get_trigram_score(self, substring):
        if not substring:
            return 1.0

        padded = f"^{substring}$"
        total_score = 0.0
        count = 0

        for i in range(len(padded) - 2):
            trigram = padded[i : i + 3]
            trig_count = self.trigram_counts.get(trigram, 0)

            if trig_count > 0:
                prob = trig_count / self.total_trigrams
                log_prob = math.log(prob)
            else:
                log_prob = self.min_log_prob

            total_score += log_prob
            count += 1

        if count == 0:
            return 0.0

        avg_log_prob = total_score / count
        normalized = (avg_log_prob - self.min_log_prob) / (-3.0 - self.min_log_prob)
        return max(0.0, min(1.0, normalized))

    def calculate_score(self, string):
        string = string.lower().strip()
        if not string.isalpha() or len(string) == 0:
            return 0.0

        n = len(string)

        dp = [(0, [])] * (n + 1)

        for i in range(n):
            max_j = min(n, i + self.max_word_len)
            for j in range(i + 2, max_j + 1):
                substring = string[i:j]

                if self._in_dictionary(substring):
                    word_len = len(substring)
                    current_coverage = dp[i][0] + word_len
                    if current_coverage > dp[j][0]:
                        dp[j] = (current_coverage, dp[i][1] + [(i, j)])

            if dp[i][0] > dp[i + 1][0]:
                dp[i + 1] = (dp[i][0], dp[i][1])

        max_covered_chars, word_intervals = dp[n]
        dict_score = max_covered_chars / n

        last_idx = 0
        leftover_trigram_scores = []

        for start, end in word_intervals:
            if start > last_idx:
                garbage_chunk = string[last_idx:start]
                leftover_trigram_scores.append(self._get_trigram_score(garbage_chunk))
            last_idx = end

        if last_idx < n:
            garbage_chunk = string[last_idx:n]
            leftover_trigram_scores.append(self._get_trigram_score(garbage_chunk))

        if leftover_trigram_scores:
            garbage_score = sum(leftover_trigram_scores) / len(leftover_trigram_scores)
        else:
            garbage_score = 1.0
        final_score = (dict_score * 0.8) + (garbage_score * 0.2)

        return round(final_score, 4)


naturalness_scorer = NaturalnessScorer.load_from_json(get_path_inside_package('rules/value_scoring_model.json'))
