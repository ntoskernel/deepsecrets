from typing import Dict, List

from deepsecrets.core.model.finding import Finding


class FindingMerger:
    all: List[Finding]

    def __init__(self, full_list: List[Finding]) -> None:
        self.all = full_list

    def merge(self, choose_final_rule=False) -> List[Finding]:
        interm_dict: Dict[int, Finding] = {}

        for elem in self.all:
            if choose_final_rule:
                elem.choose_final_rule()

            hash = elem.__hash__()
            if hash not in interm_dict:
                interm_dict[hash] = elem

            interm_dict[hash].merge(elem)

        return list(interm_dict.values())
