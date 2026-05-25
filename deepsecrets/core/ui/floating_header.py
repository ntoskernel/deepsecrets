from datetime import datetime
import time
from rich.console import Group
from rich.rule import Rule


class FloatingHeaderWidget:
    start_time: datetime
    text: str

    def __init__(self, start_time: datetime, text: str):
        self.start_time = start_time
        self.text = text

    def __rich__(self) -> Group:
        elapsed = time.time() - self.start_time.timestamp()

        hours, rem = divmod(elapsed, 3600)
        minutes, seconds = divmod(rem, 60)

        return Group(
            Rule(self.text, characters='—'),
            Rule(f'[dim white]⏱️ {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}[/dim white]', characters=' '),
            "",
        )
