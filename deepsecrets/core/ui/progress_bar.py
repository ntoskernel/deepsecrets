from datetime import datetime
from typing import Iterable

from rich.console import RenderableType
from rich.progress import Progress

from deepsecrets.core.ui.floating_header import FloatingHeaderWidget


class DSApplicationProgess(Progress):
    def __init__(self, *args, **kwargs):
        self.header = FloatingHeaderWidget(
            start_time=kwargs.get('startup_time', datetime.now()),
            text='Running analysis',
        )
        try:
            kwargs.pop('startup_time')
        except Exception:
            pass

        super().__init__(*args, **kwargs)

    def set_start_time(self, start_time: datetime):
        self.header.start_time = start_time

    def get_renderables(self) -> Iterable[RenderableType]:
        progress_table = self.make_tasks_table(self.tasks)

        yield self.header
        yield progress_table
