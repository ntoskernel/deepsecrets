from rich.progress import Progress, TimeRemainingColumn
from rich.text import Text


class SyncedTimeRemainingColumn(TimeRemainingColumn):

    progress_instance: Progress

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.progress_instance = None

    def _calculate_remaining(self, task):
        max_remaining = 0.0

        for sub_task in self.progress_instance.tasks:
            if sub_task.id != task.id and sub_task.time_remaining is not None:
                if sub_task.time_remaining > max_remaining:
                    max_remaining = sub_task.time_remaining

        internal_remaining = task.time_remaining

        if internal_remaining is not None and internal_remaining < max_remaining:
            target_time = max_remaining
        else:
            return super().render(task)

        if target_time > 0:
            mins, secs = divmod(int(target_time), 60)
            hours, mins = divmod(mins, 60)
            return Text(f"{hours}:{mins:02d}:{secs:02d}", style="progress.remaining")

        return Text("-:--:--", style="progress.remaining")

    def render(self, task) -> Text:
        if self.progress_instance is None or 'overall' not in task.description.lower():
            return super().render(task)

        return self._calculate_remaining(task)
