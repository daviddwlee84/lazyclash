"""Small pyte 0.8.2 compatibility fixes for Bubble Tea's terminal renderer.

The renderer can delete sparse rows and use CSI S/T while filtering a list.
Upstream pyte leaves stale rows in the former case and ignores the latter.
Keep those screen operations faithful so PTY assertions inspect the real view.
"""

import pyte


class Screen(pyte.Screen):
    def _scroll_lines(self, top, bottom, amount):
        rows = {y: self.buffer[y] for y in range(top, bottom + 1) if y in self.buffer}
        for y in range(top, bottom + 1):
            source = y + amount
            self.buffer.pop(y, None)
            if source in rows:
                self.buffer[y] = rows[source]
        self.dirty.update(range(top, bottom + 1))

    def delete_lines(self, count=None):
        top, bottom = self.margins or (0, self.lines - 1)
        if top <= self.cursor.y <= bottom:
            count = min(max(1, count or 1), bottom - self.cursor.y + 1)
            self._scroll_lines(self.cursor.y, bottom, count)
            # Retain pyte's existing DL cursor behavior.
            self.carriage_return()

    def scroll_up(self, count=None):
        top, bottom = self.margins or (0, self.lines - 1)
        count = min(max(1, count or 1), bottom - top + 1)
        self._scroll_lines(top, bottom, count)

    def scroll_down(self, count=None):
        top, bottom = self.margins or (0, self.lines - 1)
        count = min(max(1, count or 1), bottom - top + 1)
        self._scroll_lines(top, bottom, -count)


class Stream(pyte.Stream):
    csi = dict(pyte.Stream.csi, S="scroll_up", T="scroll_down")
    events = pyte.Stream.events | frozenset(("scroll_up", "scroll_down"))
