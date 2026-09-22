"""Exercise renderer escape sequences independently of timing and the TUI."""

import unittest

from pty_emulator import Screen, Stream


class TerminalScreenTests(unittest.TestCase):
    def screen(self, rows):
        screen = Screen(12, len(rows))
        for index, row in enumerate(rows, 1):
            if row:
                screen.cursor_position(index, 1)
                screen.draw(row)
        return screen, Stream(screen)

    def rows(self, screen):
        return [row.rstrip() for row in screen.display]

    def test_delete_lines_clears_destination_when_source_row_is_absent(self):
        screen, stream = self.screen(["first", "", "third", "", "", ""])
        # Do not inspect display first: pyte materializes blank rows on read.
        stream.feed("\x1b[1;1H\x1b[M")
        self.assertEqual(self.rows(screen), ["", "third", "", "", "", ""])

    def test_delete_lines_respects_cursor_and_margins(self):
        screen, stream = self.screen(["A", "B", "C", "D", "E", "F"])
        stream.feed("\x1b[2;5r\x1b[3;4H\x1b[2M")
        self.assertEqual(self.rows(screen), ["A", "B", "E", "", "", "F"])

    def test_delete_lines_outside_margins_does_nothing(self):
        for row in (1, 6):
            with self.subTest(row=row):
                screen, stream = self.screen(["A", "B", "C", "D", "E", "F"])
                stream.feed(f"\x1b[2;5r\x1b[{row};4H\x1b[2M")
                self.assertEqual(self.rows(screen), ["A", "B", "C", "D", "E", "F"])
                self.assertEqual((screen.cursor.x, screen.cursor.y), (3, row - 1))

    def test_scroll_defaults_and_zero_preserve_cursor(self):
        for direction, expected in (
            ("S", ["B", "C", "D", "E", "F", ""]),
            ("T", ["", "A", "B", "C", "D", "E"]),
        ):
            for parameter in ("", "0"):
                with self.subTest(direction=direction, parameter=parameter):
                    screen, stream = self.screen(["A", "B", "C", "D", "E", "F"])
                    stream.feed(f"\x1b[4;3H\x1b[{parameter}{direction}")
                    self.assertEqual(self.rows(screen), expected)
                    self.assertEqual((screen.cursor.x, screen.cursor.y), (2, 3))

    def test_scroll_multiple_rows_with_margins_preserves_outside_cursor(self):
        for direction, expected in (
            ("S", ["A", "D", "E", "", "", "F"]),
            ("T", ["A", "", "", "B", "C", "F"]),
        ):
            with self.subTest(direction=direction):
                screen, stream = self.screen(["A", "B", "C", "D", "E", "F"])
                stream.feed(f"\x1b[2;5r\x1b[6;4H\x1b[2{direction}")
                self.assertEqual(self.rows(screen), expected)
                self.assertEqual((screen.cursor.x, screen.cursor.y), (3, 5))

    def test_scroll_count_clamps_to_region(self):
        for direction in ("S", "T"):
            with self.subTest(direction=direction):
                screen, stream = self.screen(["A", "B", "C", "D", "E", "F"])
                stream.feed(f"\x1b[2;5r\x1b[3;4H\x1b[999{direction}")
                self.assertEqual(self.rows(screen), ["A", "", "", "", "", "F"])
                self.assertEqual((screen.cursor.x, screen.cursor.y), (3, 2))

    def test_scroll_sparse_rows_clears_old_contents(self):
        for direction, expected in (
            ("S", ["", "C", "", "", "", ""]),
            ("T", ["", "A", "", "C", "", ""]),
        ):
            with self.subTest(direction=direction):
                screen, stream = self.screen(["A", "", "C", "", "", ""])
                stream.feed(f"\x1b[{direction}")
                self.assertEqual(self.rows(screen), expected)


if __name__ == "__main__":
    unittest.main()
