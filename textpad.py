"""
Simple textbox editing widget with Emacs-like keybindings.
But a custom and slightly altered version, which suits a particular need of more powerfull editing of a single line
(but seems to work on multiple lines windows as well)
"""

import curses
import curses.ascii

def rectangle(win, uly, ulx, lry, lrx):
    """Draw a rectangle with corners at the provided upper-left
    and lower-right coordinates.
    """
    win.vline(uly+1, ulx, curses.ACS_VLINE, lry - uly - 1)
    win.hline(uly, ulx+1, curses.ACS_HLINE, lrx - ulx - 1)
    win.hline(lry, ulx+1, curses.ACS_HLINE, lrx - ulx - 1)
    win.vline(uly+1, lrx, curses.ACS_VLINE, lry - uly - 1)
    win.addch(uly, ulx, curses.ACS_ULCORNER)
    win.addch(uly, lrx, curses.ACS_URCORNER)
    win.addch(lry, lrx, curses.ACS_LRCORNER)
    win.addch(lry, ulx, curses.ACS_LLCORNER)

class Textbox:
    """Editing widget using the interior of a window object.
     Supports the following Emacs-like key bindings:

    Ctrl-A      Go to left edge of window.
    Ctrl-B      Cursor left, wrapping to previous line if appropriate.
    Ctrl-E      Go to right edge (stripspaces off) or end of line (stripspaces on).
    Ctrl-F      Cursor right, wrapping to next line when appropriate.
    Ctrl-H      Delete character backward.
    Ctrl-J      Terminate if the window is 1 line, otherwise insert newline.
    Ctrl-K      If line is blank, delete it, otherwise clear to end of line.
    Ctrl-L      Refresh screen.
    Ctrl-N      Cursor down; move down one line.
    Ctrl-O      Insert a blank line at cursor location.
    Ctrl-P      Cursor up; move up one line.
    
    Those below, except D (its action was only rewritten for easier escaping from window) were added to make editing more flexible
    Ctrl-D      Done with the editing (bruh whos deleting using these punches). Essentially, pressing enter have the same effect
    Ctrl-R      "Reverse" changes, made to the window (in context of a certain application). Returns None to the caster instead of contents of a window.
    Ctrl-W      Remove word left from the cursor (for me literlay like in bash, but more aggressive)
    Ctrl-←      Moves one word to the left, almost like in bash, but if cursor in ~spaces~ moves to the end of the closest word
    Ctrl-→      The same as one above but to the right. It may be a little bit off the regular moving, but feels more natural (applies to both)

    Move operations do nothing if the cursor is at an edge where the movement
    is not possible.  The following synonyms are supported where possible:

    KEY_LEFT = Ctrl-B, KEY_RIGHT = Ctrl-F, KEY_UP = Ctrl-P, KEY_DOWN = Ctrl-N
    KEY_BACKSPACE = Ctrl-h
    """
    def __init__(self, win, insert_mode=False):
        self.win = win
        self.insert_mode = insert_mode
        self._update_max_yx()
        self.stripspaces = 1
        self.lastcmd = None
        win.keypad(1)

    def _update_max_yx(self):
        maxy, maxx = self.win.getmaxyx()
        self.maxy = maxy - 1
        self.maxx = maxx - 1

    def _end_of_line(self, y):
        """Go to the location of the first blank on the given line,
        returning the index of the last non-blank character."""
        self._update_max_yx()
        last = self.maxx
        while True:
            if curses.ascii.ascii(self.win.inch(y, last)) != curses.ascii.SP:
                last = min(self.maxx, last+1)
                break
            elif last == 0:
                break
            last = last - 1
        return last

    def _insert_printable_char(self, ch):
        self._update_max_yx()
        (y, x) = self.win.getyx()
        backyx = None
        while y < self.maxy or x < self.maxx:
            if self.insert_mode:
                oldch = self.win.inch()
            # The try-catch ignores the error we trigger from some curses
            # versions by trying to write into the lowest-rightmost spot
            # in the window.
            try:
                self.win.addch(ch)
            except curses.error:
                pass
            if not self.insert_mode or not curses.ascii.isprint(oldch):
                break
            ch = oldch
            (y, x) = self.win.getyx()
            # Remember where to put the cursor back since we are in insert_mode
            if backyx is None:
                backyx = y, x

        if backyx is not None:
            self.win.move(*backyx)

    def do_command(self, ch):
        "Process a single editing command."
        self._update_max_yx()
        (y, x) = self.win.getyx()
        self.lastcmd = ch
        if curses.ascii.isprint(ch):
            if y < self.maxy or x < self.maxx:
                self._insert_printable_char(ch)

        elif ch == curses.ascii.TAB or ch == '\t':
            ts = curses.get_tabsize()
            curs_offset = [i for i in range(x, x + ts) if i % ts == 0][0]
            if x % ts == 0:
                curs_offset = x + ts

            line = self.win.instr(0, 0)
            tabbed_line = line[:x] + b' ' * (curs_offset - x) + line[x:].strip()
            self.win.addstr(y, 0, tabbed_line)
            self.win.move(y, curs_offset)
        
        elif ch == 23:                                         # ^w
            regular_char_seen = False
            for i in range(1, 100):
                if x - i < 0:
                    break
                if self.win.instr(y, x - i, 1) == b' ' and regular_char_seen:
                    self.win.move(y, x - i + 1)
                    break
                if self.win.instr(y, x - i, 1) != b' ':
                    regular_char_seen = True
                self.win.delch(y, x - i)


        elif ch == 554:                                       # ^ ←
            line = self.win.instr(0, 0)
            if chr(line[x - 1]) == ' ':
                until_regular = True
            else:
                until_regular = False
            offset = 0
            for i in range(2, 100):
                offset = i - 1
                if (chr(line[x - i]) != ' ' and until_regular) or (chr(line[x - i]) == ' ' and not until_regular):
                    break
            if x - offset < 0:
                offset = x
            self.win.move(y, x - offset)

        elif ch == 569:                                       # ^ →
            line = self.win.instr(0, 0)
            if chr(line[x + 1]) == ' ':
                until_regular = True
            else:
                until_regular = False
            offset = 0
            for i in range(2, 100):
                offset = i
                if x + i > len(line.rstrip()):
                    break
                if (chr(line[x + i]) != ' ' and until_regular) or (chr(line[x + i]) == ' ' and not until_regular):
                    break
            self.win.move(y, x + offset)

        elif ch == 18:                                         # ^r
            return -1

        elif ch == '^W':
            return 0
        elif ch == curses.ascii.SOH:                           # ^a
            self.win.move(y, 0)
        elif ch in (curses.ascii.STX,curses.KEY_LEFT,
                    curses.ascii.BS,
                    curses.KEY_BACKSPACE,
                    curses.ascii.DEL):
            if x > 0:
                self.win.move(y, x-1)
            elif y == 0:
                pass
            elif self.stripspaces:
                self.win.move(y-1, self._end_of_line(y-1))
            
            else:
                self.win.move(y-1, self.maxx)
            if ch in (curses.ascii.BS, curses.KEY_BACKSPACE, curses.ascii.DEL):
                if self.win.instr(y, x - 1, 1) == b' ':
                    for i in range(1, curses.get_tabsize() + 1):
                        if self.win.instr(y, x - i, 1) != b' ':
                            self.win.move(y, x - i + 1)
                            break
                        self.win.delch(y, x - i)
                else:
                    self.win.delch()
        
        elif ch == curses.ascii.EOT:                           # ^d
            return 0
        elif ch == curses.ascii.ENQ:                           # ^e
            if self.stripspaces:
                self.win.move(y, self._end_of_line(y))
            else:
                self.win.move(y, self.maxx)
        elif ch in (curses.ascii.ACK, curses.KEY_RIGHT):       # ^f
            if x < self.maxx:
                self.win.move(y, x+1)
            elif y == self.maxy:
                pass
            else:
                self.win.move(y+1, 0)
        elif ch == curses.ascii.NL:                            # ^j
            if self.maxy == 0:
                return 0
            elif y < self.maxy:
                self.win.move(y+1, 0)
        elif ch == curses.ascii.VT:                            # ^k
            if x == 0 and self._end_of_line(y) == 0:
                self.win.deleteln()
            else:
                # first undo the effect of self._end_of_line
                self.win.move(y, x)
                self.win.clrtoeol()
        elif ch == curses.ascii.FF:                            # ^l
            self.win.refresh()
        elif ch in (curses.ascii.SO, curses.KEY_DOWN):         # ^n
            if y < self.maxy:
                self.win.move(y+1, x)
                if x > self._end_of_line(y+1):
                    self.win.move(y+1, self._end_of_line(y+1))
        elif ch == curses.ascii.SI:                            # ^o
            self.win.insertln()
        elif ch in (curses.ascii.DLE, curses.KEY_UP):          # ^p
            if y > 0:
                self.win.move(y-1, x)
                if x > self._end_of_line(y-1):
                    self.win.move(y-1, self._end_of_line(y-1))
        return 1

    def gather(self):
        "Collect and return the contents of the window."
        result = ""
        self._update_max_yx()
        for y in range(self.maxy+1):
            self.win.move(y, 0)
            stop = self._end_of_line(y)
            if stop == 0 and self.stripspaces:
                continue
            for x in range(self.maxx+1):
                if self.stripspaces and x > stop:
                    break
                result = result + chr(curses.ascii.ascii(self.win.inch(y, x)))
            if self.maxy > 0:
                result = result + "\n"
        return result

    def edit(self, validate=None):
        "Edit in the widget window and collect the results."
        while 1:
            ch = self.win.getch()
            if validate:
                ch = validate(ch)
            if not ch:
                continue
            do_results = self.do_command(ch)
            if do_results == -1:     # In case contents of the window do not need to be returned
                return
            if not do_results:
                break
            self.win.refresh()
        return self.gather()

if __name__ == '__main__':
    def test_editbox(stdscr):
        ncols, nlines = 50, 20
        uly, ulx = 15, 20
        stdscr.addstr(uly-2, ulx, "Use Ctrl-G to end editing.")
        win = curses.newwin(nlines, ncols, uly, ulx)
        rectangle(stdscr, uly-1, ulx-1, uly + nlines, ulx + ncols)
        stdscr.refresh()
        return Textbox(win, insert_mode=True).edit()

    str = curses.wrapper(test_editbox)
    print('Contents of text box:', repr(str))
