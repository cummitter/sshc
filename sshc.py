#!/usr/bin/python

import curses
import keyring
import os
import re
import signal
import socket
import subprocess
import threading
import traceback
import warnings
import sys
from copy import deepcopy
from getpass import getpass
from gnupg import GPG
from curses.textpad import Textbox
from time import sleep, time
from secrets import token_urlsafe


alt_pressed = focused = nodetails = tab_completion = False
nested = highlstr = topprof = topconn = pos = conn_count = 0
copied_details = sort = file_selection = unprompted_file = ''
tunnels = {}
undo_changes = {'outer': []}
redo_changes = {'outer': []}
buffer_changes = {'outer': []}
msgq = []
upload_to_history = []
upload_from_history = []
picked_cons = set()
pattern = re.compile(rf'^{sort}.*|.*\| *{sort}.*', re.I)
gpg = GPG()
stop_print = threading.Event()
lock = threading.Lock()
tabsize = curses.get_tabsize()

# os.forkpty() complains about multi-threaded enviroment, but as far as i've read, deadlocks might appear only
# if the forked process runs the same code as its parent, which is not the case here.
warnings.filterwarnings("ignore", category=DeprecationWarning)


def accept_input(message='', preinput='', start=None, voffset=0):
    global focused
    focused = True
    if start is None:
        conn = profiles[resolve('conn')]
        start = len(conn.expandtabs().rstrip()) + tabsize + len(message)
        if nodetails:
            start = len('\t'.join(conn.split('\t')[:3]).expandtabs().rstrip()) + tabsize + len(message)
    print_message(message, voffset=voffset)
    editwin = curses.newwin(1, curses.COLS - 2 - start, scr.getyx()[0] + voffset, start)
    editwin.addstr(preinput)
    curses.curs_set(2)
    scr.refresh()
    box = Textbox_enhanced(editwin, insert_mode=True)
    res = box.edit()
    curses.curs_set(0)
    redraw(breakout=False)
    focused = False
    return res

def autocomplete(path):
    def addslash(s):
        if os.path.isdir(path[:path.rfind('/') + 1] + s) and not s.endswith('/'):
            return s + '/'
        return s

    if not path:
        path = '/'
    file = path[path.rfind('/') + 1:]
    path = path[:path.rfind('/') + 1]
    if not os.access(path, os.R_OK):
        return path, ['can not access the directory']

    suggestions = [f for f in os.listdir(path) if re.match(rf'{re.escape(file)}.*', f) and not f.startswith('.')]
    if file.startswith('.'):
        suggestions = [f for f in os.listdir(path) if re.match(rf'{re.escape(file)}.*', f) and f.startswith('.')]
    if len(suggestions) > 1:
        for pos, char in enumerate(sorted(suggestions, key=len)[0], 0):
            if len(suggestions) == len([sug for sug in suggestions if sug[pos] == char]):
                path += char
                continue
            break
    elif len(suggestions) == 1:
        if not os.path.isdir(path + suggestions[0]):
            return path + suggestions[0], []
        path, suggestions = autocomplete(path + suggestions[0] + '/')
    else:
        if len(os.listdir(path)) == 0:
            return path, ['directory is empty']
        path, suggestions = autocomplete(path + file[:-1])

    return path, list(map(addslash, suggestions))

def autocomplete_loop(msg, path):
    global tab_completion
    tab_completion = True
    filename = path
    while True:
        path, suggestions = autocomplete(filename)
        print_message(suggestions, offset=tabsize + len(msg) + len(path[:path.rfind('/') + 1]), voffset=1)
        filename, return_by = accept_input(message=msg, preinput=path)
        if os.path.isfile(filename):
            if return_by == 'enter':
                return filename
            if return_by == 'tab':
                print_message('Nothing to complete', offset=tabsize + len(msg), voffset=1, cursesoptions=curses.A_DIM)
                continue


def conn_params(conn_num=None, prof_index=None, commands=False):
    if prof_index is None:
        prof_index = profiles.index([i for i in profiles if i[0] != '\t' and pattern.match(i)][topprof:][highlstr])
        conn_index = prof_index + pos
    if conn_num is not None:
        conn_index = prof_index + conn_num

    conn_str = profiles[conn_index].strip().split('\t')
    prof_str = profiles[prof_index].strip().split('\t')
    params = \
    {
        'prof_name': prof_str[0],
        'syntax': None,
        'address': conn_str[1],
        'port': cfg['port'],
        'user': cfg['user'],
        'key': None,
        'pass': None,
        'afterwards': cfg['afterwards']
    }

    prof_details = conn_details = ''
    if len(prof_str) > 1:
        prof_details = prof_str[1]
    if len(conn_str) > 2:
       conn_details = conn_str[2]

    for pstr in [prof_details, conn_details]:
        if '| ' in pstr:
            pstr, params['afterwards'] = map(str.strip, pstr.split('| '))
        if pstr.endswith('!'):
            params['afterwards'] = ''
            pstr = pstr[:-1]
        if pstr.startswith('!'):
            params['syntax'] = None
            pstr = pstr[1:]

        for templ in cfg['templ_list']:
            if pstr.startswith(templ + ' ') or pstr == templ:
                params['syntax'] = templ
        for param in ['port', 'pass', 'user']:
            if param + ' ' in pstr:
                params[param] = re.search(rf'{param} ([^ ]+)', pstr).group(1)
                pstr = re.sub(rf'{param} [^ ]+ ?', '', pstr)

        if re.match(r'^[^ ]+/[^ ]', pstr):
            params['user'], params['pass'] = re.search(r'^([^ ]+)/([^ ]+)', pstr).groups()
        
        if re.match('key [^ ]+/[^ ]', pstr):
            params['user'], params['key'] = re.search(r'key ([^ ]+)?/([^ ]+)', pstr).groups()
        
        elif re.match('^key [^ /]+', pstr):
            params['user'] = re.search(r'key (\w+)', pstr).group(1)
            params['key'] = cfg['key']

    if params['key']:
        params['key']= cfg['keys_path'] + params['key']
            

    if not commands:
        return params

    command = 'ssh {user}@{address} -p {port}' if params['syntax'] is None else cfg['templ_list'][params['syntax']]
    if params['key'] is not None:
        command += f' -i {params["key"]}'
    for param, value in params.items():
        command = command.replace('{'+param+'}', str(value))
    command = command.split(', ')

    if params['pass'] is not None:
        command.append(f"wf '' then '{params['pass']}'")
    for i in params['afterwards'].split(', '):
        if len(i) > 0:
            command.append(i.strip())
    return command


def create_connection(pane, conn_num, prof_index=None, name=''):
    line = 0
    for command in conn_params(conn_num, prof_index, commands=True):

        if command.startswith('wf'):
            sent = False
            try:
                timeout, waitfor, send = re.search(r"wf (\d+)? ?'(.*)' then '(.*)'", command).groups()
                if not waitfor:
                    waitfor = cfg['wf_default']
            except Exception:
                raise AssertionError("Could not parse 'wait for' expression, further execution terminated")

            if timeout is None:
                timeout = cfg['wf_timeout']
            start = time()
            while time() - start < timeout:
                content = tmux_exec(f'capture-pane -t {pane} -p -S {line} -E {line + cfg["wf_lines"] - 1}', output=cfg['wf_lines'])
                if content:
                    if sent: break
                    line += content.count('\n')
                    if waitfor in content:
                        tmux_exec(f"send-keys -t {pane} '{send}' Enter")
                        sent = True
                sleep(0.1)
            else:
                break       # If timeout occured, do not send the rest
        else:
            tmux_exec(f"send-keys -t {pane} '{command.rstrip('!')}' " + ('' if command.endswith('!') else 'Enter'))


def decrypt(file, passphrase=None):
    try:
        with open(file, 'rb') as f:
            res = str(gpg.decrypt_file(f, passphrase=key))
            if len(res) == 0:
                return None
            return [rec + '\n' for rec in res.split('\n')[:-1]]
    except OSError:
        exit(f'{file} file can not be opened')

def deinitialize_scr(noexit=False):
    scr.keypad(0)
    curses.echo()
    curses.nocbreak()
    curses.endwin()
    if noexit:
        return
    exit(0)

def handle_resize():
    global focused, max_displayed
    curses.update_lines_cols()
    max_displayed = int(cfg['max_conn_displayed']) if curses.LINES - 3 > int(cfg['max_conn_displayed']) else curses.LINES - 3
    if focused:
        focused = False
        msgq.append('Terminal window has been resized canceling the action that was accepting the input')
        curses.curs_set(0)
        redraw()

def hide_sensitive(params):
    params = re.sub(r"(wf \d* ?'.*?' then )'.*?'", r"\g<1>'******'", params)
    params = re.sub(r"(pass )[^ ]*", r"\g<1>******", params)
    params = re.sub(r'^!?([^ ]+/)[^ ]+', r"\g<1>******", params)
    return params

def macros(signal, frame):
    client = tmux_exec("list-client -f '#{==:#{client_control_mode},0}' -F '#{client_tty}'", output=1).strip()
    try:
        macros_file = open(f'{userdir}/macros')
    except FileNotFoundError:
        tmux_exec(f"display-message -c {client} -d 3000 'Could not find or open \"macros\" file'")
        return

    cmd = f'menu -T Macroses -c {client} -x R -y 0 '
    keys = [48]     # 48 - ASCII code for zero
    nestlevel = 0
    for line in macros_file.readlines():
        line = line.split('#  ')[0].strip()
        firstwords = ''.join(line.split(' ')[:3])   # hard coded limitation for considering a string as a part of macroses
        if '(' in firstwords:
            keys.append(48)
            if keys[nestlevel] == 58:
                keys[nestlevel] = 97    # Shift to the a-z part of ASCII after all digits were used

            name = line.replace('(', '')
            cmd += f'"{name}" {chr(keys[nestlevel])} {{menu -T {name} -x R -y 0 '
            keys[nestlevel] += 1
            nestlevel += 1

        if ')' in firstwords:
            keys[nestlevel] = 48
            nestlevel -= 1
            cmd += '}'

        if ':' in firstwords:
            if keys[nestlevel] == 58:
                keys[nestlevel] = 97

            termsignals = ''
            name = line[:line.find(':')]
            command = line[line.find(':')+1:].strip()
            if '---' in command:
                command, termsignals = command.split('---')
            command = command.replace(r'\n', '<to be rereplaced>').replace('\\', '\\\\').replace('<to be rereplaced>', r'\n')
            for char in '{}"$':
                command = command.replace(char, f'\\{char}')
            command = command.replace("'", r"\'\"\'\"\'")

            for multisignal in re.findall(r'[^ ]* x\d+', termsignals):
                signal, multiplier = re.search(r'(.*) x(\d+)', multisignal).groups()
                termsignals = termsignals.replace(multisignal, (signal + ' ') * int(multiplier))

            cmd += f'"{name}" {chr(keys[nestlevel])} "send-keys \\\'{command}\\\'{termsignals}" '
            keys[nestlevel] += 1

    macros_file.close()
    tmux_exec(cmd)


def monitor_process(proc):
    rc = proc.wait()
    stdout = proc.stdout.read().decode().strip()
    stderr = proc.stderr.read().decode().strip()
    cmd = ' '.join(proc.args)
    templ = []
    for name, commands in cfg['templ_list'].items():
        if cmd in commands:
            templ.append(name)
            cfg['templ_list'][name] = commands.replace(f'#{{{cmd}}}', stdout)
    templ = ' and '.join(templ)

    if rc != 0:
        msgq.append(f'Execution of "{cmd}" as part of "{templ}" template has returned a non-zero ({rc}) return code and the following came to the stderr:\n{stderr}\n'\
                + 'stdout was empty' if not stdout else 'but the stdout was not empty:\n{stdout}')
    elif not stdout:
        msgq.append(f'Execution of "{cmd}" as part of "{templ}" template was successful but nothing came to stdout')

# Function is called both for creating a menu in an active pane and as a handler for creating new pane and "populating" it with keys
# This is required by the fact, that some keys' sending has to be precieved by returned characters, which implementation
# better to be kept in a single file. $NEIGHBOR enviroment variable is used for comunicating the host to connect to
def neighbors(signal, frame):
    name = tmux_exec("display-message -p '#W'", output=1).strip()
    client = tmux_exec("list-client -f '#{==:#{client_control_mode},0}' -F '#{client_tty}'", output=1).strip()
    pid = os.getpid()
    try:
        index = [i for i, v in enumerate(profiles) if not v.startswith('\t') and name in v.split('\t')[0]][0]
    except IndexError:
        tmux_exec(f"display-message -c {client} -d 3000 'There is no profile with the \"{name}\" name'")
        return

    if signal == 10:     # SIGUSR1
        exclcount = 0
        tmcmd = f'menu -c {client} -x R -y 0 '
        for i, conn in enumerate(profiles[index + 1:], 48):
            i -= exclcount
            if not conn.startswith('\t'):
                break
            conn = conn.strip().split('\t')
            if i >= 58:
                i += 39     # Shift to the a-z part of ASCII
            if conn[0].startswith('#'):
                conn[0] = '#{}-' + conn[0]
                exclcount += 1
                if i != 48:
                    tmcmd += "'' '' '' "
            tmcmd += f'"{"\t".join(conn[:min(len(conn), 2)]).expandtabs()}" {chr(i)} {{set-environment neighbor {chr(i)}; run-shell "kill -s 29 {pid}"}} '
        tmux_exec(tmcmd)
        return 0

    if signal == 29:    # SIGPOLL
        conn_num = tmux_exec('show-environment neighbor', output=1).strip().split('=')[1]
        if conn_num.isdigit():
            conn_num = int(conn_num) + 1
        else:
            conn_num = ord(conn_num) - 87 + 1   # 87 shifts ASCII code for letters to the integers higher than 9
        for i, conn in enumerate(profiles[index +1:], 1):
            if not conn.startswith('\t'):
                break
            if conn.startswith('\t#') and conn_num >= i:
                conn_num += 1

        try:
            create_connection(tmux_exec('split-window -P -F " #{pane_id}"', output=1).strip(), conn_num, index)
            tmux_exec('set-environment -u neighbor')
        except Exception:
            tmux_exec(f'kill-pane\n \
                    display-message -c {client} -d 3000 "Could not parse chosen host configuration"')

def tmux_exec(cmd, output=0):
    lock.acquire()
    if cmd.startswith('capture'):
        os.set_blocking(tmux.stdout.name, False)
    ret = __tmux_exec(cmd, output)
    if not os.get_blocking(tmux.stdout.name):
        os.set_blocking(tmux.stdout.name, True)
    lock.release()
    return ret


def __tmux_exec(cmd, output):
    tmux.stdin.write(cmd + '\n')
    if output:
        sleep(0.01)
        while True:
            try:
                line = tmux.stdout.readline()
            except Exception:
                return ''
            if line.startswith('%begin'):
                line = tmux.stdout.readline()
                if not line.startswith('%'):
                    return (line if line != '\n' else '') + ''.join(filter(lambda x: x != '\n', [tmux.stdout.readline() for i in range(output - 1)]))

def normalexit(signal, frame):
    global profiles, key, focused, nodetails
    if focused:
        focused = False
        nodetails = False
        curses.curs_set(0)
        redraw()
    if profs_hash == hash(str(profiles)):
        deinitialize_scr()
    
    sort_profiles()
    if not os.path.isfile(mainfile):    # By default encrypt newly created files
        open(mainfile, 'a').close()
        key = token_urlsafe(64)
        keyring.set_password(mainfile + '_' + str(os.stat(mainfile).st_ino), os.getlogin(), key)

    elif 'plain' in filetype:
        if not cfg['never_ask_for_encryption']:
            deinitialize_scr(noexit=True)
            option = input("Would you like to encrypt the file? (y - generate passphrase and save it to local keyring, n - don't encrypt, m - manually specified passphrase): ").lower()

            if option == 'y':
                key = token_urlsafe(64)
                keyring.set_password(mainfile + '_' + str(os.stat(mainfile).st_ino), os.getlogin(), key)
                gpg.encrypt(''.join(profiles), recipients=None, symmetric=True, passphrase=key, output=mainfile)
                exit(0)

            elif option == 'm':
                key = getpass('Enter the passphrase: ')
                keyring.set_password(mainfile + '_' + str(os.stat(mainfile).st_ino), os.getlogin(), key)
                gpg.encrypt(''.join(profiles), recipients=None, symmetric=True, passphrase=key, output=mainfile)
                exit(0)

            elif option == 'n':
                pass

            else:
                print('Unrecognized option was entered, file will be saved in plain text')

        with open(mainfile, 'w') as f:
            for line in profiles:
                f.write(line)

    gpg.encrypt(''.join(profiles), recipients=None, symmetric=True, passphrase=key, output=mainfile)
    deinitialize_scr()


def parse_config():
    try:
        config_file = open(f'{userdir}/config')
    except OSError:
        msgq.append('Configuration file is missing or have insufficient priviligies to open, please refer to ~/.sshc/config.template')
        return

    lines = [l for l in config_file.readlines() if not l.startswith('#') and l != '\n']
    tmpcfg = {}
    for line in lines:
        if '=' in line:
            name, value = line.strip().split('=')
            if ' ' in name or (' ' in value and name != 'afterwards') or len(value) == 0:
                continue
            if name in cfg:
                tmpcfg[name] = value
            else:
                msgq.append(f'Unknown parameter - {name}')

    for key, value in tmpcfg.copy().items():
        # numerical parameters
        if key in ('never_ask_for_encryption', 'port', 'local_spacing', 'wf_timeout', 'select_multiplier', 'max_conn_displayed', 'src_tunnel_port', 'dst_tunnel_port') \
            and not value.isdigit():
                msgq.append(f'{key} was defined, but is not integer')
                tmpcfg.pop(key)

        # local paths
        if key in ('file_path', 'logfile', 'upload_from_dest', 'keys_path', 'import_path', 'from_scripts_path', 'to_scripts_path', 'upload_to_path', 'upload_from_dest'):
            if value[0] not in ('~', '/'):
                value = f'{userdir}/{value}'
            if key in ('file_path', 'logfile'):
                if not os.path.isfile(value):
                    msgq.append(f'{key} parameter was treated as {value} and there is no such file')
                    tmpcfg.pop(key)
                    continue
                if not os.access(value, os.R_OK):
                    msgq.append(f'{key} parameter points to an existing file ({value}), but it can not be read from')
                    tmpcfg.pop(key)
                    continue
                if not os.access(value, os.W_OK):
                    msgq.append(f'{key} parameter points to an existing file ({value}), but it can not be written to')
                    tmpcfg.pop(key)
                    continue
            else:
                if not os.path.isdir(value):
                    msgq.append(f'{key} parameter was treated as {value} and this directory does not exist')
                    tmpcfg.pop(key)
                    continue

    for key in tmpcfg:
        cfg[key] = tmpcfg[key]


    # Above was parsing and sanitization of generic parameters, below are two special ones


    if 'templ_list(\n' in lines:
        if ')\n' not in lines[lines.index('templ_list(\n'):]:
            msgq.append('templ_list has been attempted to be defined, but no closing bracket found')
        else:
            templs = lines[lines.index('templ_list(\n') + 1:lines.index(')\n')]
            for templ in map(str.strip, templs):
                name, commands = templ.split('=')
                cfg['templ_list'][name] = commands
            for extcmd in set(re.findall(r'#\{(.*?)\}', ''.join(cfg['templ_list'].values()))):
                proc = subprocess.Popen(extcmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                threading.Thread(target=monitor_process, args=[proc], daemon=True).start()

    if 'new_profile:\n' in lines:
        proflines = []
        start = lines.index('new_profile:\n')
        if not lines[start + 1].startswith('\t'):
            proflines.append(lines[start + 1])
            for line in lines[start + 2:]:
                if not line.startswith('\t'):
                    break
                proflines.append(line)

            lines = [l for l in lines if l not in proflines]
            cfg['new_profile'] = proflines
        else:
            msgq.append('new_profile template has been attempted to be defined, but the profile name starts with a tab')

    if len(cfg['new_profile']) < 2:
        msgq.append('new_profile directive was processed, but ended up in an unsitable state, the value was reverted to defaults')
        cfg['new_profile'] = ['New profile\n', '\tnew\t10.100.0.0\n']


def print_message(text, offset=tabsize, voffset=0, cursesoptions=0):
    conn = profiles[resolve('conn')]
    print_point = len(conn.expandtabs().rstrip()) + offset
    if nodetails:
        print_point = len('\t'.join(conn.split('\t')[:3]).expandtabs().rstrip()) + offset
    if isinstance(text, list):
        text = ' \n'.join(text)

    if len(text) + print_point > curses.COLS - 10 or '\n' in text:    # If message does not visually fits in single line, put it into a rectangled window
        lines = ['']
        linenum = 0
        for word in text.split(' '):
            if '\n' in word:
                words = word.split('\n')
                lines[linenum] += words[0]
                lines.append('')
                linenum += 1
                if len(words) > 1:
                    word = words[1]
            if len(word) + 1 + len(lines[linenum]) > 80:
                lines[linenum] = lines[linenum].rstrip()    # delete space from last word
                lines.append('')
                linenum += 1
            lines[linenum] += word + ' '

        text = '\n'.join(lines)
        msgwin = curses.newwin(text.count('\n') + 1, curses.COLS - 10, scr.getyx()[0] + voffset, print_point)
        msgwin.addstr(text)
        msgwin.refresh()
        return

    cursor_pos = scr.getyx()[0]
    scr.addstr(scr.getyx()[0] + voffset, print_point, text, cursesoptions)
    scr.move(cursor_pos, 0)  # addstr() also moves the cursor for some reason
    scr.refresh()


# The only function responsible for printing everything displayed on the screen, called only in redraw()
# It has been proved to be easier to redraw everything with each motion
def print_profiles(move):
    global profiles_count, conn_count
    profiles_count = len([i for i in profiles if i[0] != '\t' and pattern.match(i)][topprof:])

    pntr = 0
    for prof in [i for i in profiles if i[0] != '\t' and pattern.match(i)][topprof:]:
        if pntr + 3 == curses.LINES:
            return

        if pntr == highlstr:
            changes_hint = ''
            if not nodetails:
                undo_count = len(undo_changes.get(prof if nested else 'outer', []))
                redo_count = len(redo_changes.get(prof if nested else 'outer', []))
                changes_hint = (f'{undo_count} changes to undo' if undo_count else '') + \
                               (' and ' if undo_count and redo_count else '') + \
                               (f'{redo_count} {"changes " if not undo_count else ""}to redo' if redo_count else '')

            profname, conndetails = (prof + '\t').split('\t')[:2]
            conndetails = hide_sensitive(conndetails)
            scr.addstr(pntr, 0, profname.rstrip('\n'), curses.A_BOLD)
            scr.addstr(('\t' if conndetails else '') + conndetails.rstrip('\n'), curses.A_DIM + curses.A_ITALIC)
            if changes_hint:
                scr.addstr('\t[', curses.A_DIM)
                scr.addstr(changes_hint, curses.A_DIM + curses.A_UNDERLINE)
                scr.addstr(']\n', curses.A_DIM) 
            scr.addstr('\n')

            conn_list = []
            conns_to_draw = []
            for i in profiles[resolve('prof') + 1:]:
                if not i.startswith('\t'): break
                conn_list.append(i)
            conn_count = len(conn_list)

            for counter, i in enumerate(conn_list[topconn:]):
                if counter == max_displayed - 1:
                    break
                conns_to_draw.append('\t'.join(i.split('\t')[:3]) if nodetails else i)

            if topconn: conns_to_draw[0] = f'\t...\t{topconn + 1} hosts above'
            if max_displayed + topconn < conn_count: conns_to_draw[-1] = f'\t...\t{conn_count - max_displayed - topconn + 1} hosts below'

            for index, conn in enumerate(conns_to_draw, 1):
                if pntr == curses.LINES - 4:
                    return
                pntr += 1
                params = conn.split('\t')[-1]
                conn = conn.replace(params, hide_sensitive(params))
                if (conn.startswith('\t#') or conn.startswith('\t...')) and index != move - highlstr:
                    scr.addstr(pntr, 0, conn, curses.A_DIM + curses.A_ITALIC)
                    continue
                if index + topconn in picked_cons and not conn.startswith('\t...'):
                    if index == move - highlstr:
                        scr.addstr(pntr, 4, conn, curses.A_REVERSE)
                        continue
                    scr.addstr(pntr, 0, conn, curses.A_REVERSE)
                    continue
                if index == move - highlstr:
                    scr.addstr(pntr, 8, conn[1:], curses.A_REVERSE)
                    continue

                scr.addstr(pntr, 0, conn)

        else:
            scr.addstr(pntr, 0, prof.split('\t')[0])
        pntr += 1


# war crime happenning, i won't disagree, but apparently, ssh's keyboard interactive auth desparetly needs a tty to attach to (apparently, but obviously)
# and in the context of curses program, a child process attaches to a parent's tty, while i want password to be sent non-interactively
# just an os.write() to a processe's FD (because password is either already entered for the host or fetched from the template)
# That's the whole reason for writing this garbage that manually forks and further monitors the output to react with a password
def proc_handler(cmd, args, waitfor=None):
    pid, fd = os.forkpty()
    if pid == 0:
        os.execvp(cmd, args)
    elif pid > 0:
        threading.Thread(target=__proc_watcher, args=[fd, pid, waitfor, ('-L' in args)], daemon=True).start()

# The second part is only related to the tunnel's monitoring, as its just convinient to create a tunnel with a few keystrokes
# why not extend this functionality with an ability to both see the tunnel's status and kill/restart it if needed
def __proc_watcher(fd, pid, waitfor, tunnel):
    while not (tunnel and not waitfor):
        try:
            out = os.read(fd, 1024)
        except OSError:
            wrt(f'{pid} has *probably* finished its execution, as os.read() raised an exception on processe\'s FD')
            return
        wrt(f'[PID - {pid}] ' + out.decode())
        if b'word:' in out and waitfor is not None:
            os.write(fd, f'{waitfor}\n'.encode())
            waitfor = None
        sleep(0.1)

    tunid = max(tunnels.keys())
    sport = tunnels[tunid][0][:tunnels[tunid][0].index(':')]
    wrt('[' + tunnels[tunid][0] + ']' + ' -> ' + tunnels[tunid][2])
    prev = tunnels[tunid][2]
    alivecheck = 0
    while True:
        sleep(0.1)
        alivecheck += 1
        try:
            if tunnels[tunid][2].startswith('to be'):       # user request for tunnel to be either killed or restarted
                os.kill(pid, 9)
                for _ in range(5):
                    os.kill(pid, 0)
                    sleep(0.5)
                wrt(f'[PID - {pid}] is still alive for the past 10 seconds after sending SIGKILL')
            if alivecheck == 20:
                alivecheck = 0
                os.kill(pid, 0)
                sock = socket.socket()
                sock.settimeout(10)
                sock.connect(('127.0.0.1', int(sport)))
                tunnels[tunid][2] = 'connected'
                sock.close()

        except ConnectionError as exc:
            tunnels[tunid][2] = str(exc.args)

        except ProcessLookupError:

            if tunnels[tunid][2].startswith('to be'):
                wrt(f'[PID - {pid}] was killed by request')

                if tunnels[tunid][2] == 'to be restarted':
                    params = tunnels[tunid][1]
                    newtunid = max(tunnels.keys()) + 1
                    tunnels[newtunid] = tunnels[tunid]
                    tunnels[newtunid][2] = 'starting'
                    tailing_print()
                    wrt(f'\nRestarting a tunnel with the following command:\nssh {' '.join(params[0])}')
                    proc_handler('ssh', *params)
                tunnels.pop(tunid)

            else:
                tunnels[tunid][2] = 'exited'

        finally:
            #if not tunnels.get(tunid):
            #    break
            if tunnels[tunid][2] != prev:
                wrt('[' + tunnels[tunid][0] + ']' + ' -> ' + tunnels[tunid][2])
                prev = tunnels[tunid][2]
                if prev == 'exited':
                    tunnels.pop(tunid)
                    message = ''
                    while True:
                        try:
                            message += os.read(fd, 1024).decode()
                        except Exception:
                            break
                    wrt(f"The following output was captured:\n{message}")
             #       break


# An essential function, used both for rerendering the whole screen and handling all the movement in its vast complexity
# Over the time of development it has accumulated all of the general activities so the main loop cases can be looked on
# and understanded much more easily with as least repetead code (all edge cases are also handled here)
# All of the abstraction from which main loop gains simplicity is handled in this god forsaken place

def redraw(move=None, breakout=True, sort_profs=False):
    global pos, highlstr, topconn
    if move is not None:
        if nested:

            shown = range(2 if topconn else 1, max_displayed + (0 if topconn + max_displayed < conn_count else 1))
            if conn_count < max_displayed: shown = shown[:conn_count]

            if move not in range(1, conn_count + 1):    # if requested move out of range of all hosts under profile
                while move > conn_count:                # then try to loop around (both whiles also work like if statements)
                    move = pos = move - conn_count
                    topconn = 0
                while move < 1:
                    topconn = conn_count - len(shown) - (1 if conn_count > max_displayed else 0)
                    pos = conn_count + move
                    move += max(shown) + (1 if conn_count > max_displayed else 0)

            else:
                if move - topconn > max(shown):         # if requested move in the profile's range, but not on the screen
                    topconn += (move - topconn) - shown[-1]
                if move - topconn < min(shown):
                    topconn -= shown[0] - (move - topconn)
                    topconn = max(topconn, 0)
                pos = move
                move -= topconn
            move += highlstr

        else:
            highlstr = move
    else:
        move = pos + highlstr - topconn if nested else highlstr

    if sort_profs:
        sort_profiles()
    scr.erase()
    print_profiles(move)
    scr.addstr(curses.LINES - 2, 4, f'Sort by {sort}.*   Copied details: {copied_details}')
    scr.move(move, 0)
    scr.refresh()
    if breakout:
        raise AssertionError


def reset(n=True, h=True, c=True, t=True, r=0):
    global nested, highlstr, topconn, topprof, picked_cons, pattern
    nested = 0 if n else None
    highlstr = 0 if h else None
    topconn = 0 if c else None
    topprof = 0 if t else None
    picked_cons = set()
    pattern = re.compile(rf'^{sort}.*|.*\| *{sort}.*', re.I)
    redraw(r)

# resolve actual position in the profiles list from the relative position on the screen
def resolve(only_one=None):
    try:
        prof_index = profiles.index([i for i in profiles if i[0] != '\t' and pattern.match(i)][topprof:][highlstr])
    except Exception:
        return 0
    if only_one == 'prof':
        return prof_index
    if only_one == 'conn':
        return prof_index + pos
    return prof_index, prof_index + pos

def save_changes(action, location=None, value=None):
    prof_name = profiles[resolve('prof')]
    add = lambda change: undo_changes.get(prof_name, []) + [change]

    if isinstance(location, int):
        location = [location]
    if value is not None and isinstance(value, str):
        value = [value]
    
    if action == 'edit':
        if nested:
            undo_changes[prof_name] = add({'action': 'e', 'location': location, 'value': value})
        else:
            undo_changes['outer'].append({'action': 'e', 'name': prof_name, 'value': value})
            if undo_changes.get(value[0]):
                undo_changes[prof_name] = undo_changes.pop(value[0])

    if action == 'remove':
        if nested:
            undo_changes[prof_name] = add({'action': 'r', 'location': location})
        else:
            undo_changes['outer'].append({'action': 'r', 'name': prof_name})

    if action == 'insert':
        if nested:
            undo_changes[prof_name] = add({'action': 'i', 'location': location, 'value': value})
        else:
            undo_changes['outer'].append({'action': 'i', 'value': value})

def sort_profiles():
    global profiles
    sorted_prof = [prof for prof in profiles if prof[0] != '\t']
    sorted_prof.sort(key=str.lower)
    result = []
    for prof in sorted_prof:
        result.append(prof)
        for conn in profiles[profiles.index(prof) + 1:]:
            if conn[0] != '\t':
                break
            result.append(conn)
    profiles = result


def tailing_print(start_from_the_end=True):
    global nodetails
    if not nodetails:
        nodetails = True
        redraw(breakout=False)
    stop_print.clear()
    l = open(cfg['logfile'])
    if start_from_the_end:
        l.seek(0, 2)
    else:
        with open(cfg['logfile'], "rb") as f:
            linecount = sum(1 for _ in f)
        while linecount > curses.LINES - scr.getyx()[0]:
            l.readline()
            linecount -= 1
    threading.Thread(target=__continuous_print, args=[l], daemon=True).start()

def __continuous_print(fd):

    def tailf():
        while not stop_print.is_set():
            line = fd.readline()
            if not line or not line.endswith('\n'):
                sleep(0.01)
                continue
            yield line
        fd.close()
        return

    lucorner = len('\t'.join(profiles[resolve('conn')].split('\t')[:3]).expandtabs().rstrip()) + tabsize
    if not nested:
        lucorner += tabsize
    msgwin = curses.newwin(curses.LINES, curses.COLS - 10, scr.getyx()[0], lucorner)
    message = []
    for linenum, line in enumerate(tailf()):
        msgwin.erase()
        if linenum > curses.LINES - scr.getyx()[0] - 6:
            message.pop(0)
        message.append(line)
        msgwin.addstr(''.join(message))
        msgwin.refresh()

def main_thread_handler(exc_type, exc_value, exc_traceback):
    deinitialize_scr(noexit=True)
    print('Uncaught exception was raised, terminal should be returned to its original state')
    print(traceback.print_tb(exc_traceback), traceback.print_exception(exc_value))
    return


def thread_handler(args):
    func = args.thread.name

    reason = 'which tracing is not yet implemented'
    if 'create_connection' in func:
        reason = 'during the creation of the connection'
    if 'starter' in func:
        reason = 'while sending macroses command to the tmux'
    if 'thr_handler' in func:
        reason = 'in the forked process managing'
    if '__continuous_print' in func:
        'during the procedure of continious log streaming'

    wrt(func, args.exc_value)
    msgq.append(f'There was an unhandled error {reason}, see log for details')


def redo():
    global highlstr
    prof_name = profiles[resolve('prof')] if nested else 'outer'
    redraw_location = None

    if nested and len(redo_changes.get(prof_name, [])) == 0:
        print_message('No changes were undone for this profile, nothing to redo')
        return
    if not nested and len(redo_changes['outer']) == 0:
        print_message("No changes were undone to the profiles' scope, nothing to redo")
        return

    change = redo_changes[prof_name].pop()
    undo_changes[prof_name].append(buffer_changes[prof_name].pop())
    if change.get('location'):
        change['location'] = [profiles.index(prof_name) + i  for i in change['location']]
    match change['action']:
        case 'e':
            if change.get('location'):
                for location, value in zip(change['location'], change['value']):
                    profiles[location] = value
            else:
                location = profiles.index(change['name'])
                profiles[location] = change['value'][0]
                msgq.append(f'Changed {redo["value"]}back to {change["value"][0]}')
                redraw_location = len([i for i in profiles[:location] if not i.startswith('\t')])
        
        case 'r':
            if change.get('location'):
                for location in change['location']:
                    del profiles[location]
            else:
                location = profiles.index(change['name'])
                for i in profiles[location + 1:]:
                    if not i.startswith('\t'):
                        break
                    del profiles[location + 1]
                del profiles[location]
                msgq.append(f'Deleted {change["name"].replace("\n", " ").replace("\t", "  ")} profile and all of its contents')
                highlstr -= 1 if location - resolve('prof') < 0 else 0

        case 'i':
            if change.get('location'):
                for location, value in zip(change['location'], change['value']):
                    profiles[location:location] = [value]
            else:
                profiles[0:0] = change['value']
                msgq.append('Restored and moved to the top previously removed profile')
                redraw_location = 0

    if not change.get('location'):
        redraw(redraw_location, breakout=False)
        return
    redraw(change.get('location')[0] - profiles.index(prof_name), breakout=False)


def undo(signal, frame):
    global highlstr
    prof_name = profiles[resolve('prof')] if nested else 'outer'
    redraw_location = None
    
    if nested and len(undo_changes.get(prof_name, [])) == 0:
        print_message('No changes were made to this profile to undo')
        return

    if not nested and len(undo_changes['outer']) == 0:
        print_message("No changes were made to the profiles' scope")
        return

    change = undo_changes[prof_name].pop()
    redo = deepcopy(change)
    redo_changes[prof_name] = redo_changes.get(prof_name, []) + [redo]
    buffer_changes[prof_name] = buffer_changes.get(prof_name, []) + [deepcopy(change)]
    if change.get('location'):
        change['location'] = [profiles.index(prof_name) + i  for i in change['location']]
    match change['action']:
        case 'e':
            if change.get('location'):
                redo['value'].clear()
                for location, value in zip(change['location'], change['value']):
                    redo['value'].append(profiles[location])
                    profiles[location] = value
            else:
                location = profiles.index(change['name'])
                redo['value'] = change['name']
                profiles[location] = change['value'][0]
                msgq.append(f'Changed {redo["value"]}back to {change["value"][0]}')
                #redraw_location = len([i for i in profiles[:location] if not i.startswith('\t')])
        
        case 'r':
            redo['action'] = 'i'
            redo['value'] = []
            if change.get('location'):
                for location in change['location']:
                    redo['value'].append(profiles[location])
                    del profiles[location]
            else:
                location = profiles.index(change['name'])
                redo['value'].append(change['name'])
                for i in profiles[location + 1:]:
                    if not i.startswith('\t'):
                        break
                    redo['value'].append(i)
                    del profiles[location + 1]
                del profiles[location]
                msgq.append(f'Deleted {redo["value"][0].replace("\n", " ").replace("\t", "  ")} profile and all of its contents')
                highlstr -= 1 if location - resolve('prof') < 0 else 0

        case 'i':
            redo['action'] = 'r'
            redo['value'].clear()
            if change.get('location'):
                for location, value in zip(change['location'], change['value']):
                    profiles[location:location] = [value]
            else:
                profiles[0:0] = change['value']
                redo['name'] = change['value'][0]
                msgq.append('Restored and moved to the top previously removed profile')
                redraw_location = 0
    
    if not change.get('location'):
        redraw(redraw_location, breakout=False)
        return
    redraw(change.get('location')[0] - profiles.index(prof_name), breakout=False)

def unique_name(name):
    actualname = ''
    profnames = [i.strip() for i in profiles if not i.startswith('\t')]
    while name in profnames:
        actualname = name.split('\t')[0]
        if actualname[-1].isdigit():
            actualname = re.sub(r'\d+$', lambda num: str(int(num.group()) + 1).zfill(2), actualname)
        else:
            actualname += '_00'

        if '\t' in name:
            name = '\t'.join([actualname] + name.split('\t')[1:])
            continue
        name = actualname
    return name


def wrt(*values):
    for value in values:
        if len(str(value)) > 0:
            log.write(str(value) + '\n')
    log.flush()


class Textbox_enhanced(Textbox):

    def do_command(self, ch):
        self._update_max_yx()
        (y, x) = self.win.getyx()
        self.lastcmd = ch

        if ch == curses.ascii.TAB:
            if tab_completion:
                return -2
            ts = curses.get_tabsize()
            curs_offset = [i for i in range(x, x + ts) if i % ts == 0][0]
            if x % ts == 0:
                curs_offset = x + ts

            line = self.win.instr(0, 0)
            tabbed_line = line[:x] + b' ' * (curs_offset - x) + line[x:].strip()
            self.win.addstr(y, 0, tabbed_line)
            self.win.move(y, curs_offset)

        elif ch in (258, 259) and file_selection:
            global unprompted_file
            direction = 'forth' if ch == 258 else 'back'
            upload_history = upload_from_history if file_selection == 'from' else upload_to_history
            cursor_pos = self.win.getyx()[1]
            written = self.win.instr(0, 0).decode().strip()
            overwrite = ''
            if not unprompted_file:
                unprompted_file = written

            if upload_history:
                if written in upload_history:
                    if upload_history.index(written) == (len(upload_history) - 1 if direction == 'forth' else 0):
                        overwrite = unprompted_file
                    else:
                        overwrite = upload_history[upload_history.index(written) + (1 if direction == 'forth' else -1)]
                else:
                    overwrite = upload_history[0 if direction == 'forth' else -1]

            if overwrite:
                self.win.erase()
                self.win.addstr(overwrite)
            else:
                self.win.move(0, cursor_pos)

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


        elif ch == 554:                                       # ^←
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

        elif ch == 569:                                       # ^→
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
        
        elif ch == curses.KEY_BACKSPACE:
            if self.win.instr(y, x - 1, 1) == b' ':
                for i in range(1, curses.get_tabsize() + 1):
                    if self.win.instr(y, x - i, 1) != b' ':
                        self.win.move(y, x - i + 1)
                        break
                    self.win.delch(y, x - i)
            else:
                self.win.delch()

        elif ch == curses.KEY_RESIZE:
            handle_resize()
        else:
            return super().do_command(ch)
        return 1

    def edit(self, validate=None):
        "Edit in the widget window and collect the results."
        while 1:
            ch = self.win.getch()
            if validate:
                ch = validate(ch)
            if not ch:
                continue
            do_results = self.do_command(ch)
            if do_results == 0:
                break
            if do_results == -1:     # In case contents of the window do not need to be returned
                return
            if do_results == -2:
                return self.gather().rstrip(), 'tab'
            self.win.refresh()
        if tab_completion:
            return self.gather().rstrip(), 'enter'
        return self.gather().rstrip()


signal.signal(signal.SIGINT, normalexit)
signal.signal(signal.SIGHUP, normalexit)
signal.signal(signal.SIGTERM, normalexit)
signal.signal(signal.SIGPOLL, neighbors)
signal.signal(signal.SIGUSR1, neighbors)
signal.signal(signal.SIGUSR2, macros)
signal.signal(signal.SIGCHLD, signal.SIG_IGN)
signal.signal(signal.SIGTSTP, undo)
threading.excepthook = thread_handler
sys.excepthook = main_thread_handler

userdir = os.path.expanduser('~') + '/.sshc'
if not os.path.isdir(userdir):
    os.mkdir(userdir)

cfg = {
    'file_path': f'{userdir}/profiles',
    'never_ask_for_encryption': 0,
    'logfile': f'{userdir}/log',
    'templ_list': {},
    'default_templ': '',
    'keys_path': '',
    'key': '',
    'user': 'undefined_user',
    'port': 22,
    'password': 'undefined_password',
    'afterwards': '',                       # not described
    'session_name': 'managed_session',      # not described
    'wf_default': 'word:',                  # not desctibed
    'wf_lines': 3,                          # not desctibed
    'local_spacing': 0,
    'wf_timeout': 10,
    'select_multiplier': 4,
    'import_path': '',
    'from_scripts_path': f'{userdir}/from_scripts/',
    'to_scripts_path': f'{userdir}/to_scripts/',
    'upload_from_path': '',
    'upload_to_path': '',
    'upload_from_dest': os.path.expanduser('~'),
    'src_tunnel_port': '',
    'dst_tunnel_port': '',
    'new_profile': ['New profile\n', '\tnew\t10.100.0.0\n'],
    'max_conn_displayed': 30
}

parse_config()

mainfile = cfg['file_path']

if os.path.isfile(mainfile):
    filetype = os.popen(f'file --mime-type -b {mainfile}').read()

    if 'pgp-encrypted' in filetype:
        key = keyring.get_password(mainfile + '_' + str(os.stat(mainfile).st_ino), os.getlogin())
        if key:
            profiles = decrypt(mainfile, key)
            if not profiles:
                exit('Profiles file is encrypted and there is a passphrase associated with the file found in keyring, but it doesn\'t decrypt the file')

        else:
            key = getpass('Profiles file is encrypted, but there is no passphrase in the keyring to decrypt it\n' \
                          'You can enter password manually, it will be used for encrypting file after you done with the program: ')
            for i in range(3):
                profiles = decrypt(mainfile, key)
                if profiles:
                    break
                key = getpass('Sorry, try again: ')
            if not profiles:
                exit()

    elif 'plain' in filetype:
        with open(mainfile, 'r') as f:
            profiles = f.readlines()
    else:
        exit('Profiles file is not in a plain text, nor considered to be pgp-encrypted according to the "file" utility')

else:
    profiles = cfg['new_profile']
    msgq.append('Profiles file was not found (which is normal during the first launch), the new one will be saved after exiting the program')

scr = curses.initscr()
scr.keypad(True)
curses.noecho()
curses.cbreak()
try:
    curses.start_color()
except:
    pass

max_displayed = int(cfg['max_conn_displayed']) if curses.LINES - 3 > int(cfg['max_conn_displayed']) else curses.LINES - 3
log = open(cfg['logfile'], 'w')
profs_hash = hash(str(profiles))
curses.curs_set(0)
curses.meta(True)
redraw(0, breakout=False)

tmux = subprocess.Popen(['tmux', '-C', 'new-session', '-A', cfg['session_name']], bufsize=1, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
tmux_exec('refresh-client -f no-output')

if threading.active_count() > 1:
    print_message('The application is ready to work, but not all of the template substitution has finished executing')
    while threading.active_count() != 2:    # !!!!!!!fuck this busysleep!!!!!!!
        continue
    redraw(breakout=False)
    print_message('Template substitution finished, good to work')

if msgq:    # offset for startup information if there is any
    msgq = ['The following errors/warnings were encountered during the startup:\n\n'] + msgq


while True:
    nodetails = False
    tab_completion = False
    file_selection = ''
    unprompted_file = ''
    if msgq:
        if len(msgq) > 1:
            nodetails = True
            redraw(breakout=False)
        print_message(msgq, offset=tabsize * (3 if not nested else 1))
        msgq = []
    keypress = scr.getch()
    if keypress == curses.KEY_RESIZE:
        handle_resize()
        continue
    if 'print' in str(threading.enumerate()):
        stop_print.set()
        [th for th in threading.enumerate() if 'print' in th.name][0].join()
    if profiles_count == 0 and keypress not in [23, 263]:   # if nothing is displayed, no need to accept anything else except
        continue                                            # those presses that reduce the sorting string

    try:
        match keypress:

        # [Movement and selection] - "reading" actions

            case 258:   # arrow down - ↓
                exceed = 0
                if nested:
                    redraw(pos + 1)

                if highlstr + 1 == profiles_count:
                    redraw(0)

                for index, value in enumerate(profiles[resolve('prof') + conn_count + 2:]):
                    if not value.startswith('\t') or index == max_displayed:
                        break
                    if highlstr + 1 + index + 1 >= curses.LINES - 3:
                        exceed += 1
                if exceed > highlstr + 1:
                    topprof = highlstr + 1
                    redraw()
                topprof += exceed
                redraw(highlstr + 1 - exceed)

            case 259:   # arrow up - ↑
                exceed = 0
                if nested:
                    redraw(pos - 1)

                if highlstr - 1 < 0:
                    if topprof != 0:
                        topprof -= 1
                        redraw(0)

                    if profiles_count + 1 > curses.LINES - 3:
                        for index, value in enumerate(reversed(profiles)):
                            if not value.startswith('\t') or index == max_displayed:
                                break
                            exceed += 1
                        topprof += profiles_count - curses.LINES + 3 + exceed
                        redraw(curses.LINES - 3 - exceed - 1)
                    redraw(profiles_count - 1)

                for index, value in enumerate(reversed(profiles[:resolve('prof')])):
                    if not value.startswith('\t') or index == max_displayed:
                        break
                    if highlstr + 1 + index > curses.LINES - 3:
                        exceed += 1
                topprof += exceed
                redraw(highlstr - 1 - exceed)

            case 260:   # arrow left - ←
                if nested:
                    if pos in picked_cons:
                        picked_cons.remove(pos)
                        redraw()
                    nested = 0
                    picked_cons = set()
                    topconn = 0
                    pos = 0
                    redraw(highlstr)

                if highlstr == 0 and topprof != 0: topprof = 0
                redraw(0)

            case 261:   # arrow right - →
                if not nested:
                    nested = 1
                    redraw(1)
                if pos in picked_cons:
                    picked_cons.remove(pos)
                else:
                    picked_cons.add(pos)
                redraw()

            case 35 | 36 | 37 | 94 | 38 | 42 | 40:  # Shift + number (which is in fact an other key sent instead of "shift-appended" number)
                if not nested:
                    nested = True

                jump = 0
                if keypress in (35, 36, 37):
                    num = keypress - 32
                if keypress == 94:
                    num = 6
                if keypress == 38:
                    num = 7
                if keypress == 42:
                    num = 8
                if keypress == 40:
                    num = 9

                if num == 3:
                    for move, conn in enumerate(profiles[resolve('conn') + 1:], pos + 2):
                        if conn.startswith('\t#'):
                            jump = move
                            break
                        if not conn.startswith('\t'):
                            for move, conn in enumerate(profiles[resolve('prof') + 1:], 2):
                                if not conn.startswith('\t'):
                                    break
                                if conn.startswith('\t#'):
                                    jump = move
                                    break
                            break

                    # if a "comment jump" is out of bounds, manually adjust the view
                    if jump not in range(topconn, max_displayed):
                        pos = jump
                        if jump < topconn and jump >= 2:
                            topconn = (jump - 3) if jump > 15 else 0
                        if jump > topconn + max_displayed:
                            topconn = jump - max_displayed + 4
                        redraw()

                redraw(jump if jump != 0 else pos + num)

            case 336 | 337:   # Shift + arrow down/up for mass host selection
                if nested:
                    filtered = []
                    selected = list(range(pos, conn_count + 1)) if keypress == 336 else list(range(pos, 0, -1))
                    for i in selected:
                        if not profiles[resolve('prof') + i].startswith('\t#'):
                            filtered.append(i)
                        if len(filtered) == cfg['select_multiplier']:
                            break
                    picked_cons.update(filtered)
                    redraw(filtered[-1])

            case 534:   # Ctrl+↓ for moving connections inside profile
                if not nested:
                    continue
                if len(picked_cons) == 0: picked_cons.add(pos)
                start = resolve('prof')
                for conn in sorted(picked_cons, reverse=True):
                    conn_index = start + conn
                    if conn == conn_count:
                        profiles[start+1:start+1] = [profiles[conn_index]]
                        profiles.pop(conn_index + 1)
                        break
                    profiles[conn_index], profiles[conn_index + 1] = profiles[conn_index + 1], profiles[conn_index]
                picked_cons = set(map(lambda x: x + 1, picked_cons))
                if max(picked_cons) > conn_count:
                    picked_cons.remove(conn_count + 1); picked_cons.add(1)
                if len(picked_cons) == 1:
                    picked_cons = set()
                if pos == conn_count:
                    redraw(1)
                redraw(pos + 1)

            case 575:   # Ctrl+↑
                if not nested:
                    continue
                if len(picked_cons) == 0: picked_cons.add(pos)
                start = resolve('prof')
                end = start + conn_count
                for conn in sorted(picked_cons):
                    conn_index = start + conn
                    if conn == 1:
                        profiles[end+1:end+1] = [profiles[conn_index]]
                        profiles.pop(conn_index)
                        break
                    profiles[conn_index], profiles[conn_index - 1] = profiles[conn_index - 1], profiles[conn_index]
                picked_cons = set(map(lambda x: x - 1, picked_cons))
                if min(picked_cons) == 0:
                    picked_cons.remove(0); picked_cons.add(conn_count)
                if len(picked_cons) == 1:
                    picked_cons = set()
                if pos == 1:
                    redraw(conn_count)
                redraw(pos - 1)

            case 569:   # Ctrl+→ for revealing the set of commands, that will be used for connection
                if not nested:
                    continue
                try:
                    cmds = conn_params(commands=True)
                except Exception:
                    print_message(f'There is an error with the connection parsing\n\n{traceback.format_exc()}')
                    continue
                nodetails = True
                redraw(breakout=False)
                cmds = [cmd.replace("wf '' ", f"wf '{cfg['wf_default']}' ") for cmd in cmds]
                print_message([cmd[:-1] if cmd.endswith('!') else cmd + ' ↵ ' for cmd in cmds])

            case 1:         # Ctrl+A - Select all hosts from the profile
                if nested:
                    profindex = resolve('prof')
                    for num in range(1, conn_count + 1):
                        if not profiles[profindex + num].strip().startswith('#'):
                            picked_cons.add(num)
                    redraw()

            case 16:        # Ctrl+P - Create a continuously updating window with the log file contents in it
                with open(cfg['logfile'], "rb") as f:
                    linecount = sum(1 for _ in f)
                if linecount == 0:
                    print_message('The log is empty')
                else:
                    tailing_print(start_from_the_end=False)


        # [Data manipulation] - "writing" actions

            case 5:     # Ctrl+E for editing a string where cursor at
                replace_line = resolve('prof')
                if nested:
                    replace_line = resolve('conn')
                old_value = profiles[replace_line]
                editline = profiles[replace_line].rstrip()

                lasttab = 0
                incr = 0
                for ind, char in enumerate(editline, 1):
                    ind += incr
                    if char == '\t':
                        if len(editline[lasttab:ind]) == len(editline[lasttab:ind].expandtabs()):
                            editline = editline[:ind - 1] + '  ' + editline[ind:]
                            incr += 1
                        lasttab = ind

                newline = accept_input(preinput=editline.lstrip('\t'), start=tabsize if nested else 0)
                if newline == '':
                    print_message('Leaving a record empty is not a good idea')
                    continue
                newline = ('\t' if nested else '') + re.sub(' {2,}+', '\t', newline)
                if not nested and newline != profiles[replace_line].strip():
                    newline = unique_name(newline)

                profiles[replace_line] = newline + '\n'
                if old_value != newline + '\n':
                    save_changes('edit', pos, old_value)
                if not nested and len(sort) > 0 and not pattern.match(newline.split('\t')[0]):
                    sort = ''
                    for char in newline:
                        sorted_profs = sorted([i for i in profiles if i[0] != '\t' and pattern.match(i)], key=str.lower)
                        if sorted_profs and newline.split('\t')[0] == sorted_profs[0].split('\t')[0].strip():
                            break
                        sort += char.lower()
                        pattern = re.compile(rf'^{sort}.*|.*\| *{sort}.*', re.I)
                    redraw(0, sort_profs=True)
                redraw(sort_profs=True)

            case 14:    # Ctrl+N for adding new profiles and servers
                if nested:
                    profiles[resolve('conn') + 1:resolve('conn') + 1] = ['\tnew\t10.100.0.0\n']
                    save_changes('remove', pos + 1)
                    if highlstr + (pos - topconn) == curses.LINES - 4:
                        topprof += 1
                        highlstr -= 1
                    conn_count += 1
                    if (pos - topconn) + 1 >= max_displayed + 1:    # calling redraw() without arguments avoids adjusting of
                        topconn += 1; pos += 1; redraw()            # pos and topconn variables, for which it is an edge case
                    redraw(pos + 1)

                profname = sort.lower() + ('_' if sort else '') + cfg['new_profile'][0].strip()
                hosts = cfg['new_profile'][1:]
                if cfg['default_templ'] and '\t' not in cfg['new_profile']:
                    profname += '\t' + cfg["default_templ"]
                new_name = unique_name(profname) + '\n'
                profiles = [new_name, *hosts] + profiles
                save_changes('remove', new_name)
                reset(n=False)

            case 18:     # Ctrl+R for removing profiles or servers
                prof_head = resolve('prof')
                if nested:
                    if len(picked_cons) == 0: picked_cons.add(pos)
                    picked_resolved = sorted(map(lambda x: x + prof_head, picked_cons), reverse=True)
                    save_changes('insert', sorted(picked_cons), [profiles[i] for i in picked_resolved])

                    for conn in picked_resolved:
                        if topconn and conn in range(conn_count - max_displayed, conn_count + 1):
                            topconn -= 1
                        if conn_count == 1:
                            msgq.append('Removing the only one left host is not safe. Consider editing it or removing profile')
                            picked_cons = set()
                            redraw(sort_profs=True)
                        profiles.pop(conn)

                    redrawpoint = min(picked_cons)
                    if redrawpoint > conn_count - len(picked_cons):
                        redrawpoint -= 1
                    conn_count -= len(picked_cons)
                    picked_cons = set()
                    redraw(redrawpoint)

                for index, value in enumerate(profiles[prof_head + 1:], 1):
                    if value[0] != '\t':
                        prof_end = prof_head + index
                        break
                    prof_end = prof_head + index + 1   # this copied only for the case of the last profile removal
                save_changes('insert', value=profiles[prof_head:prof_end])
                del profiles[prof_head:prof_end]
                if highlstr == 0:
                    redraw(sort_profs=True)
                redraw(highlstr - 1, sort_profs=True)

            case 4 | 9:     # Ctrl+D | I for duplicating (connections only). I increases last octet and turns out that <TAB> is also Ctrl+I???
                if not nested:
                    continue
                copy_point = resolve('conn')
                copy = profiles[copy_point]
                if keypress == 9:
                    try:    # try to increment the last octet of the IP address
                        origip = incrip = profiles[copy_point].strip().split('\t')[1]
                        last_octet = int(origip.split('.')[3])
                        if last_octet < 255:
                            incrip = re.sub(r'\d+(\n)?$', rf'{str(last_octet + 1)}\g<1>', incrip)
                            copy = copy.replace(origip, incrip)
                    except Exception:
                        wrt(traceback.format_exc())
                profiles[copy_point+1:copy_point] = [copy]
                save_changes('remove', pos + 1)

                if highlstr + (pos - topconn) == curses.LINES - 4:
                    topprof += 1
                    highlstr -= 1
                conn_count += 1
                if (pos - topconn) + 1 >= max_displayed + 1:    # calling redraw() without arguments avoids adjusting of
                    topconn += 1; pos += 1; redraw()        # pos and topconn variables, for which it is an edge case
                redraw(pos + 1)


            case 393:   # Shift + arrow left for copying host's details
                line = profiles[resolve('conn')]
                if nested and line.count('\t') > 2:
                    copied_details = line.split('\t')[3]
                elif not nested and line.count('\t') > 0:
                    copied_details = line.split('\t')[1]
                else:
                    copied_details = ''
                redraw()

            case 402:   # Shift + arrow right for applying copied details (can be used on many)
                if nested:
                    if len(picked_cons) == 0: picked_cons.add(pos)
                    picked_resolved = sorted(map(lambda x: x + resolve('prof'), picked_cons))
                    save_changes('edit', picked_cons, [profiles[i] for i in picked_resolved])

                    for conn in picked_cons:
                        line = profiles[resolve('prof') + conn].split('\t')
                        if copied_details == '':
                            profiles[resolve('prof') + conn] = '\t'.join(line[:3]).strip('\n') + '\n'
                        else:
                            profiles[resolve('prof') + conn] = '\t'.join(line[:3]).strip('\n') + '\t' + copied_details.strip('\n') + '\n'

                    picked_cons = set()
                    redraw()

                old_value = profiles[resolve('prof')]
                line = profiles[resolve('prof')].split('\t')
                if copied_details == '':
                    profiles[resolve('prof')] = '\t'.join(line[:1]).strip('\n') + '\n'
                else:
                    profiles[resolve('prof')] = '\t'.join(line[:1]).strip('\n') + '\t' + copied_details.strip('\n') + '\n'
                save_changes('edit', value=old_value)
                redraw()

            case 27:    # Alt+Z reverse reversed changes
                alt_pressed = True


        # [External] - "executing" actions

            case 10:    # Enter spawns new tmux windows and sends connection commands to them
                if not nested:
                    continue

                if len(picked_cons) == 0:
                    picked_cons.add(pos)
                prof_index = resolve("prof")
                winname = profiles[prof_index].split("\t")[0].strip()
                repeats = {}
                for counter, conn in enumerate(picked_cons):
                    if counter == 0:
                        pane = int(tmux_exec(f'new-window -n "{winname}" -P -F " #{{pane_id}}"', output=1).strip()[1:]) - 1
                    elif counter % 4 == 0 and counter > 0:      # 4 is the optimal amount of panes per tiled window
                        tmux_exec(f'select-layout tiled\nnew-window -n "{winname}"')
                    else:
                        tmux_exec('split-window')
                    pane += 1

                    panename = profiles[prof_index + conn].split("\t")[1]
                    if panename in repeats:
                        repeats[panename] += 1
                        panename += ' #' + str(repeats.get(panename))
                    else:
                        repeats[panename] = 0
                    tmux_exec(f'select-pane -t %{pane} -T "{panename}"')
                    threading.Thread(target=create_connection, args=[f'%{pane}',conn]).start()
                tmux_exec('select-layout tiled')
                picked_cons = set()
                redraw()


            case 21:        # Ctrl+U - Upload(?) a profile from file (only IPs)
                filename = autocomplete_loop('File to take IPs from - ', cfg['import_path'])
                try:
                    file = open(filename)
                    ips = sorted(set(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', file.read())))
                except Exception:
                    print_message('Could not open or read given file')
                    file.close()
                    continue

                if len(ips) == 0:
                    print_message('Could not find any IP addresses in the file')
                    file.close()
                    continue

                profname = filename[filename.rfind('/') + 1:]
                if '.' in profname:
                    profname = profname[:profname.find('.')]

                if len(cfg['default_templ']) > 0:
                    profname += f'\t{cfg["default_templ"]}'
                newprof = [unique_name(profname) + '\n']
                for ind, ip in enumerate(ips):
                    newprof.append(f'\thost_{str(ind).zfill(2)}\t{ip}\n')

                profiles = newprof + profiles
                file.close()
                reset()

            case 12:        # Ctrl+L - Create a background process for tunneling
                if not nested:
                    if not tunnels:
                        print_message('There is yet no tunnels created through this program')
                        continue
                    nodetails = True
                    focused = True
                    redraw(breakout=False)
                    if len(tunnels) > 1:
                        tun_options = ''
                        for enum, value in enumerate(tunnels.values(), 1):
                            tun_options += str(enum) + ') [' + value[0] + ']' + ' -> ' + value[2] + '\n'
                        print_message(f'The list of tunnels the program keeps track of:\n{tun_options}')
                        choice = accept_input(message = 'Enter a number of a tunnel to interact with - ', voffset=tun_options.count('\n') + 2)
                        if not choice.isdigit():
                            print_message('Entered value is not a number')
                            continue
                        choice = int(choice)
                        if choice not in range(1, len(tunnels) + 1):
                            print_message('No tunnel with such number')
                            continue
                        tun_choice = tunnels[list(tunnels.keys())[choice - 1]]
                        print_message(f"Chosen tunnel - {'[' + tun_choice[0] + ']' + ' -> ' + tun_choice[2]}")
                    else:
                        tun_choice = list(tunnels.values())[0]
                        print_message(f'The only installed tunnel is - {'[' + tun_choice[0] + ']' + ' -> ' + tun_choice[2]}')
                    print_message('Action to take (kill or restart) [k/r]', voffset=1)
                    focused = True
                    action = scr.getkey()
                    if action == 'KEY_RESIZE':
                        handle_resize()
                    focused = False

                    if action.lower() == 'k':
                        tailing_print()
                        tun_choice[2] = 'to be killed'
                    elif action.lower() == 'r':
                        tailing_print()
                        tun_choice[2] = 'to be restarted'
                    else:
                        redraw(breakout=False)
                        print_message('Entered action is neither r nor k')
                    continue

                try:
                    hp = conn_params()  # hp - host parameters
                except Exception:
                    print_message(f'There is an error with the connection parsing\n\n{traceback.format_exc()}')
                    continue

                __target = ''
                nodetails = True
                redraw(breakout=False)

                srcport = cfg["src_tunnel_port"]
                if srcport:
                    srcport = int(srcport)
                    for num in range(0, 65535 - srcport):
                        try:
                            s = socket.socket()
                            s.bind(('', srcport + num))
                            srcport = s.getsockname()[1]
                            s.close()
                            break
                        except OSError:
                            s.close()
                            continue
                    print_message('pre-inserted value is taken from the config file and incremented until an opened port is met', voffset=1, cursesoptions=curses.A_DIM)
                sport = accept_input(message='Source port (empty for random) - ', preinput=str(srcport))
                if sport:
                    if not sport.isdigit():
                        print_message('Entered value is not a number')
                        continue
                    sport = int(sport)
                    if sport > 65535:
                        print_message('Entered port out of range of available ports')
                        continue
                else:
                    s = socket.socket()
                    s.bind(('', 0))
                    sport = s.getsockname()[1]

                print_message(f'Source port - {sport}')
                dport = accept_input(message='Destination port - ', preinput=cfg["dst_tunnel_port"], voffset=1)
                if not dport.isdigit():
                    print_message('Entered value is not a number')
                    continue
                dport = int(dport)
                if dport > 65535:
                    print_message('Entered port out of range of available ports')
                    continue

                targethost = '127.0.0.1'
                if 'ssh ' in hp['afterwards'] and re.search(r'ssh ([\.\w]+)', hp['afterwards']):
                    optionaltarget = re.search(r'ssh ([\.\w]+)', hp['afterwards']).group(1)
                    print_message(f'Found an additional host this entry is connecting to, should {optionaltarget} be used as a target one? [y or Enter/n]')
                    focused = True
                    choice = scr.getkey()
                    if choice in ('y', 'Y', '\n'):
                        targethost = optionaltarget
                        __target = f'{hp["address"]}:{targethost}'
                    elif choice == 'KEY_RESIZE':
                        handle_resize()
                    focused = False

                ssh_options = f'-4 -N -L {sport}:{targethost}:{dport} {hp["user"]}@{hp["address"]} -p {hp["port"]}'

                if hp['key'] is not None:
                    ssh_options += f' -i {hp["key"]}'
                tunnels[0 if not tunnels else max(tunnels.keys()) + 1] = [f'{sport}:{__target if __target else hp["address"]}:{dport}', (ssh_options.split(' '), hp['pass']), 'starting']
                tailing_print()
                wrt(f'\nStarting a tunnel with the following command:\nssh {ssh_options}')
                proc_handler('ssh', ssh_options.split(' '), hp['pass'])

            case 11:        # Ctrl+K - Put an identity file in remote host's authorized_keys (should work only if password is defined for connection)
                pass


            case 6 | 20:    # Ctrl+F or Ctrl+T for uploading files from or to host
                if not nested:
                    print_message('File uploading is yet not supported for the multiple hosts at a time')
                    continue
                try:
                    hp = conn_params()  # hp - host parameters
                except Exception:
                    print_message(f'There is an error with the connection parsing\n\n{traceback.format_exc()}')
                    continue

                nodetails = True
                focused = True
                redraw(breakout=False)
                action = 'to'
                if keypress == 6:
                    action = 'from'
                file_selection = action
                scripts_dir = cfg[f'{action}_scripts_path']

                try:
                    custom_opts = sorted([i for i in os.listdir(scripts_dir) if os.access(f'{scripts_dir}/{i}', os.X_OK) and os.path.isfile(f'{scripts_dir}/{i}')])
                except Exception:
                    custom_opts = []
                options = ['1 - Automatic upload (based on the connection details)'] + [str(num) + ' - ' + script for num, script in enumerate(custom_opts, 2)]
                option = 1
                if len(options) > 1:
                    print_message(['Enter a number from the list of available options:'] + options)
                    focused = True
                    keypress = scr.getch()
                    if keypress == curses.KEY_RESIZE:
                        handle_resize()
                    focused = False
                    redraw(breakout=False)
                    if keypress not in list(range(49, 49 + len(options))):
                        print_message('Entered key out of range of available options')
                        continue
                    option = int(chr(keypress))

                if action == 'to':
                    filename = autocomplete_loop('Enter a filename to be uploaded to host - ', cfg['upload_to_path'])
                else:
                    filename = accept_input(message='Enter a filename to be uploaded from host - ', preinput=cfg['upload_from_path'])

                tailing_print()
                if option == 1:
                    src, dst = filename, f'{hp["user"]}@{hp["address"]}:'
                    if action == 'from':
                        src, dst = f'{hp["user"]}@{hp["address"]}:{filename}', cfg['upload_from_dest']

                    scp_options = f'-P {hp["port"]}'
                    if hp['key'] is not None:
                        scp_options += f' -i {hp["key"]}'

                    wrt(f'The following command will be executed:\nscp {scp_options} {src} {dst}')
                    proc_handler('scp', [scp_options, src, dst], hp['pass'])

                else:
                    subprocess.Popen([scripts_dir + custom_opts[option - 2], hp['address'],
                                  str(hp['port']), str(hp['key']), f'"{hp["pass"]}"', str(hp["user"]), str(filename)], stdout=log, stderr=log)
                if action == 'from':
                    upload_from_history.append(filename)
                    continue
                upload_to_history.append(filename)


        # [Sorting string manipulation]

            case 23:        # Ctrl+W - nuke sort string
                sort = ''
                reset()

            case 263:   # backspace removes characters from sorting string
                sort = sort[:-1]
                reset()

            case _: # rest of the keys for sorting (or ignoring)
                if keypress == 122 and alt_pressed:
                    alt_pressed = False
                    redo()
                    continue
                if keypress in list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58)):
                    if nested:
                        sort = chr(keypress)
                    else:
                        sort += chr(keypress)
                    reset()
                else:
                    continue

    except curses.error:
        try:
            reset()
        except AssertionError:
            pass
        #redraw(breakout=False)
        print_message('There was a not-so critical error with the screen rendering')
        wrt(traceback.format_exc())
    except AssertionError:  # Exception raised intentionally to avoid unnecessary if statements
        pass
    except Exception:
        redraw(0, breakout=False)
        print_message('There was a relatively critical error, details of which were written to a log')
        wrt(traceback.format_exc())
