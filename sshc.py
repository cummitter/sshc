#!/usr/bin/python

import os
import curses
import traceback
import re
import libtmux
import signal
import warnings
import threading
from base64 import b64decode as dcd
from gnupg import GPG
from subprocess import Popen
from textpad import Textbox
from time import sleep, time
warnings.filterwarnings("ignore")


user_folder = os.path.expanduser('~') + '/.sshc'
if not os.path.isdir(user_folder):
    os.mkdir(user_folder)
try:
    config_file = open(f'{user_folder}/config')
except OSError:
    exit('Configuration file is missing or have insufficient priviligies to open, please refer to ~/.sshc/config.template')

cfg = {
    'file_path': 'profiles',
    'passphrase': '',
    'logfile': '/var/log/sshc',
    'templ_list': {},
    'default_templ': '',
    'keys_path': '',
    'key': '',
    'user': 'undefined_user',
    'port': 22,
    'password': 'undefined_password',
    'timeout': 10,
    'import_path': '',
    'from_scripts': [],
    'to_scripts': [],
    'upload_from_path': '',
    'upload_to_path': '',
    'new_profile': ['New profile\n', '\tnew\t10.100.0.0\n']
}

lines = [l for l in config_file.readlines() if not l.startswith('#') and l != '\n']
if 'templ_list(\n' in lines:
    if ')\n' not in lines[lines.index('templ_list(\n'):]:
        exit('templ_list attempted to be defined, but no closing bracket found')
    templs = lines[lines.index('templ_list(\n') + 1:lines.index(')\n')]
    lines = [l for l in lines if l not in lines[lines.index('templ_list(\n'):lines.index(')\n') + 1]]

for templ in list(map(str.strip, templs)):
    cfg['templ_list'].update([templ.split('=')])

if 'new_profile:\n' in lines:
    proflines = [l for l in lines[lines.index('new_profile:\n'):] if '=' not in l]
    lines = [l for l in lines if l not in proflines]
    cfg['new_profile'] = proflines[1:]

if len(cfg['new_profile']) < 2:     # if something unsuitable was found in a file - back to defaults
    cfg['new_profile'] = ['New profile\n', '\tnew\t10.100.0.0\n']

for param in lines:
    cfg.update([param.strip().split('=')])

if '/' not in cfg['file_path']:
    cfg['file_path'] = user_folder + '/' + cfg['file_path']

if os.path.isdir(f'{user_folder}/from_scripts'):
    cfg['from_scripts'] = sorted(os.listdir(f'{user_folder}/from_scripts'))
if os.path.isdir(f'{user_folder}/to_scripts'):
    cfg['to_scripts'] = sorted(os.listdir(f'{user_folder}/to_scripts'))



gpg = GPG()
log = open(cfg['logfile'], 'w')
srv = libtmux.Server()

try:
    with open(cfg['file_path'], 'rb') as f:
        profiles = str(gpg.decrypt_file(f)).split('\n')[:-1]
except OSerror:
    exit("Profiles file is not found or can't be opened")

if len(profiles) > 0:
    profiles = [rec + '\n' for rec in profiles]
    os.system(f'cp {cfg["file_path"]} {user_folder}/.profbkp')
else:
    exit(f'Wrong passprhase for {cfg["file_path"]}')
profs_hash = hash(str(profiles))


def main(scr, entrymessage=None):

    global profiles
    global conn_params
    global create_connection
    global nodetails
    global pthread
    nodetails = False
    tabsize = curses.get_tabsize()
    bottom, width = scr.getmaxyx()
    nested = 0
    highlstr = 0
    top_displayed = 0
    sort = ''
    picked_cons = set()

    # The only function responsible for printing everything displayed in the screen, called only in redraw()
    # It is prooved to be easier to redraw everything with each motion
    def print_profiles(move):
        global profiles_count
        global conn_count
        profiles_count = len([i for i in profiles if i[0] != '\t' and re.match(sort + '.*', i, re.I)][top_displayed:])
        
        pntr = 0
        for prof in [i for i in profiles if i[0] != '\t' and re.match(sort + '.*', i, re.I)][top_displayed:]:
            if pntr + 3 == bottom:
                break

            if pntr == highlstr:
                if '\t' in prof:
                    profname, conndetails = prof.split('\t')[:2]   # Only first two parts are valuable, anything else can be dropped
                    conndetails = hide_password(conndetails)
                    scr.addstr(pntr, 0, profname, curses.A_BOLD)
                    scr.addstr(pntr, len(profname) + 4, conndetails, curses.A_DIM + curses.A_ITALIC)
                else:
                    scr.addstr(pntr, 0, prof, curses.A_BOLD)

                conns_to_draw = []
                for i in profiles[resolve('prof') + 1:]:
                    if not i.startswith('\t'):
                        break
                    if nodetails:
                        conns_to_draw.append('\t'.join(i.split('\t')[:3]))
                        continue
                    conns_to_draw.append(i)
                conn_count = len(conns_to_draw)

                for index, conn in enumerate(conns_to_draw):
                    index += 1
                    pntr += 1
                    params = conn.split('\t')[-1]
                    conn = conn.replace(params, hide_password(params))
                    if index in picked_cons:
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


    def hide_password(params):
        if 'key ' in params:
            return params
        elif 'pass ' in params:
            params = params.replace(re.search(r'pass ([^ ]*)', params).group(1), '******')
        elif re.search(r'[^ ]*?/.*', params):
            params = params.replace(re.search(r'[^ ]*?/([^ ]*)', params).group(1), '******')

        if params[-1] != '\n':
            params += '\n'
        return params

    def print_message(message_text, offset=tabsize, voffset=0):
        conn = profiles[resolve('conn')]
        print_point = len(conn.expandtabs().rstrip()) + offset
        if nodetails:
            print_point = len('\t'.join(conn.split('\t')[:3]).expandtabs().rstrip()) + offset 
        if isinstance(message_text, list):
            message_text = ' \n'.join(message_text)

        if len(message_text) + print_point > width - 15 or '\n' in message_text:    # If message does not visually fits in single line, put it into a rectangled window  
            redraw(pos)                                                             # and remove the details of surrounding connections if nodetails is set
            lines = ['']
            linenum = 0
            for word in message_text.split(' '):
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
 
            message_text = '\n'.join(lines)
            msgwin = curses.newwin(message_text.count('\n') + 1, 80, pos + voffset, print_point)
            msgwin.addstr(message_text)
            msgwin.refresh()
            return
        
        scr.addstr(pos + voffset, print_point, message_text)
        scr.refresh()


    def accept_input(message='', preinput='', start=None):
        if start is None:
            conn = profiles[resolve('conn')]
            start = len(conn.expandtabs().rstrip()) + tabsize + len(message)
            if nodetails:
                start = len('\t'.join(conn.split('\t')[:3]).expandtabs().rstrip()) + tabsize + len(message) 
        print_message(message)
        editwin = curses.newwin(1, width - 2 - start, pos, start)
        editwin.addstr(preinput)
        curses.curs_set(2)
        scr.refresh()
        box = Textbox(editwin, insert_mode=True)
        if box.edit() is None:  # editing was canceled, no changes needs to be applied
            redraw(pos)
            curses.curs_set(0)
            return
        redraw(pos)
        curses.curs_set(0)
        return box.gather()[:-1]

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

    def autocomplete(path):     # path considered to be uncompleted
        splited = path.split('/')
        file = splited[-1]
        path = '/'.join(splited[:-1]) + '/'
        suggestions = [f for f in os.listdir(path) if re.match(rf'{file}.*', f)]
        if len(suggestions) > 0:
            for pos, char in enumerate(sorted(suggestions, key=len)[0], 0):
                if len(suggestions) == len([sug for sug in suggestions if sug[pos] == char]):
                    path += char
                    continue
                break
        else:
            path, suggestions = autocomplete(path + file[:-1])
        return path, suggestions

    def continuous_print(stop):
        def tailf():
            l = open(cfg['logfile'])
            while not stop():
                line = l.readline()
                if not line or not line.endswith('\n'):
                    sleep(0.01)
                    continue
                yield line
            else:
                l.close()
                return

        lucorner = len('\t'.join(profiles[resolve('conn')].split('\t')[:3]).expandtabs().rstrip()) + tabsize
        msgwin = curses.newwin(bottom, 80, pos, lucorner)
        message = []
        for linenum, line in enumerate(tailf()):
            msgwin.erase()
            if linenum > bottom - pos - 6:
                message.pop(0)
            message.append(line)
            msgwin.addstr(''.join(message))
            msgwin.refresh()

    # resolve actual position in the profiles list from the relative position on the screen
    def resolve(only_one=None):
        try:
            prof_index = profiles.index([i for i in profiles if i[0] != '\t' and re.match(sort + '.*', i, re.I)][top_displayed:][highlstr])
        except Exception:
            return 0
        if only_one == 'prof':
            return prof_index
        if only_one == 'conn':
            return prof_index + pos - highlstr
        return prof_index, prof_index + pos - highlstr


    def conn_params(conn_num=None, prof_index=None, commands=False):
        if prof_index is None:
            prof_index = profiles.index([i for i in profiles if i[0] != '\t' and re.match(sort + '.*', i, re.I)][top_displayed:][highlstr])
            conn_index = prof_index + pos - highlstr
        if conn_num is not None:
            conn_index = prof_index + conn_num

        conn_str = profiles[conn_index].strip().split('\t')
        prof_str = profiles[prof_index].strip().split('\t')
        params = {
                'prof_name': prof_str[0],
                'syntax': None,
                'address': conn_str[1],
                'port': 22,
                'user': cfg['user'],
                'key': None,
                'pass': None,
                'afterwards': 'sudo -i'
                }

        prof_details = conn_details = ''
        if len(prof_str) > 1:
            prof_details = prof_str[1]
            params['syntax'] = None
        if len(conn_str) > 2:
            conn_details = conn_str[2]

        for i, pstr in enumerate([prof_details, conn_details]):
            if i == 1 and pstr.startswith('!'):
                params['syntax'] = None
                pstr = pstr[1:]

            for templ in cfg['templ_list'].keys():
                if pstr.startswith(templ + ' ') or pstr == templ:
                    params['syntax'] = templ
            for param in ['port', 'pass', 'user']:
                if param + ' ' in pstr:
                    params[param] = re.search(rf'{param} ([^ ]+)', pstr).group(1)
                    pstr = re.sub(rf'{param} [^ ]+ ?', '', pstr)

            if 'key ' in pstr:
                if '/' in pstr:
                    params['user'], params['key'] = re.search(r'key ([^ ]+)?/([^ ]+)', pstr).groups()
                    if params['user'] is None:
                        params['user'] = cfg['user']
                else:
                    params['user'] = re.search(r'key (\w+)', pstr).group(1)
                    params['key'] = cfg['key']
                params['key'] = cfg['keys_path'] + params['key']
            if 'key ' not in pstr and '/' in pstr:
                params['user'], params['pass'] = re.search(r'^([^ ]+)/([^ ]+)', pstr).groups()
            if '|' in pstr:
                params['afterwards'] = pstr.split('|')[1]

        if not commands:
            return params

        command = 'ssh {user}@{address} -p {port}'
        if params['syntax'] is not None:
            command = cfg['templ_list'][params['syntax']]
        elif params['key'] is not None:
            command += f' -i {params["key"]}'
        for param in params.keys():
            command = command.replace('{'+param+'}', str(params[param]))
        command = command.split(', ')

        if params['pass'] is not None:
            command.append(f"wf 'assword:' then '{params['pass']}'")
        for i in params['afterwards'].split(', '):
            command.append(i.strip())
        return command

    def create_connection(pane, conn_num, prof_index=None):
        first_line = 0
        for command in conn_params(conn_num, prof_index, commands=True):
            
            if command.startswith('wf'):
                try:
                    timeout, waitfor, send = re.search(r"wf (\d+)? ?'(.*)' then '(.*)'", command).groups()
                except Exception:
                    raise AssertionError("Could not parse 'wait for' expression, further execution terminated")
                
                if timeout is None:
                    timeout = cfg['timeout']
                start = time()
                while time() - start < timeout:
                    content = pane.capture_pane(first_line)
                    first_line += len(content)
                    if waitfor in ''.join(content):
                        pane.cmd('send-keys', send + '\n')
                        break
                    sleep(0.01)
                else:
                    break   # If timeout occured, do not to send the rest
                continue

            pane.cmd('send-keys', command + '\n')

    def redraw(y_pos):
        scr.erase()
        print_profiles(y_pos)
        scr.addstr(bottom - 2, 4, f'Sort by {sort}.*')
        scr.move(y_pos, 0)
        scr.refresh()
    
    curses.curs_set(0)
    redraw(0)

    while True:
        bottom, width = scr.getmaxyx()
        pos = scr.getyx()[0]
        nested_pos = pos - highlstr
        nodetails = False
        if entrymessage:
            print_message(entrymessage)
            entrymessage = None
        keypress = scr.getch()
        
        for thr in threading.enumerate():           # Making sure to kill a printing thread if there is one
            if 'continuous_print' in thr.name:
                stop_printing = True
                pthread.join()

        if profiles_count == 0 and keypress in [258, 259, 260, 261]:
            continue
        
        try:
            match keypress:
                case 258:   # arrow down - ↓
                    exceed = 0
                    if nested:
                        if conn_count == nested_pos:
                            redraw(highlstr + 1)
                            continue
                    else:
                        if highlstr + 1 == profiles_count:
                            highlstr = 0
                            redraw(0)
                            continue
                        
                        for index, value in enumerate(profiles[resolve('prof') + conn_count + 2:]):
                            if not value.startswith('\t'):
                                break
                            if pos + 1 + index + 1 >= bottom - 3:
                                exceed += 1
                        top_displayed += exceed

                        highlstr = pos + 1 - exceed
                    redraw(pos + 1 - exceed)

                case 259:   # arrow up - ↑
                    exceed = 0
                    if nested:
                        if nested_pos == 1:
                            redraw(highlstr + conn_count)
                            continue
                    else:
                        if highlstr - 1 < 0:
                            if top_displayed != 0:
                                top_displayed -=1
                                redraw(0)
                                continue
                            
                            if profiles_count + 1 > bottom - 3:
                                for index, value in enumerate(reversed(profiles)):
                                    if not value.startswith('\t'):
                                        break
                                    exceed += 1
                                top_displayed += profiles_count - bottom + 3 + exceed
                                highlstr = bottom - 3 - exceed - 1
                                redraw(highlstr)
                                continue

                            highlstr = profiles_count - 1
                            redraw(highlstr)
                            continue
                        
                        exceed = 0
                        for index, value in enumerate(reversed(profiles[:resolve('prof')])):
                            if not value.startswith('\t'):
                                break
                            if pos + 1 + index > bottom - 3:
                                exceed += 1
                        top_displayed += exceed

                        highlstr = pos - 1 - exceed
                    redraw(pos - 1 - exceed)
                
                case 260:   # arrow left - ←
                    if nested:
                        if nested_pos in picked_cons:
                            picked_cons.remove(nested_pos)
                            redraw(pos)
                        else:
                            nested = 0
                            picked_cons = set()
                            redraw(highlstr)
                    else:
                        if highlstr == 0 and top_displayed != 0:
                            top_displayed = 0
                        highlstr = 0
                        redraw(0)

                case 261:   # arrow right - →
                    if not nested:
                        nested = 1
                        redraw(pos + 1)
                    else:
                        picked_cons.add(nested_pos)
                        redraw(pos)


                case 10:    # Enter spawns new tmux windows and sends connection commands to them
                    if not nested:
                        continue

                    if len(picked_cons) == 0:
                        picked_cons.add(None)
                    winname = profiles[resolve('prof')].split('\t')[0]
                    for counter, conn in enumerate(picked_cons):
                        if counter % 4 == 0:      # 4 is the optimal amount of panes per tiled window
                            if counter > 0:
                                win.select_layout('tiled')
                            win = new_win(winname)
                            win.select()
                            pane = win.select_pane(0)
                        else:
                            pane = win.split_window()
                       
                        error_message = ''
                        try:
                            threading.Thread(target=create_connection, args=[pane,conn]).start()
                        except AssertionError as e:
                            error_message = str(e)
                            pane.kill()
                        except Exception as e:
                            error_message = f'An error occured during an attempt to create chosen connection(s)\n\n{traceback.format_exc()}'
                            pane.kill()

                    try:
                        win.select_layout('tiled')
                    except libtmux.exc.LibTmuxException:    # All created panes were killed and no window remained
                        pass
                    picked_cons = set()
                    redraw(pos)
                    print_message(error_message)

                case 5: # Ctrl+E for editing a string where cursor at
                    replace_line = resolve('prof')
                    if nested:
                        replace_line = resolve('conn')
                    editline = profiles[replace_line][:-1]
                    
                    lasttab = 0
                    incr = 0
                    for ind, char in enumerate(editline, 1):
                        ind += incr
                        if char == '\t':
                            if len(editline[lasttab:ind]) == len(editline[lasttab:ind].expandtabs()):
                                editline = editline[:ind - 1] + '  ' + editline[ind:]
                                incr += 1
                            lasttab = ind

                    newline = accept_input(preinput=editline, start=0)
                    if newline is None:
                        continue
                    newline = re.sub(' {2,}+', '\t', newline)
                    
                    if not nested:
                        if len(sort) > 0 and not re.match(sort, newline.split('\t')[0], re.I):
                            sort = newline[:2].lower()
                        if newline != profiles[replace_line].strip():
                            newline = unique_name(newline)

                    profiles[replace_line] = newline + '\n'
                    redraw(pos)


                case 14:    # Ctrl+N for adding new profiles and servers
                    if nested:
                        insert_point = resolve('conn') + 1
                        profiles[insert_point:insert_point] = ['\tnew\t10.100.0.0\n']
                        redraw(pos + 1)
                    else:
                        profname = sort.lower() + cfg['new_profile'][0].strip()
                        hosts = cfg['new_profile'][1:]
                        if len(cfg['default_templ']) > 0 and '\t' not in cfg['new_profile']:
                            profname = f'{profname}\t{cfg["default_templ"]}'
                        profiles = [unique_name(profname) + '\n', *hosts] + profiles
                        highlstr = 0
                        top_displayed = 0
                        redraw(0)

                case 18:     # Ctrl+R for removing profiles or servers
                    if nested:
                        if conn_count == 1:
                            print_message('Removing the only one left host is not safe. consider editing it or removing profile')
                            continue
                        profiles.pop(resolve('conn'))
                        if pos - conn_count == highlstr:  # if removed host was last in the list
                            redraw(pos - 1)
                        else:
                            redraw(pos)
                    else:
                        remove_start_point = resolve('prof')
                        remove_end_point = 0 
                        for index, value in enumerate(profiles[remove_start_point + 1:], 1):
                            if value[0] != '\t':
                                remove_end_point = remove_start_point + index
                                break
                            remove_end_point = remove_start_point + index + 1   # this copied only for the case of removal the last profile
                        del profiles[remove_start_point:remove_end_point]
                        if highlstr == 0:
                            redraw(0)
                        else:
                            highlstr = pos - 1
                            redraw(highlstr)

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
                    redraw(pos + 1)

                case 23:        # Ctrl+W - nuke sort string
                    sort = ''
                    redraw(0)

                case 1:         # Ctrl+A - Select all hosts from the profile
                    if nested:
                        profindex = resolve('prof')
                        for num in range(1, conn_count + 1):
                            if not profiles[profindex + num].strip().startswith('#'):
                                picked_cons.add(num)
                        redraw(pos)


                case 21:        # Ctrl+U - Upload(?) a profile from file (only IPs) 
                    path = accept_input(message='File to take IPs from - ', preinput=f"{cfg['import_path']}/")
                    if path is None:
                        continue
                    try:
                        file = open(path)
                    except OSError:
                        print_message(f'Could not open or read given file - {path}')
                        continue
                    ips = sorted(set(re.findall(r'\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}', file.read())))
                    filename = path.split('/')[-1]
                    profname = filename[:filename.find('.')]
                    if len(cfg['default_templ']) > 0:
                        profname = f'{profname}\t{cfg["default_templ"]}'
                    newprof = [unique_name(profname) + '\n']
                    for ind, ip in enumerate(ips):
                        newprof.append(f'\thost_{str(ind).zfill(2)}\t{ip}\n')

                    profiles = newprof + profiles
                    nested = 0
                    highlstr = 0
                    top_displayed = 0
                    redraw(0)

                
                case 12:        # Ctrl+L - Create a continuously updating window with the log file contents in it
                    nodetails = True
                    redraw(pos)
                    stop_printing = False
                    pthread = threading.Thread(target=continuous_print, args=[lambda: stop_printing])
                    pthread.daemon = True
                    pthread.start()

                case 0:        # Ctrl+T - Create a background process for tunneling
                    pass


                case 11:        # Ctrl+K - Put an identity file in remote host's authorized_keys (should work only if password is defined for connection)
                    pass


                case 6 | 20:    # Ctrl+F or Ctrl+T for uploading files from or to host
                    if not nested:
                        continue

                    nodetails = True
                    action = 'to'
                    if keypress == 6:
                        action = 'from'

                    options = ['1 - Automatic upload (based on the connection details)'] + [str(num) + ' - ' + script for num, script in enumerate(cfg[f'{action}_scripts'], 2)]
                    option = 1
                    if len(options) > 1:
                        print_message(['Enter a number from the list of available options:'] + options)
                        keypress = scr.getch()
                        redraw(pos)
                        if keypress not in list(range(49, 49 + len(options))):
                            print_message('A key out of range of available options was entered')
                            continue
                        option = int(chr(keypress))

                    if action == 'to':
                        filename = ''
                        path = cfg['upload_to_path'] + '/'
                        while True:
                            filename = accept_input(message=f'Enter a filename to be uploaded to host - ', preinput=path)
                            if filename is None or os.path.isfile(filename):
                                break
                            path, suggestions = autocomplete(filename)
                            if path.endswith('/'):
                                suggestions = [s for s in suggestions if not s.startswith('.')]
                            if len(suggestions) == 1:
                                if os.path.isdir(path):
                                    path += '/'
                                continue
                            niceoffset = len(f'Enter a filename to be uploaded to host - ') + len('/'.join(path.split('/')[:-1])) + 1
                            print_message(suggestions, offset=tabsize + niceoffset, voffset=1)

                    else:
                        filename = accept_input(message=f'Enter a filename to be uploaded from host - ', preinput=cfg[f'upload_from_path'] + '/')
                    if filename is None:
                        redraw(pos)
                        continue 

                    try:
                        hp = conn_params()  # hp - host parameters
                    except Exception:
                        print_message(f'There is an error with the connection parsing\n\n{traceback.format_exc()}')
                        continue

                    if option == 1:
                        cmd = f'-P {hp["port"]} {hp["user"]}@{hp["address"]}:'
                        if hp['pass'] is not None:
                            pass    # write a catcher for the password prompt
                        if hp['key'] is not None:
                            cmd = '-i {hp["key"]} ' + cmd
                        cmd = 'scp ' + cmd

                    else:
                        chosen_script = cfg[f'{action}_scripts'][option - 2]
                        Popen([f'{user_folder}/{action}_scripts/{chosen_script}', hp['address'],
                                      str(hp['port']), str(hp['key']), f'"{hp["pass"]}"', str(hp["user"]), str(file_name)], stdout=log, stderr=log)

                case 534:   # Ctrl+↓ for moving connections inside profile
                    if not nested:
                        continue
                    conn_index = resolve('conn')
                    first_index = conn_index - conn_count + 1
                    if pos - highlstr == conn_count:
                        profiles[first_index:first_index] = [profiles[conn_index]]
                        profiles.pop(conn_index + 1)
                        redraw(pos - conn_count + 1)
                        continue
                    profiles[conn_index], profiles[conn_index + 1] = profiles[conn_index + 1], profiles[conn_index]
                    redraw(pos + 1)

                case 575:   # Ctrl+↑
                    if not nested:
                        continue
                    conn_index = resolve('conn')
                    last_index = conn_index + conn_count
                    if pos - 1 == highlstr:
                        profiles[last_index:last_index] = [profiles[conn_index]]
                        profiles.pop(conn_index)
                        redraw(pos + conn_count - 1)
                        continue
                    profiles[conn_index], profiles[conn_index - 1] = profiles[conn_index - 1], profiles[conn_index]
                    redraw(pos - 1)

                case 569:   # Ctrl-→ for revealing the set of commands, that will be used for connection
                    if not nested:
                        continue
                    try:
                        cmds = conn_params(commands=True)
                    except Exception:
                        print_message(f'There is an error with the connection parsing\n\n{traceback.format_exc()}')
                        continue
                    print_message(cmds)

                case 263:   # backspace removes characters from sorting string
                    sort = sort[:-1]
                    highlstr = 0
                    nested = 0
                    top_displayed = 0
                    picked_cons = set()
                    redraw(0)

                case _: # rest of the keys for sorting (or ignoring)
                    if keypress in list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58)):
                        if top_displayed > 0:
                            top_displayed = 0
                        if nested:
                            sort = chr(keypress)
                        else:
                            sort += chr(keypress)
                        highlstr = 0
                        nested = 0
                        picked_cons = set()
                        redraw(0)
                    else:
                        continue
            
        except curses.error:
            redraw(pos)
            print_message('There was a not-so critical error with displaying a text')
            wrt(traceback.format_exc())
            continue


def new_win(name):
    try:
        sesh = srv.new_session('managed_session')
    except libtmux.exc.TmuxSessionExists:
        sesh = [s for s in srv.list_sessions() if s.session_name == 'managed_session'][0]
    return sesh.new_window(name)

def wrt(*values, ex=False):
    for value in values:
        log.write(str(value) + '\n')
    log.flush()
    if ex:
        exit()

# Function is called both for creating a menu in an active pane and as a handler for creating new pane and "populating" it with keys
# This is required by the fact, that some keys' sending has to be precieved by returned characters, which implementation
# better to be kept in a single file. $NEIGHBOR enviroment variable is used for comunicating the host to connect to
def neighbors(signal, frame):
    try:
        sesh = srv.sessions.get(session_name='managed_session')
        win = sesh.active_window
        pane = win.active_pane
        index = [i for i, v in enumerate(profiles) if not v.startswith('\t') and win.window_name in v.split('\t')[0]][0]
    except IndexError:
        os.system(f"tmux display-message -d 3000 'There is no profile with the \"{win.window_name}\" name' 2>/dev/null")
        return
    except Exception:
        os.system(f"tmux display-message -d 3000 'Could not find \"[maanged_session]\"' 2>/dev/null")
        return

    if signal == 10:     # SIGUSR1
        tmcmd = ['menu', '-x', 'R', '-y', '0']
        for i, conn in enumerate(profiles[index + 1:]):
            if not conn.startswith('\t'):
                break
            conn = conn.strip().split('\t')
            tmcmd += [f'{conn[0]} {conn[1]}', i, f'set-environment neighbor {i}; run-shell "pkill sshc -POLL"']
        pane.cmd(*tmcmd)
        return 0

    if signal == 29:    # SIGPOLL
        create_connection(pane.split_window(), int(sesh.show_environment()['neighbor']) + 1, index)
        sesh.remove_environment('neighbor')

def macros(signal, frame):

    try:
        macros_file = open(f'{user_folder}/macros')
    except FileNotFoundError:
        os.system("tmux display-message -d 3000 'Could not find or open \"macros\" file' 2>/dev/null")
        return
    
    # I was unable to find a different solution for including curly braces in a command's syntax,
    # so it is straight up garbage relying on a what-so constant execution of command-prompt
    # If you wish to debug this code, run resulting 'command' into the tmux, not via "tmux 'command-prompt'" command
    def th(cmd):
        srv.cmd('command-prompt', cmd)

    cmd = 'menu -T Macroses -x R -y 0 '
    keys = [0,0,0,0,0,0,0,0,0,0,0,0]    # 've never done such a shame
    nestlevel = 0
    for line in macros_file.readlines():
        line = line.split('# ')[0].strip()
        firstword = line.split(' ')[0]
        if '(' in firstword:
            name = firstword.replace('(', '')
            cmd += f'"{name}" {keys[nestlevel]} {{menu -T {name} -x R -y 0 '
            keys[nestlevel] += 1
            nestlevel += 1
        if ')' in firstword:
            keys[nestlevel] = 0
            nestlevel -= 1
            cmd += '}'

        if ':' in firstword:
            termsignals = ''
            name = firstword.replace(':', '')
            command = line[line.find(':')+1:].strip()
            if '---' in command:
                command, termsignals = command.split('---')
            command = command.replace(r'\n', '<to be rereplaced>').replace('\\', '\\\\').replace('<to be rereplaced>', r'\n')
            for char in '{}"$':
                command = command.replace(char, f'\\{char}')
            command = command.replace("'", r"\'\"\'\"\'")
            cmd += f'{name} {keys[nestlevel]} "send-keys \\\'{command}\\\'{termsignals}" '
            keys[nestlevel] += 1
    threading.Thread(target=th, args=[cmd]).start(); sleep(0.005); srv.cmd('send-keys', '-K', 'Enter')    # It is sort of a pipeline, no judgies pls
    macros_file.close()

def normalexit(signal, frame):
    
    global profiles
    if profs_hash == hash(str(profiles)):
        exit(0)

    sorted_prof = [prof for prof in profiles if prof[0] != '\t']
    sorted_prof.sort()
    result = []
    for prof in sorted_prof:
        result.append(prof)
        for conn in profiles[profiles.index(prof) + 1:]:
            if conn[0] != '\t':
                break
            result.append(conn)
    profiles = result
    gpg.encrypt(''.join(profiles), recipients=None, symmetric=True, passphrase=cfg['passphrase'], output=f'{cfg["file_path"]}')
    exit(0)

signal.signal(signal.SIGINT, normalexit)
signal.signal(signal.SIGHUP, normalexit)
signal.signal(signal.SIGTERM, normalexit)
signal.signal(signal.SIGPOLL, neighbors)
signal.signal(signal.SIGUSR1, neighbors)
signal.signal(signal.SIGUSR2, macros)

if __name__ == '__main__':
    entrymessage = 'test entry message'
    curses.wrapper(main, entrymessage)
