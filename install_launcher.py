#!/usr/bin/env python3
"""Installeer een gebruikerslauncher; optioneel met --autostart. Geen sudo."""
import argparse
import os
from pathlib import Path
import sys


def quote_exec(value):
    # Freedesktop Exec heeft eigen quoting, geen shell-syntaxis.
    value = str(value).replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$').replace('%', '%%')
    return '"' + value + '"'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--autostart', action='store_true')
    args = parser.parse_args()
    program = Path(__file__).resolve().parent / 'netwerkwacht.py'
    content = ('[Desktop Entry]\nType=Application\nName=NetworkWatch\n'
               'Comment=Vertrouwde apparaten en HTTP-waarschuwingen\n'
               f'Exec={quote_exec(sys.executable)} {quote_exec(program)}\n'
               'Terminal=false\nIcon=network-workgroup\nCategories=Network;Utility;\n')
    dest = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'applications/netwerkwacht.desktop'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content)
    print(f'Launcher gemaakt: {dest}')
    if args.autostart:
        dest = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'autostart/netwerkwacht.desktop'
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
        print(f'Autostart gemaakt: {dest}')
        print('Je desktop moet XDG Autostart ondersteunen. Zie README voor Hyprland/Omarchy.')


if __name__ == '__main__':
    main()
