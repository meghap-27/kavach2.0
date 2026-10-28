"""Storage helpers for path_app. Intentionally vulnerable."""
import os
import shutil

NOTES = "/srv/notes"


def _resolve(folder, item):
    return os.path.join(folder, item)


def _load(path):
    with open(path) as fh:  # ZDS:PATH-W1
        return fh.read()


def read_note(note_id):
    return _load(_resolve(NOTES, note_id + ".txt"))


def export_attachment(filename):
    dest = _resolve("/srv/exports", filename)
    shutil.copy("/tmp/upload.bin", dest)  # ZDS:PATH-W2
    return dest


def remove_cache(key):
    os.remove(os.path.join("/srv/cache", key))  # ZDS:PATH-N2
