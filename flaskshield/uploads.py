"""Safe handling of uploaded projects. Files are extracted to a temp dir, scanned, then deleted."""
import os
import zipfile

from werkzeug.utils import secure_filename

ALLOWED_SINGLE = {".py", ".ini", ".cfg", ".json", ".yml", ".yaml", ".env"}
MAX_FILES = 2000
MAX_UNCOMPRESSED = 50 * 1024 * 1024


class UploadError(ValueError):
    pass


def save_upload(file_storage, dest):
    """Store an upload in dest. Returns the display name."""
    filename = secure_filename(file_storage.filename or "")
    if not filename:
        raise UploadError("No file selected.")
    ext = os.path.splitext(filename)[1].lower()
    if ext == ".zip":
        tmp = os.path.join(dest, "_upload.zip")
        file_storage.save(tmp)
        try:
            _safe_extract(tmp, dest)
        except zipfile.BadZipFile:
            raise UploadError("File is not a valid zip archive.")
        finally:
            os.remove(tmp)
    elif ext in ALLOWED_SINGLE or filename.lower().startswith(".env") or filename.lower() == "env":
        file_storage.save(os.path.join(dest, filename))
    else:
        raise UploadError("Unsupported file type. Upload a .zip, .py, .env, .ini, .cfg, .json or .yaml file.")
    return filename


def _safe_extract(zip_path, dest):
    dest_real = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise UploadError("Archive contains too many files.")
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
            raise UploadError("Archive is too large when uncompressed.")
        for info in infos:
            target = os.path.realpath(os.path.join(dest, info.filename))
            if target != dest_real and not target.startswith(dest_real + os.sep):
                raise UploadError("Archive contains an unsafe path.")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # skip symlinks
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    out.write(src.read())
