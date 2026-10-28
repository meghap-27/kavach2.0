"""Helpers for cmd_app. Intentionally vulnerable."""
import os
import subprocess


def _run_task(cmdline):
    return subprocess.run(cmdline, shell=True, capture_output=True)  # ZDS:CMD-W1


def _render(job, label):
    return _run_task("generate-report --job %s --label %s" % (job, label))


def build_report(name):
    label = name.strip()
    return str(_render("nightly", label).returncode)


def _compress(path):
    os.popen("tar czf /tmp/out.tgz " + path)  # ZDS:CMD-W2


def archive_logs(folder):
    target = "/var/log/" + folder
    _compress(target)


def legacy_cleanup(pattern):
    os.system("rm -rf /tmp/cache/" + pattern)  # ZDS:CMD-N2
