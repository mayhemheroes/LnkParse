#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers
import io
from contextlib import contextmanager
import random

with atheris.instrument_imports(include=["lnkfile"]):
    import lnkfile

@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr
def TestOneInput(data):
        fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
        try:
            with fdp.ConsumeMemoryFile(all_data=True, as_bytes=True) as f, nostdout():
                lnkfile.lnk_file(f)
        except KeyError as e:
            if random.random() > 0.999:
                raise e
def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
