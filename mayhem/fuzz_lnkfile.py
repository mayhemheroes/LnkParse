#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers
import io
from contextlib import contextmanager

with atheris.instrument_imports():
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
            with fdp.ConsumeMemoryBytesFile(all_data=True) as f, nostdout():
                lnkfile.lnk_file(f)
        except KeyError:
            return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
