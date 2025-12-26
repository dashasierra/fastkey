"""
Fastkey Sample Application
"""

from os import name

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from src.router import auth

app = FastAPI()

# Include Fastkey Router
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# Mount Static Files
app.mount(
    "/", StaticFiles(directory="sample/html", html=True), name="Static Files"
)



if name == "nt":
    import ctypes

    kernel32 = ctypes.windll.kernel32
    if (
        hasattr(kernel32, "GetStdHandle")
        and hasattr(kernel32, "GetConsoleMode")
        and hasattr(kernel32, "SetConsoleMode")
    ):
        h = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE = -11
        mode = ctypes.c_uint32()
        kernel32.GetConsoleMode(h, ctypes.byref(mode))
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(h, mode.value | 0x0004)
