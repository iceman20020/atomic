"""
ATOMIC — reconnaissance & assessment toolkit.
Green-black. Operator-grade.
"""
__version__ = "3.1.0"


def banner():
    from colorama import Fore, Style
    g = Fore.GREEN + Style.BRIGHT; d = Fore.GREEN; y = Fore.YELLOW; r = Style.RESET_ALL

    art = f"""{g}  █████╗ ████████╗ ██████╗  ███╗   ███╗ ██╗  ██████╗
 ██╔══██╗╚══██╔══╝██╔═══██╗ ████╗ ████║ ██║ ██╔════╝
 ███████║   ██║   ██║   ██║ ██╔████╔██║ ██║ ██║     
 ██╔══██║   ██║   ██║   ██║ ██║╚██╔╝██║ ██║ ██║     
 ██║  ██║   ██║   ╚██████╔╝ ██║ ╚═╝ ██║ ██║ ╚██████╗
 ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═╝     ╚═╝ ╚═╝  ╚═════╝{r}"""
    print(art)
    print(f"{d}  ──────────────────────────────────────────────────────────────────{r}")
    print(f"{d}   atomic · reconnaissance · assessment · report{r}")
    print(f"{d}  ──────────────────────────────────────────────────────────────────{r}")
    print(f"  {y}v{__version__}{r}  ·  {d}green-black{r}  ·  {d}operator{r}")
    print()
