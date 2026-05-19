import sys

from rich.align import Align

from deepsecrets.utils import setup_interrupts

setup_interrupts()


def runnable_entrypoint():
    from deepsecrets.cli import DeepSecretsCliTool

    return_code = DeepSecretsCliTool(sys.argv).start()
    sys.exit(return_code)


try:
    if __name__ == '__main__':
        runnable_entrypoint()

except KeyboardInterrupt:
    from deepsecrets import console

    console.rule(style='red')
    console.print(Align('[italic]Feel free to report bugs and difficulties here', align='left'))
    console.print(Align('[italic]https://github.com/ntoskernel/deepsecrets/issues', align='left'))
    console.line()
    console.print(Align('[bold yellow]FINISHED WITH EXIT CODE 130', align='left'))
    console.line()
    sys.exit(130)
