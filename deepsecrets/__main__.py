import sys
from deepsecrets.cli import DeepSecretsCliTool


def runnable_entrypoint():
    sys.exit(DeepSecretsCliTool(sys.argv).start())


if __name__ == '__main__':
    runnable_entrypoint()
