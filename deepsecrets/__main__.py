import sys
from deepsecrets.cli import DeepSecretsCliTool


def runnable_entrypoint():
    return_code = DeepSecretsCliTool(sys.argv).start()
    sys.exit(return_code)


if __name__ == '__main__':
    runnable_entrypoint()
