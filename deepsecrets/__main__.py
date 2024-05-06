from multiprocessing import freeze_support
import sys
from deepsecrets.cli import DeepSecretsCliTool

if __name__ == '__main__':
    freeze_support()
    sys.exit(DeepSecretsCliTool(sys.argv).start())

