from multiprocessing import freeze_support
import sys
from deepsecrets.cli import DeepSecretsCliTool

freeze_support()
sys.exit(DeepSecretsCliTool(sys.argv).start())

