"""EC2 supervisor for the Unpacked analysis pilot: claims jobs, runs MachSentry in an isolated
container, calls the AI provider within site-granted budgets and publishes the artifacts."""

__version__ = '0.1.0'
USER_AGENT = 'unpacked-analysis-worker/1'
