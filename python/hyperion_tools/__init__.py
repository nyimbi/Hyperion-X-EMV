"""Python helpers for Hyperion EMV certification workflows."""

__all__ = ["main", "sha256_file", "write_submission_index"]


def __getattr__(name):
    if name in __all__:
        from . import cli

        return getattr(cli, name)
    raise AttributeError(name)
