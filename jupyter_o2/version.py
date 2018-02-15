from pbr.version import VersionInfo

_v = VersionInfo('jupyter-o2').semantic_version()
__version__ = _v.release_string()
version_info = _v.version_tuple()
