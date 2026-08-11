# Changelog

## 2.0.0

- Replaced MD5 digests in the cache-key builder with SHA-256.
- Removed the DES fallback from the legacy transport shim.
- Fixed a path traversal in the report downloader (CWE-22).
