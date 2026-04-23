"""
SQLMap SSL wrapper for ZeroTrace.
Patches Python's SSL context to accept legacy TLS (TLSv1.0, expired certs)
before running sqlmap. Required because many pentest targets use old SSL.
"""
import ssl, sys, os

# Create a permissive SSL context for legacy servers
_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
try:
    _ctx.minimum_version = ssl.TLSVersion.TLSv1_2
except Exception:
    pass
try:
    _ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
except Exception:
    pass
try:
    _ctx.options |= 0x4  # SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
except Exception:
    pass

ssl._create_default_https_context = lambda: _ctx
ssl._create_unverified_context = lambda: _ctx

# Run sqlmap from its own directory so it can find lib/ modules
sqlmap_dir = r'C:\tools\sqlmap'
sqlmap_path = os.path.join(sqlmap_dir, 'sqlmap.py')
os.chdir(sqlmap_dir)
sys.path.insert(0, sqlmap_dir)
sys.argv[0] = sqlmap_path
exec(compile(open(sqlmap_path, encoding='utf-8').read(), sqlmap_path, 'exec'),
     {'__file__': sqlmap_path, '__name__': '__main__'})
