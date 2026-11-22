"""Host-side Ultra kernel spec generator.

Release-independent by construction: sites are symbol references, addresses inside the payload
are relocations, and the credential is an input rather than a constant. See ``../README.md``.
"""
