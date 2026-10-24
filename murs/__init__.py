"""MURS — Matrix Upload Research Suite.

An authorized web-security research tool: scope-bound active discovery, inert
upload-safety assessment, a finding engine, an isolated local lab for
reproducing (and fixing) upload vulnerabilities, and automatic PDF reporting.

MURS is for systems you own or are explicitly authorized to test. It performs
passive, inert checks against external targets — it never uploads functional
webshells, backdoors, or command-execution payloads, and never attempts to
bypass authentication or access control. Code-execution risk is demonstrated
only inside the bundled localhost lab.
"""

__version__ = "1.0.0"
MARKER_PREFIX = "MURS"
