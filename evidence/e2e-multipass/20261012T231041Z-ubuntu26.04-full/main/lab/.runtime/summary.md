# vexproof lab: 5 fast-path run(s) + FULL

| run | steps ok | rows as expected | different | missing | unexpected |
|---|---|---|---|---|---|
| 1 | 6/6 | 249/249 | 0 | 0 | 0 |
| 2 | 6/6 | 249/249 | 0 | 0 | 0 |
| 3 | 6/6 | 249/249 | 0 | 0 | 0 |
| 4 | 6/6 | 249/249 | 0 | 0 | 0 |
| 5 | 6/6 | 249/249 | 0 | 0 | 0 |

FULL=1: exit 0 (results/full/)
- ok metrics-server source: v0.9.0 2a7c4b2c7d46
- ok release manifest sha256: https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.9.0/components.yaml
- ok step source completed: 56 s
- ok ci chain GO-2026-5970 (measured under_investigation|): under_investigation|
- ok ci chain GO-2026-6061 (measured under_investigation|): under_investigation|
- ok ci chain GO-2026-6348 (measured under_investigation|): under_investigation|
- ok ci chain GO-2026-6603 (measured under_investigation|): under_investigation|
- ok ci chain GO-2026-6610 (measured under_investigation|): under_investigation|
- ok ci chain GO-2026-6611 (measured under_investigation|): under_investigation|
- ok ci chain GO-2026-6612 (measured under_investigation|): under_investigation|
- ok ci chain GO-2026-6617 (measured under_investigation|): under_investigation|
- ok ci chains for OSVs published after the measurement (listed, not compared): none
- ok step ci completed: 272 s
- ok mode-b vxb_framer_readmetaframe fires on the official binary: 60
- ok mode-b vxb_serverconn_closestream fires on the official binary: 56
- ok mode-b vxb_serverconn_processheaders fires on the official binary: 56
- ok mode-b other probes (reported; 0 hits is not 'not executed'): {'vxb_clientconnreadloop_handleresponse': 4, 'vxb_transport_roundtripopt': 0, 'vxb_transportresponsebody_read': 0, 'vxb_transportresponsebody_read_value': 27}
- ok step mode-b completed: 160 s
- ok codeql all-args: queries compiled: 23/23
- ok codeql all-args: taint and sink-site queries ran: 23/23
- ok codeql all-args: OSVs with a taint path (measured ['GO-2026-6348', 'GO-2026-6603', 'GO-2026-6611', 'GO-2026-6612', 'GO-2026-6613', 'GO-2026-6617']): ['GO-2026-6348', 'GO-2026-6603', 'GO-2026-6611', 'GO-2026-6612', 'GO-2026-6613', 'GO-2026-6617']
- ok step codeql completed: 1232 s
- ok step cleanup completed: 1 s

**Result: OK**
