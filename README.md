# logpulse

A simple, zero-dependency Python stream processor for parsing Combined Log Format HTTP logs and flagging error rate anomalies.

It parses logs line-by-line using standard library generators to keep memory usage low, then applies a rolling Z-Score threshold to catch sudden error spikes (4xx/5xx).

## Quick Setup

No external libraries needed. Works out of the box with standard Python 3.8+.

```bash
