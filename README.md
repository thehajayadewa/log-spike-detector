# http-log-anomaly-detector

Most 404 and 500 spikes get noticed way too late — usually after someone's already yelling in a Slack channel. This is a small, zero-dependency Python tool I built to catch those spikes earlier, straight from Apache/Nginx access logs, without dragging in a full ELK stack or paying for a SaaS dashboard just to answer one question: *"is something wrong right now?"*

It's deliberately simple. Built purely with the standard library, you can read it in ten minutes, understand every line, and trust it in production.

---

## Why this exists

Servers log everything, all the time. Somewhere in that noise is the early signal you actually care about — a bad deploy throwing 500s, a scanner probing for `.env` files and racking up 404s, or a bot hammering `/wp-login.php` at 3 AM. Most of that signal drowns in sheer volume.

Instead of eyeballing `tail -f access.log` like it's 2009, this script:

1. **Parses** raw log lines into structured data safely.
2. **Buckets** requests into configurable time windows.
3. **Watches** the error rate per bucket against its own recent history.
4. **Flags** anomalies when the current bucket doesn't look like the baseline.

### Z-Scores over Hardcoded Limits

Comparing error rates against a rolling Z-Score baseline matters. A fixed threshold (like *"alert if > 100 errors"*) is either too sensitive at 2 AM or completely useless during a peak traffic spike at noon. Comparing against a moving average ensures the script adapts whether your service is handling 50 req/min or 50,000 req/min.

---

## Project Structure

```text
├── log_parser.py          # Handles line-by-line parsing & regex safety
├── anomaly_monitor.py      # Tracks error history and flags statistical outliers
└── log_anomaly_detector.py # CLI entry point connecting the parser and detector
