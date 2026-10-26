# Reproduce the interface demo

The README animation and screenshot use this repository's actual frontend with synthetic names, metrics and users. API requests are intercepted locally. The scenario does not contact a target, identity provider or cluster.

Build `web` as described in the README and start Vite preview on a loopback address. Install Playwright with Chromium in your development environment, then run:

```sh
DEMO_URL=http://127.0.0.1:4187 \
PLAYWRIGHT_MODULE=/path/to/playwright \
DEMO_OUTPUT=/path/to/frames \
node scripts/record-demo.cjs
python3 scripts/build-demo.py /path/to/frames assets/readme/demo.gif
```

The capture script refuses non-local preview URLs and intercepts API traffic. The GIF builder needs Pillow. The static alternative is [screenshot.png](../assets/readme/screenshot.png).

A recorded fixture is a UI demonstration, not evidence of a live database operation or deployment.
