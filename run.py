"""Start the Mini-SIEM web dashboard.

    python run.py                 # http://127.0.0.1:5000
    python run.py --port 8080
    python run.py --host 0.0.0.0  # expose on your LAN (e.g. Kali VM -> Windows host); be careful
"""
import argparse

from siem import create_app


def main():
    parser = argparse.ArgumentParser(description="Mini-SIEM web dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind (default: localhost only)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true", help="Flask debug mode (never on a shared network)")
    args = parser.parse_args()
    app = create_app()
    print(f" * Mini-SIEM running on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
