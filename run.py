import os
from app import create_app
from app.config import Config

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', Config.PORT))
    # When deployed to hosting platforms (e.g. Render) or when PORT is provided, bind to 0.0.0.0
    host = os.environ.get('HOST', '0.0.0.0' if (os.environ.get('PORT') or os.environ.get('RENDER')) else Config.HOST)
    print("=" * 60)
    print("  CYBERFORTIFY: Security Simulation & Evaluation Platform")
    print(f"  Target Portal: http://{Config.HOST}:{port}/api/target/status")
    print(f"  Platform UI:   http://{Config.HOST}:{port}/")
    print("=" * 60)
    app.run(host=host, port=port, debug=Config.DEBUG)
