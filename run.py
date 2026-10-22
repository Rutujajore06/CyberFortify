from app import create_app
from app.config import Config

app = create_app()

if __name__ == '__main__':
    print("=" * 60)
    print("  CYBERFORTIFY: Security Simulation & Evaluation Platform")
    print(f"  Target Portal: http://{Config.HOST}:{Config.PORT}/api/target/status")
    print(f"  Platform UI:   http://{Config.HOST}:{Config.PORT}/")
    print("=" * 60)
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
