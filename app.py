from flask import Flask
from config import Config
from utils.logging import setup_logging
from pdf_analyzer.routes import pdf_bp

def create_app():
    """Application factory function."""
    app = Flask(__name__, 
                template_folder=Config.TEMPLATE_FOLDER, 
                static_folder=Config.STATIC_FOLDER)
    
    # Load configuration
    app.config.from_object(Config)
    
    # Setup logging
    setup_logging(app.config)
    
    # Register blueprints
    app.register_blueprint(pdf_bp)
    
    return app

if __name__ == '__main__':
    app = create_app()
    print("Starting PDF Forensic Analyzer Pro with enhanced UI and logging")
    print("Features: Comprehensive forensic analysis, intelligent table extraction, premium UI")
    print("Logging: All activities are logged to ./logs/ directory")
    print(f"Open your browser and go to: http://{Config.HOST}:{Config.PORT}")
    print("Enhanced with Agility branding and premium design")
    print("="*80)
    
    app.run(debug=Config.DEBUG, host=Config.HOST, port=Config.PORT)
