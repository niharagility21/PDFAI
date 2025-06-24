
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration class for the PDF Analyzer application."""
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here-change-this-in-production')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    
    # File upload settings
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB default
    
    # API keys
    MISTRAL_API_KEY = os.getenv('MISTRAL_API_KEY', 'fvrbS59yLn1aZi0EhyAeUdupJy8AIuaR')
    
    # Server settings
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    
    # Directory settings
    TEMPLATE_FOLDER = 'templates'
    STATIC_FOLDER = 'static'
    LOG_DIR = os.getenv('LOG_DIR', 'logs')
    
    # Logging settings
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
    LOG_MAX_BYTES = int(os.getenv('LOG_MAX_BYTES', 10 * 1024 * 1024))  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', 5))
