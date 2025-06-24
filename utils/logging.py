import os
import logging
from logging.handlers import RotatingFileHandler

def make_rotating_logger(name, filename, level=logging.DEBUG, max_bytes=10*1024*1024, backup_count=5):
    """Create a rotating file logger with the specified configuration."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    # Create file handler
    file_handler = RotatingFileHandler(
        filename,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

def setup_logging(config):
    """Set up comprehensive logging system using app configuration."""
    # Create logs directory
    log_dir = config.get('LOG_DIR', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Get logging configuration
    log_level = getattr(logging, config.get('LOG_LEVEL', 'DEBUG').upper())
    max_bytes = config.get('LOG_MAX_BYTES', 10*1024*1024)
    backup_count = config.get('LOG_BACKUP_COUNT', 5)
    
    # Create loggers
    app_logger = make_rotating_logger(
        'pdf_analyzer',
        os.path.join(log_dir, 'pdf_analyzer.log'),
        log_level, max_bytes, backup_count
    )
    
    forensic_logger = make_rotating_logger(
        'forensic_analysis',
        os.path.join(log_dir, 'forensic_analysis.log'),
        logging.INFO, max_bytes, backup_count
    )
    
    error_logger = make_rotating_logger(
        'errors',
        os.path.join(log_dir, 'errors.log'),
        logging.ERROR, max_bytes, backup_count
    )
    
    return app_logger, forensic_logger, error_logger
