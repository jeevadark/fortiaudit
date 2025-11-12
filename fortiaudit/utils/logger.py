"""
Logging configuration for FortiAudit
"""

import sys
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False
    

class Logger:
    """Centralized logging configuration"""
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.log_dir = Path("logs")
            self.log_dir.mkdir(exist_ok=True)
            self.log_file = self.log_dir / f"fortiaudit_{datetime.now():%Y%m%d_%H%M%S}.log"
            self._setup_logging()
            self._initialized = True
    
    def _setup_logging(self):
        """Configure logging"""
        if LOGURU_AVAILABLE:
            self._setup_loguru()
        else:
            self._setup_standard_logging()
    
    def _setup_loguru(self):
        """Setup loguru logger"""
        # Remove default handler
        loguru_logger.remove()
        
        # Console handler (colored)
        loguru_logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
            level="INFO",
            colorize=True
        )
        
        # File handler (detailed)
        loguru_logger.add(
            self.log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level="DEBUG",
            rotation="10 MB",
            retention="30 days",
            compression="zip"
        )
    
    def _setup_standard_logging(self):
        """Setup standard Python logging (fallback)"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stderr),
                logging.FileHandler(self.log_file)
            ]
        )
    
    def get_logger(self, name: str):
        """Get logger instance"""
        if LOGURU_AVAILABLE:
            return loguru_logger.bind(name=name)
        else:
            return logging.getLogger(name)


# Global logger instance
_logger_instance = Logger()


def get_logger(name: str):
    """
    Get a logger instance
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        Logger instance
    
    Example:
        >>> from fortiaudit.utils.logger import get_logger
        >>> logger = get_logger(__name__)
        >>> logger.info("Starting audit")
    """
    return _logger_instance.get_logger(name)


def set_log_level(level: str):
    """
    Set logging level
    
    Args:
        level: DEBUG, INFO, WARNING, ERROR, CRITICAL
    """
    if LOGURU_AVAILABLE:
        loguru_logger.remove()
        loguru_logger.add(sys.stderr, level=level.upper())
    else:
        logging.getLogger().setLevel(getattr(logging, level.upper()))
