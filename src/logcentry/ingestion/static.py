"""
LogCentry Ingestion - Static File Reader

Handles reading and parsing of static log files (text, JSON, JSONL).
"""

from pathlib import Path
from typing import Generator

from logcentry.core import LogBatch, LogEntry, LogParser
from logcentry.utils import get_logger, validate_file_path

logger = get_logger(__name__)


class StaticLogReader:
    """
    Reader for static log files.
    
    Supports:
    - Plain text logs (.log, .txt)
    - JSON/JSONL logs (.json, .jsonl)
    """
    
    SUPPORTED_EXTENSIONS = {".log", ".txt", ".json", ".jsonl"}
    
    def __init__(self):
        self.parser = LogParser()
    
    def read(
        self,
        filepath: str | Path,
        max_entries: int | None = None,
    ) -> LogBatch:
        """
        Read and parse a log file.
        
        Args:
            filepath: Path to the log file
            max_entries: Maximum entries to read (None for all)
            
        Returns:
            LogBatch containing parsed entries
        """
        path = validate_file_path(
            filepath,
            allowed_extensions=self.SUPPORTED_EXTENSIONS,
            must_exist=True,
        )
        
        logger.info("reading_static_file", path=str(path))
        return self.parser.parse_file(path, max_entries=max_entries)
    
    def stream(
        self, 
        filepath: str | Path,
    ) -> Generator[LogEntry, None, None]:
        """
        Stream entries from a file one at a time.
        
        Useful for very large files.
        """
        path = validate_file_path(
            filepath,
            allowed_extensions=self.SUPPORTED_EXTENSIONS,
            must_exist=True,
        )
        
        yield from self.parser.stream_file(path)
    
    def read_multiple(
        self,
        filepaths: list[str | Path],
        max_entries_per_file: int | None = None,
    ) -> LogBatch:
        """
        Read and combine multiple log files.
        
        Args:
            filepaths: List of file paths
            max_entries_per_file: Max entries per file
            
        Returns:
            Combined LogBatch
        """
        all_entries = []
        sources = []
        
        for filepath in filepaths:
            try:
                batch = self.read(filepath, max_entries=max_entries_per_file)
                all_entries.extend(batch.entries)
                sources.append(str(filepath))
            except Exception as e:
                logger.error("file_read_failed", path=str(filepath), error=str(e))
        
        return LogBatch(
            entries=all_entries,
            source_file=", ".join(sources),
            source_type="multi_file",
        )
