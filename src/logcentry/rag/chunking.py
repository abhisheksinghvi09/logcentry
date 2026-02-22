"""
LogCentry RAG - Chunking Strategies

Configurable text chunking for optimal RAG retrieval.
Supports fixed-size, semantic, and sentence-aware chunking.
"""

import re
from dataclasses import dataclass, field
from typing import Iterator, Optional


@dataclass
class ChunkConfig:
    """
    Configuration for text chunking.
    
    Attributes:
        chunk_size: Target chunk size in characters (default 512 tokens ≈ 2048 chars)
        chunk_overlap: Overlap between chunks for context preservation
        min_chunk_size: Minimum chunk size (avoid tiny fragments)
        max_chunk_size: Maximum chunk size
        preserve_sentences: Try to break at sentence boundaries
        preserve_paragraphs: Try to break at paragraph boundaries
    """
    
    chunk_size: int = 2048  # ~512 tokens
    chunk_overlap: int = 200  # ~50 tokens
    min_chunk_size: int = 100
    max_chunk_size: int = 4096  # ~1024 tokens
    preserve_sentences: bool = True
    preserve_paragraphs: bool = True


@dataclass
class Chunk:
    """
    A text chunk with metadata.
    
    Attributes:
        content: The chunk text content
        index: Position in the source document
        start_char: Starting character position
        end_char: Ending character position
        metadata: Additional chunk metadata
    """
    
    content: str
    index: int
    start_char: int
    end_char: int
    metadata: dict = field(default_factory=dict)
    
    @property
    def length(self) -> int:
        """Get chunk length in characters."""
        return len(self.content)
    
    def to_dict(self) -> dict:
        """Serialize chunk to dictionary."""
        return {
            "content": self.content,
            "index": self.index,
            "start_char": self.start_char,
            "end_char": self.end_char,
            "length": self.length,
            "metadata": self.metadata,
        }


class TextChunker:
    """
    Base text chunker with configurable strategies.
    
    Usage:
        chunker = TextChunker(ChunkConfig(chunk_size=1024))
        chunks = list(chunker.chunk(long_document))
    """
    
    # Sentence boundary pattern
    SENTENCE_END = re.compile(r'(?<=[.!?])\s+')
    
    # Paragraph boundary pattern
    PARAGRAPH_END = re.compile(r'\n\s*\n')
    
    def __init__(self, config: Optional[ChunkConfig] = None):
        """
        Initialize chunker with config.
        
        Args:
            config: Chunking configuration (uses defaults if None)
        """
        self.config = config or ChunkConfig()
    
    def chunk(self, text: str, metadata: Optional[dict] = None) -> Iterator[Chunk]:
        """
        Split text into chunks using configured strategy.
        
        Args:
            text: Text to chunk
            metadata: Optional metadata to attach to all chunks
            
        Yields:
            Chunk objects
        """
        if not text or not text.strip():
            return
        
        text = text.strip()
        base_metadata = metadata or {}
        
        # Split into initial segments
        if self.config.preserve_paragraphs:
            segments = self._split_paragraphs(text)
        elif self.config.preserve_sentences:
            segments = self._split_sentences(text)
        else:
            segments = [text]
        
        # Build chunks from segments
        current_chunk = ""
        current_start = 0
        chunk_index = 0
        char_position = 0
        
        for segment in segments:
            segment_start = char_position
            char_position += len(segment)
            
            # Check if adding this segment exceeds max size
            if len(current_chunk) + len(segment) > self.config.max_chunk_size:
                # Emit current chunk if it's big enough
                if len(current_chunk) >= self.config.min_chunk_size:
                    yield Chunk(
                        content=current_chunk.strip(),
                        index=chunk_index,
                        start_char=current_start,
                        end_char=current_start + len(current_chunk),
                        metadata={**base_metadata, "chunk_strategy": "paragraph" if self.config.preserve_paragraphs else "sentence"},
                    )
                    chunk_index += 1
                    
                    # Calculate overlap start
                    overlap_start = max(0, len(current_chunk) - self.config.chunk_overlap)
                    current_chunk = current_chunk[overlap_start:] + segment
                    current_start = segment_start - len(current_chunk) + len(segment)
                else:
                    current_chunk += segment
            else:
                current_chunk += segment
            
            # Check if we've reached target size
            if len(current_chunk) >= self.config.chunk_size:
                yield Chunk(
                    content=current_chunk.strip(),
                    index=chunk_index,
                    start_char=current_start,
                    end_char=current_start + len(current_chunk),
                    metadata={**base_metadata, "chunk_strategy": "size"},
                )
                chunk_index += 1
                
                # Overlap for next chunk
                overlap_start = max(0, len(current_chunk) - self.config.chunk_overlap)
                overlap_text = current_chunk[overlap_start:]
                current_chunk = overlap_text
                current_start = char_position - len(overlap_text)
        
        # Emit remaining content
        if current_chunk.strip() and len(current_chunk.strip()) >= self.config.min_chunk_size:
            yield Chunk(
                content=current_chunk.strip(),
                index=chunk_index,
                start_char=current_start,
                end_char=current_start + len(current_chunk),
                metadata={**base_metadata, "chunk_strategy": "final"},
            )
    
    def _split_paragraphs(self, text: str) -> list[str]:
        """Split text into paragraphs."""
        parts = self.PARAGRAPH_END.split(text)
        # Preserve paragraph breaks
        result = []
        for i, part in enumerate(parts):
            if i < len(parts) - 1:
                result.append(part + "\n\n")
            else:
                result.append(part)
        return result
    
    def _split_sentences(self, text: str) -> list[str]:
        """Split text into sentences."""
        parts = self.SENTENCE_END.split(text)
        # Preserve sentence structure
        result = []
        for i, part in enumerate(parts):
            if i < len(parts) - 1:
                result.append(part + " ")
            else:
                result.append(part)
        return result


class TokenAwareChunker(TextChunker):
    """
    Chunker that respects token limits.
    
    Uses approximate token counting (4 chars ≈ 1 token).
    """
    
    CHARS_PER_TOKEN = 4  # Approximate for English text
    
    def __init__(
        self,
        token_limit: int = 512,
        token_overlap: int = 50,
        **kwargs,
    ):
        """
        Initialize token-aware chunker.
        
        Args:
            token_limit: Maximum tokens per chunk
            token_overlap: Token overlap between chunks
        """
        config = ChunkConfig(
            chunk_size=token_limit * self.CHARS_PER_TOKEN,
            chunk_overlap=token_overlap * self.CHARS_PER_TOKEN,
            **kwargs,
        )
        super().__init__(config)
        self.token_limit = token_limit
        self.token_overlap = token_overlap
    
    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text."""
        return len(text) // self.CHARS_PER_TOKEN


class LogChunker(TextChunker):
    """
    Specialized chunker for log data.
    
    Preserves log line boundaries and groups related entries.
    """
    
    def __init__(
        self,
        lines_per_chunk: int = 50,
        line_overlap: int = 5,
    ):
        """
        Initialize log chunker.
        
        Args:
            lines_per_chunk: Target lines per chunk
            line_overlap: Line overlap between chunks
        """
        self.lines_per_chunk = lines_per_chunk
        self.line_overlap = line_overlap
        super().__init__(ChunkConfig(
            preserve_sentences=False,
            preserve_paragraphs=False,
        ))
    
    def chunk(self, text: str, metadata: Optional[dict] = None) -> Iterator[Chunk]:
        """Chunk by log lines."""
        lines = text.strip().split("\n")
        base_metadata = metadata or {}
        
        chunk_index = 0
        i = 0
        
        while i < len(lines):
            # Get chunk lines
            end = min(i + self.lines_per_chunk, len(lines))
            chunk_lines = lines[i:end]
            
            content = "\n".join(chunk_lines)
            start_char = sum(len(l) + 1 for l in lines[:i])
            
            yield Chunk(
                content=content,
                index=chunk_index,
                start_char=start_char,
                end_char=start_char + len(content),
                metadata={
                    **base_metadata,
                    "chunk_strategy": "log_lines",
                    "line_start": i,
                    "line_end": end,
                    "line_count": len(chunk_lines),
                },
            )
            
            chunk_index += 1
            i = end - self.line_overlap if end < len(lines) else end


class SemanticChunker(TextChunker):
    """
    Chunker that uses semantic similarity to group related content.
    
    Requires sentence-transformers for embedding comparison.
    """
    
    def __init__(
        self,
        similarity_threshold: float = 0.7,
        max_chunk_size: int = 4096,
    ):
        """
        Initialize semantic chunker.
        
        Args:
            similarity_threshold: Minimum similarity to group sentences
            max_chunk_size: Maximum chunk size in characters
        """
        self.similarity_threshold = similarity_threshold
        super().__init__(ChunkConfig(
            max_chunk_size=max_chunk_size,
            preserve_sentences=True,
        ))
    
    def chunk(self, text: str, metadata: Optional[dict] = None) -> Iterator[Chunk]:
        """
        Chunk based on semantic similarity.
        
        Falls back to sentence chunking if embeddings unavailable.
        """
        try:
            from logcentry.rag.embeddings import embed_texts
        except ImportError:
            # Fall back to basic chunking
            yield from super().chunk(text, metadata)
            return
        
        # Split into sentences
        sentences = self._split_sentences(text)
        if len(sentences) <= 1:
            yield from super().chunk(text, metadata)
            return
        
        # Get embeddings
        try:
            embeddings = embed_texts(sentences)
        except Exception:
            yield from super().chunk(text, metadata)
            return
        
        # Group similar sentences
        base_metadata = metadata or {}
        groups = []
        current_group = [0]
        
        for i in range(1, len(sentences)):
            # Compare with previous sentence
            similarity = self._cosine_similarity(
                embeddings[i],
                embeddings[current_group[-1]]
            )
            
            current_size = sum(len(sentences[j]) for j in current_group)
            
            if similarity >= self.similarity_threshold and current_size < self.config.max_chunk_size:
                current_group.append(i)
            else:
                groups.append(current_group)
                current_group = [i]
        
        if current_group:
            groups.append(current_group)
        
        # Create chunks from groups
        char_pos = 0
        for chunk_index, group in enumerate(groups):
            content = "".join(sentences[i] for i in group)
            
            yield Chunk(
                content=content.strip(),
                index=chunk_index,
                start_char=char_pos,
                end_char=char_pos + len(content),
                metadata={
                    **base_metadata,
                    "chunk_strategy": "semantic",
                    "sentence_indices": group,
                },
            )
            
            char_pos += len(content)
    
    def _cosine_similarity(self, a: list[float], b: list[float]) -> float:
        """Calculate cosine similarity between two vectors."""
        import math
        
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        
        if norm_a == 0 or norm_b == 0:
            return 0.0
        
        return dot / (norm_a * norm_b)


# Factory function
def create_chunker(
    strategy: str = "default",
    **kwargs,
) -> TextChunker:
    """
    Create a chunker with the specified strategy.
    
    Args:
        strategy: Chunking strategy ("default", "token", "log", "semantic")
        **kwargs: Strategy-specific arguments
        
    Returns:
        Configured chunker instance
    """
    strategies = {
        "default": TextChunker,
        "token": TokenAwareChunker,
        "log": LogChunker,
        "semantic": SemanticChunker,
    }
    
    chunker_class = strategies.get(strategy, TextChunker)
    return chunker_class(**kwargs)
