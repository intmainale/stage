"""Domain-level exception hierarchy."""


class EurosystemError(Exception):
    """Base exception for all domain errors."""
    pass


class ParseError(EurosystemError):
    """Raised when a log line cannot be parsed."""
    pass


class CollectionError(EurosystemError):
    """Raised when log collection fails."""
    pass


class PublishError(EurosystemError):
    """Raised when publishing a log entry fails."""
    pass


class EnrichmentError(EurosystemError):
    """Raised when an enrichment step fails."""
    pass


class PipelineError(EurosystemError):
    """Raised when pipeline construction or execution fails."""
    pass


class ConfigurationError(EurosystemError):
    """Raised for invalid or missing configuration."""
    pass