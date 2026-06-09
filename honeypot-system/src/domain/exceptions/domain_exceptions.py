"""Domain-level exception hierarchy."""


class HoneypotError(Exception):
    """Base exception for all domain errors."""
    pass


class SettingsError(HoneypotError): #exceptions
    """Raised when application settings are invalid or missing."""
    pass

class ParseError(HoneypotError): #errors
    """Raised when a log line cannot be parsed."""
    pass

class TimestampError(ParseError): #exceptions
    """Raised when a timestamp cannot be parsed, created or is invalid."""
    pass


class CollectionError(HoneypotError): #exceptions
    """Raised when log collection fails."""
    pass


class PublishError(HoneypotError): #exceptions
    """Raised when publishing a log entry fails."""
    pass


class EnrichmentError(HoneypotError): #exceptions
    """Raised when an enrichment step fails."""
    pass


class PipelineError(HoneypotError): #exceptions
    """Raised when pipeline construction or execution fails."""
    pass


class ConfigurationError(HoneypotError): #exceptions
    """Raised for invalid or missing configuration."""
    pass