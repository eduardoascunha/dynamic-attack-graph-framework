from pydantic import BaseModel, Field


class Orchestrator(BaseModel):
    """
    Configuration settings for the Orchestrator service.

    Attributes:
        mulval_root: Path to MulVAL root directory.
        default_mapped_scenario: Default path to mapped scenario file.
        default_graph_dir: Default directory for generated attack graphs.
        graph_timeout_seconds: Timeout in seconds for graph generation.
    """

    mulval_root: str = Field(
        default="/mulval",
        description="Path to MulVAL root directory"
    )
    default_mapped_scenario: str = Field(
        default="/output/scenario.P",
        description="Default path to mapped scenario file"
    )
    default_graph_dir: str = Field(
        default="/gen_graph",
        description="Default directory for generated attack graphs"
    )
    graph_timeout_seconds: int = Field(
        default=300,
        ge=50,
        description="Timeout for graph generation in seconds"
    )