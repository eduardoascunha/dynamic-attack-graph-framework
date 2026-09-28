from pydantic import BaseModel, Field, HttpUrl


class Epss(BaseModel):
    """
    Configuration settings for EPSS (Exploit Prediction Scoring System).

    Attributes:
        csv_url (HttpUrl):
            Optional URL to the EPSS CSV data source.
    """

    csv_url: HttpUrl = Field(
        default=HttpUrl("https://epss.cyentia.com/epss_scores-current.csv.gz"),
        description="URL to the EPSS CSV data file (optional)",
    )
