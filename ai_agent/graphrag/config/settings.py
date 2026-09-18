from pathlib import Path
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict



class Settings(BaseSettings):
    model_config = SettingsConfigDict(
          env_file=Path(__file__).parent.parent / ".env",
          env_file_encoding="utf-8",
      )
    #Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str
    #llm
    openrouter_api_key: str
    llm_model: str = "openai/gpt-4o-mini"
    #embeddings
    embedding_model: str = "all-MiniLM-L6-v2"
    vector_index_dim: int = 384
    #retrieval
    vector_top_k: int = 20
    bm25_top_k: int = 20
    rerank_top_k: int = 10
    rrf_top_k: int = 60
    max_retries: int = 3
    #data sources
    data_dir: Path = Path("data")
    #APIs
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    #logging
    log_level: str = "INFO"
    
    
    @field_validator("vector_index_dim")
    @classmethod
    def check_dim(cls,v,info):
        model=info.data.get("embedding_model","")
        if "MiniLM" in model and v!=384:
            raise ValueError("MiniLM outputs vector_index_dim of 384, not {}".format(v))
        if "mpnet" in model and v!=768:
            raise ValueError("mpnet outputs vector_index_dim of 768, not {}".format(v))
        return v
settings=Settings()