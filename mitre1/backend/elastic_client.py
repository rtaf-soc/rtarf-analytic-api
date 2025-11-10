import os
from dotenv import load_dotenv
from elasticsearch import AsyncElasticsearch

load_dotenv()

es = AsyncElasticsearch(
    hosts=[os.getenv("ES_URL")],
    http_auth=(os.getenv("ES_USER"), os.getenv("ES_PASS")),
    verify_certs=False
)