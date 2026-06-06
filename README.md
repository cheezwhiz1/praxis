# praxis

# run the elastic startup
./elastic.sh

# from windows open Elastic UI
https://192.168.86.45:5601/

# Elastic cluster
https://192.168.86.45:9200/

## Credentials

Copy `.env` and set your Elasticsearch password before running setup scripts:

```bash
# .env (not committed)
ES_PASS=your_password
```

## Index setup

Seed the forensics and test_rat indexes after a stack rebuild:

```bash
source .env
ES_PASS=$ES_PASS bash indexes/forensics/setup.sh
ES_PASS=$ES_PASS bash indexes/test_rat/setup.sh
```

Each script creates the index (with risk_score runtime field), inserts events, and imports the Kibana dashboard.

