#!/bin/bash
python -m streamlit run ui/app.py --server.port $PORT --server.address 0.0.0.0
