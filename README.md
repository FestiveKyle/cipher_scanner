# cipher_scanner

Installation instructions:
```
pip3 install -r requirements.txt

pip3 install "uvicorn[standard]"
```


Run with:
```
uvicorn main:app --reload
```

Requiest scan by requesting url `http://localhost:8000/scan/<DOMAIN_TO_SCAN>`
