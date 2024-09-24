FROM python:3.10-slim
WORKDIR /code
COPY ./requirements.txt ./
# RUN python3 -m venv .env
# RUN source .env/bin/activate
RUN pip install --no-cache-dir --upgrade -r requirements.txt
COPY ./src ./src
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "1991", "--reload"]