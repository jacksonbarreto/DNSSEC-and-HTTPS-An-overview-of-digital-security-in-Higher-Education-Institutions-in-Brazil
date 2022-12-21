FROM python:3

WORKDIR /app/

COPY ./code/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN pip freeze
COPY ./code/ ./
CMD [ "python", "/app/main.py" ]