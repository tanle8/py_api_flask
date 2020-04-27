FROM python:3.6
WORKDIR /usr/src/app
COPY requirement.txt .
RUN pip install --no-cache-dir -r requirement.txt
COPY . .
CMD ["python", "app.py"]