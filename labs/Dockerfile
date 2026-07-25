FROM python:3.11-slim

WORKDIR /labs
RUN pip install --no-cache-dir paramiko==5.0.0 PyYAML==6.0.3
COPY labs /labs

EXPOSE 2222
CMD ["python", "/labs/mock_ssh_server.py"]
