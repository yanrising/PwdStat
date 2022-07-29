# dockerfile for pwdstat

# build stage
FROM python:slim AS build
ENV PATH="/opt/venv/bin":$PATH
WORKDIR /opt
RUN apt-get update; apt-get install -y git python3 pip curl; rm -rf /var/lib/apt/lists/*; python3 -m pip install virtualenv; \
    virtualenv -p python venv; PATH="/opt/venv/bin:$PATH";\
    git clone https://github.com/JakeWnuk/PwdStat; pip3 install -r /opt/PwdStat/requirements.txt; \
    mv /opt/PwdStat/pwdstat.py /opt/venv/bin/pwdstat.py; chmod +x /opt/venv/bin/pwdstat.py

# final stage
FROM python:slim
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN apt-get update; apt-get install -y tini; rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/venv/bin/pwdstat.py"]
