FROM registry.access.redhat.com/ubi9/python-39:1-186@sha256:5e280686bdb36e2317118f93c3de9e59ce2171dce69a3ddaf241399f576b367b

WORKDIR /app
COPY app/requirements.txt  /app
COPY app/base_images_sbom_script.py /app

RUN pip3 install -r requirements.txt
