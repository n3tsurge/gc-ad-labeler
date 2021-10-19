FROM python:3.7-slim-buster

COPY Pipfile /
COPY Pipfile.lock /
COPY gc-ad-labeler.py /
COPY guardicore /guardicore

WORKDIR /

RUN pip install --upgrade pip \
&& pip install pipenv \ 
&& pipenv install

CMD ["pipenv", "run", "python", "gc-ad-labeler.py"]