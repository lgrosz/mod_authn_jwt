FROM python

RUN pip install \
  ping3 \
  pyjwt[crypto] \
  pytest \
  requests

ADD tests /tests
WORKDIR /tests

CMD pytest
