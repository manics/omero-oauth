FROM library/alpine:3.9

RUN apk add --no-cache \
        py3-flask \
        py3-sqlalchemy \
        py3-requests \
        py3-cryptography && \
    pip3 install \
        authlib \
        Flask-SQLAlchemy

RUN adduser -D python
COPY . /example-oauth2-server
RUN chown -R 1000:1000 /example-oauth2-server
WORKDIR /example-oauth2-server
USER python

EXPOSE 5000
ENV AUTHLIB_INSECURE_TRANSPORT=1
CMD ["sh", "-c", "flask initdb && flask run --host=0.0.0.0"]
