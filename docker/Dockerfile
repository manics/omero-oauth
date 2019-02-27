FROM docker.io/openmicroscopy/omero-web-standalone:5.4.10

ADD . /opt/omero/src/omero-oauth
USER root
RUN cd /opt/omero/web/OMERO.web && \
    patch -p1 < /opt/omero/src/omero-oauth/omeroweb-5.4.10-webgateway-marshal-py.patch && \
    cp /opt/omero/src/omero-oauth/omeroweb-config.omero /opt/omero/web/config/50-oauth.omero && \
    /opt/omero/web/venv/bin/pip install /opt/omero/src/omero-oauth
USER omero-web
