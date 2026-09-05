FROM 127.0.0.1:80/kpimon-ocudu-cell:ztx-experiment-v1
COPY ztx-kpimon-actuator-c /opt/ztx/ztx-kpimon-actuator-c
COPY ztx-entrypoint-c.sh /opt/ztx/ztx-entrypoint-c.sh
RUN chmod +x /opt/ztx/ztx-kpimon-actuator-c /opt/ztx/ztx-entrypoint-c.sh
ENTRYPOINT ["/opt/ztx/ztx-entrypoint-c.sh"]
