FROM 127.0.0.1:80/kpimon-ocudu-cell:ztx-experiment-v1
COPY ztx-kpimon-actuator /opt/ztx/ztx-kpimon-actuator
COPY ztx-entrypoint.sh /opt/ztx/ztx-entrypoint.sh
RUN chmod +x /opt/ztx/ztx-kpimon-actuator /opt/ztx/ztx-entrypoint.sh
ENTRYPOINT ["/opt/ztx/ztx-entrypoint.sh"]
