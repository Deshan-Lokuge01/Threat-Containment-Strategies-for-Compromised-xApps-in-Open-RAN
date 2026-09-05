function fig_exp1_latency_dist()
%FIG_EXP1_LATENCY_DIST  Full per-tick cycle-latency distribution per N.
% Reads raw_campaign_data/exp1/detector_cycles.csv (per-tick latencies) and
% draws a Tukey box-and-whisker per N (measured ticks only, warmup excluded),
% i.e. the full spread the p50/p95/p99 lines in fig_exp1_detector summarise.
% Portable: boxes drawn manually (no Statistics Toolbox needed). Self-contained.

% ---- STYLE ----
box_face=[0.776 0.859 0.937]; box_edge=[0.13 0.29 0.5];
med_col=[0.03 0.19 0.42]; whisk_col=[0.2 0.3 0.5]; out_col=[0.902 0.333 0.051];
med_line_col=[0.902 0.333 0.051];
fsize=11; figsize=[0 0 6.8 4.2]; use_logy=true;   % latencies span sub-ms..ms
% ---------------
here=fileparts(mfilename('fullpath'));
T=readtable(fullfile(here,'raw_campaign_data','exp1','detector_cycles.csv'));
T=T(T.measured==1,:);                       % drop warmup ticks
Ns=unique(T.workloads); Ns=sort(Ns);
xpos=1:numel(Ns);                            % even categorical spacing
fig=figure('Units','inches','Position',figsize,'Color','w'); ax=axes(fig); hold(ax,'on');
meds=nan(1,numel(Ns)); w=0.30;
for i=1:numel(Ns)
    v=T.cycle_latency_ms(T.workloads==Ns(i)); v=v(~isnan(v));
    q=quantile(v,[0.25 0.5 0.75]); iqr=q(3)-q(1);
    lo=max(min(v),q(1)-1.5*iqr); hi=min(max(v),q(3)+1.5*iqr);   % Tukey whiskers
    out=v(v<lo | v>hi); meds(i)=q(2);
    x=xpos(i);
    fill(ax,x+[-w w w -w],[q(1) q(1) q(3) q(3)],box_face,'EdgeColor',box_edge,'FaceAlpha',0.85);
    plot(ax,x+[-w w],[q(2) q(2)],'Color',med_col,'LineWidth',1.7);
    plot(ax,[x x],[q(3) hi],'Color',whisk_col); plot(ax,[x x],[lo q(1)],'Color',whisk_col);
    plot(ax,x+[-w/2 w/2],[hi hi],'Color',whisk_col); plot(ax,x+[-w/2 w/2],[lo lo],'Color',whisk_col);
    if ~isempty(out), scatter(ax,x*ones(size(out)),out,7,out_col,'filled','MarkerFaceAlpha',0.25); end
end
plot(ax,xpos,meds,'-o','Color',med_line_col,'LineWidth',1.4,'MarkerFaceColor',med_line_col,'MarkerSize',4);
xlabel(ax,'Independent detector contexts N','FontSize',fsize);
ylabel(ax,'Per-tick cycle latency (ms)','FontSize',fsize);
xticks(ax,xpos); xticklabels(ax,string(Ns)); xlim(ax,[0.5 numel(Ns)+0.5]);
if use_logy, set(ax,'YScale','log'); end
grid(ax,'on'); ax.GridAlpha=0.25; box(ax,'on'); ax.FontSize=fsize-1;
title(ax,'Detector cycle-latency distribution vs N (measured ticks; box=IQR, whisker=1.5\timesIQR)','FontSize',fsize-2);
text(ax,0.02,0.97,'all ticks \ll 1000 ms budget (0 deadline misses)','Units','normalized','FontSize',fsize-3,'Color',[0.4 0.4 0.4],'VerticalAlignment','top');
hold(ax,'off');
exportgraphics(fig,fullfile(here,'exp1_latency_distribution.pdf'),'ContentType','vector');
exportgraphics(fig,fullfile(here,'exp1_latency_distribution.png'),'Resolution',200); close(fig);
end
