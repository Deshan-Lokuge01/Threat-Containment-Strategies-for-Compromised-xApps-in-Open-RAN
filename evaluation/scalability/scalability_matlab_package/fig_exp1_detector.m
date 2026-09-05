function fig_exp1_detector()
%FIG_EXP1_DETECTOR  Detector computational scalability: N contexts vs cycle latency.
% Reads exp1_detector_scaling.csv. Plots p50/p95/p99 (and max) per-tick cycle
% latency against N, with the 1000 ms (1 Hz) processing budget as reference.
% Edit the STYLE block to restyle. Self-contained (no external helpers).

% ---- STYLE ----
col_p50=[0.031 0.318 0.612]; col_p95=[0.192 0.510 0.741];
col_p99=[0.416 0.239 0.604]; col_max=[0.902 0.333 0.051];
lw=1.6; ms=5; fsize=11; figsize=[0 0 6.4 4.0];
use_logy=false;   % set true if you prefer a log y-axis (values are tiny vs 1000 ms)
% ---------------
here=fileparts(mfilename('fullpath'));
T=readtable(fullfile(here,'exp1_detector_scaling.csv'));

fig=figure('Units','inches','Position',figsize,'Color','w'); ax=axes(fig); hold(ax,'on');
plot(ax,T.N_contexts,T.p50_ms,'-o','Color',col_p50,'LineWidth',lw,'MarkerFaceColor',col_p50,'MarkerSize',ms,'DisplayName','p50');
plot(ax,T.N_contexts,T.p95_ms,'--s','Color',col_p95,'LineWidth',lw,'MarkerFaceColor',col_p95,'MarkerSize',ms,'DisplayName','p95');
plot(ax,T.N_contexts,T.p99_ms,'-.^','Color',col_p99,'LineWidth',lw,'MarkerFaceColor',col_p99,'MarkerSize',ms,'DisplayName','p99');
plot(ax,T.N_contexts,T.max_ms,':d','Color',col_max,'LineWidth',lw,'MarkerFaceColor',col_max,'MarkerSize',ms,'DisplayName','max');
yline(ax,1000,'-','1 Hz budget = 1000 ms','Color',[0.5 0.5 0.5],'LineWidth',1,'FontSize',fsize-3,'LabelHorizontalAlignment','left');
xlabel(ax,'Independent detector contexts N','FontSize',fsize);
ylabel(ax,'Per-tick cycle latency (ms)','FontSize',fsize);
xticks(ax,T.N_contexts); grid(ax,'on'); ax.GridAlpha=0.25; box(ax,'on'); ax.FontSize=fsize-1;
if use_logy, set(ax,'YScale','log'); end
legend(ax,'Location','northwest','Box','off','FontSize',fsize-2);
title(ax,'Detector computational scalability (0 deadline misses, N=1..80)','FontSize',fsize-1);
hold(ax,'off');
exportgraphics(fig,fullfile(here,'exp1_detector_latency.pdf'),'ContentType','vector');
exportgraphics(fig,fullfile(here,'exp1_detector_latency.png'),'Resolution',200);
close(fig);
end
